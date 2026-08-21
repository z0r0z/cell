"""CELL calibration harness — see BUILD.md.

The thresholds shipped in blood_gate.py are physically-reasoned starting
points. They are NOT validated on your hardware. This tool fixes that.

    python calibrate.py capture --label genuine        # record one sample
    python calibrate.py enroll-reference               # build REFERENCE_OXYHB
    python calibrate.py roc                            # sweep + operating point
    python calibrate.py selftest                       # synthetic, no hardware

report() states the bound your sample size supports. By the rule of three,
zero spoof acceptances in n trials bounds the false-accept rate at 3/n with 95%
confidence: n=100 gives FAR <= 3%, n=300 gives <= 1%. A 0.1% claim needs ~3000
trials. The number it prints is the number you can publish.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np

from blood_gate import (
    IDX, REFERENCE_OXYHB, TUNABLE, SensorHead, Thresholds,
    absorbance, evaluate, metrics, speckle_metrics,
)

DATA = Path("captures")

# BUILD.md spoof panel. Anything not "genuine" must be rejected.
PANEL = {
    "genuine":        "Your own fresh capillary blood, <=20 s drop to lid",
    "dye":            "Allura Red food colouring in water",
    "ketchup":        "Ketchup, thinned",
    "beet":           "Beet juice",
    "stage_blood":    "Corn syrup + red dye + cocoa",
    "commercial_fx":  "Theatrical blood, 2 brands",
    "aged_10m":       "Own blood, 10 min, room temp",
    "aged_30m":       "Own blood, 30 min, room temp",
    "aged_60m":       "Own blood, 60 min, room temp",
    "rewarmed":       "Aged blood warmed to 37 C before application",
    "edta":           "EDTA/citrate tube blood -- MOST IMPORTANT NEGATIVE",
    "animal":         "Pig or beef blood from a butcher",
    "hemolyzed":      "Own blood, frozen and thawed",
    "deoxygenated":   "Venous or oxygen-depleted blood -- the G4 shape negative",
    "empty":          "No sample",
    # The two sealed pre-flight cartridges (BUILD.md section 5). They are kept
    # with the device and run before any signing that matters, so their
    # behaviour is part of the contract and is tested like any other class.
    "null_cartridge": "NULL pre-flight cartridge -- bright red swatch, must fail G1",
    "reference":      "REFERENCE pre-flight cartridge -- spectral target, cannot clot",
}

MIN_PER_CLASS = 30
GOOD_PER_CLASS = 100

ROI = 64          # synthetic speckle ROI, px
BURST = 16        # frames per burst


# --------------------------------------------------------------------------
# Synthetic head — exercises the whole pipeline without hardware.
# Its output is plausible, NOT calibration data. Never set thresholds from it.
# --------------------------------------------------------------------------


class SyntheticHead(SensorHead):
    def __init__(self, label: str, seed: int = 0):
        self.label = label
        self.rng = np.random.default_rng(seed)
        self.t = 0.0
        # static speckle field this sample would produce if fully arrested
        self.base = self.rng.exponential(1.0, (ROI, ROI))

    # ---- optical shapes, F1..F8 reflectance ------------------------------
    # Reflectance vs the cartridge's white patch, F1..F8. Each shape is set by
    # what the material physically does in a 0.55 mm optically semi-infinite
    # well, because that is what the gates see:
    #
    #   blood     near-total absorption at 415 (Soret) and 445, rising sharply
    #             past 600 nm. Dark overall.
    #   solution  a transparent dye or juice in a DEEP well returns almost
    #             nothing — the light goes in and does not come back. This is
    #             what G1's floor is for, and it is why a dye is rejected on
    #             geometry before chemistry is even consulted.
    #   paste     an opaque red paste (ketchup, corn-syrup stage blood) DOES
    #             return light and IS dark red, so it clears G1's window and
    #             has to be rejected on chemistry: it absorbs blue broadly,
    #             but it has no porphyrin and so no Soret edge.
    #   swatch    the NULL pre-flight cartridge — a bright red printed target.
    #             Far brighter than blood; rejected by G1's ceiling.
    #   empty     the white well itself, brighter still.
    _SHAPES = {
        "blood":    np.array([0.004, 0.012, 0.048, 0.040, 0.022, 0.030, 0.420, 0.533]),
        # deoxyHb: Soret still present (it is still a porphyrin, so G3 passes)
        # but it absorbs far more in the red, which is the whole basis of pulse
        # oximetry. Chemically closest thing to genuine in the panel, and the
        # only class G4 is there to catch.
        "deoxy":    np.array([0.004, 0.010, 0.045, 0.045, 0.015, 0.045, 0.150, 0.300]),
        "solution": np.array([0.010, 0.009, 0.008, 0.008, 0.009, 0.012, 0.020, 0.022]),
        "paste":    np.array([0.100, 0.110, 0.130, 0.160, 0.220, 0.340, 0.450, 0.470]),
        "swatch":   np.array([0.300, 0.280, 0.220, 0.260, 0.400, 0.620, 0.800, 0.820]),
        "empty":    np.array([0.900, 0.905, 0.910, 0.912, 0.915, 0.918, 0.920, 0.922]),
    }
    _BLOODY = ("genuine", "aged_10m", "aged_30m", "aged_60m",
               "rewarmed", "edta", "animal", "hemolyzed", "reference")

    _CELLULAR_NONBLOOD = ("deoxygenated",)

    def _shape(self):
        if self.label == "deoxygenated":
            return self._SHAPES["deoxy"]
        if self.label in self._BLOODY:
            s = self._SHAPES["blood"].copy()
            if self.label == "hemolyzed":
                s *= 1.35                      # cells lysed, far less scattering
            return s
        if self.label in ("dye", "beet"):
            return self._SHAPES["solution"]
        if self.label in ("ketchup", "stage_blood", "commercial_fx"):
            return self._SHAPES["paste"]
        if self.label == "null_cartridge":
            return self._SHAPES["swatch"]
        return self._SHAPES["empty"]

    def _cells(self):
        return self.label not in ("dye", "beet", "empty", "hemolyzed",
                                  "null_cartridge")

    # ------------------------------------------------------------------

    # ---- motion model ----------------------------------------------------
    def _mix(self) -> float:
        """Fraction of the static field present. 0 = freely moving, 1 = frozen.

        genuine   : starts liquid, clots -> the only start-high-end-low case
        edta/animal: anticoagulated, never clots -> stays liquid
        aged/rewarmed: already clotted before it got here -> starts frozen
        syrups/gels : too viscous to move -> starts frozen
        dye/empty   : no coherent scatterers at all
        """
        if self.label in ("genuine", "deoxygenated"):
            # deoxygenated blood still clots normally — it must reach G4 to be
            # rejected, not be caught early by a motion gate.
            return float(0.05 + 0.90 / (1 + np.exp(-0.014 * (self.t - 300))))
        if self.label in ("edta", "animal"):
            return 0.05                       # never sets
        if self.label in ("aged_10m", "aged_30m", "aged_60m", "rewarmed",
                          "hemolyzed", "ketchup", "stage_blood", "commercial_fx",
                          "reference"):
            return 0.94                       # already set / too viscous / solid
        return 0.0

    def read_speckle_burst(self):
        if self.label in ("dye", "beet", "empty", "null_cartridge"):
            # no coherent scattering: sensor noise only, near-zero contrast
            self.t += 1.0
            return self.rng.normal(1.0, 0.02, (BURST, ROI, ROI))
        m = self._mix()
        frames = np.empty((BURST, ROI, ROI))
        for i in range(BURST):
            frames[i] = m * self.base + (1 - m) * self.rng.exponential(1.0, (ROI, ROI))
        self.t += 1.0
        return frames

    # ---- spectrometer ----------------------------------------------------
    def read_channels(self):
        s = self._shape() + self.rng.normal(0, 0.0012, 8)
        clear = float(np.mean(np.clip(s, 0, None)) * 1.05)
        nir = clear * (2.9 if self._cells() else 1.1)
        return np.clip(s, 1e-5, None) * 65535, clear * 65535, nir * 65535

    def read_white_reference(self):
        w = np.full(8, 0.93) + self.rng.normal(0, 0.002, 8)
        return w * 65535, 0.94 * 65535, 0.95 * 65535

    def read_dark(self):
        b = np.full(8, 0.006) + self.rng.normal(0, 0.0004, 8)
        return b * 65535, 0.007 * 65535, 0.007 * 65535


def synth_capture(label: str, seed: int) -> dict:
    h = SyntheticHead(label, seed)
    th = Thresholds()
    white, dark = h.read_white_reference(), h.read_dark()
    chem = h.read_channels()
    speckle = []
    t = 0.0
    while t < th.duration_s:
        h.t = t
        D, K = speckle_metrics(h.read_speckle_burst())
        speckle.append((t, D, K))
        t += th.speckle_period_s
    return {"white": white, "dark": dark, "chem": chem,
            "speckle": speckle, "label": label, "aborted_at_s": None}


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Capture storage
#
# npz, not pickle. These files are meant to be shared — a spoof panel is only
# worth anything if other people can replay it against their own thresholds —
# and unpickling a file someone sent you executes whatever is in it. npz is
# plain arrays and cannot run code.
# --------------------------------------------------------------------------


def save_capture(path: Path, cap: dict) -> None:
    w, d, c = cap["white"], cap["dark"], cap["chem"]
    sp = np.asarray(cap["speckle"], dtype=float).reshape(-1, 3)
    ab = cap.get("aborted_at_s")
    np.savez_compressed(
        path,
        white_f8=w[0], white_clear=w[1], white_nir=w[2],
        dark_f8=d[0], dark_clear=d[1], dark_nir=d[2],
        chem_f8=c[0], chem_clear=c[1], chem_nir=c[2],
        speckle=sp,
        label=np.array(cap["label"]),
        aborted_at_s=np.array(np.nan if ab is None else ab),
    )


def load_capture(path: Path) -> dict:
    z = np.load(path, allow_pickle=False)
    ab = float(z["aborted_at_s"])
    return {
        "white": (z["white_f8"], float(z["white_clear"]), float(z["white_nir"])),
        "dark": (z["dark_f8"], float(z["dark_clear"]), float(z["dark_nir"])),
        "chem": (z["chem_f8"], float(z["chem_clear"]), float(z["chem_nir"])),
        "speckle": [tuple(r) for r in z["speckle"]],
        "label": str(z["label"]),
        "aborted_at_s": None if np.isnan(ab) else ab,
    }


def cmd_capture(args):
    if args.label not in PANEL:
        sys.exit(f"Unknown label. Valid: {', '.join(PANEL)}")
    DATA.mkdir(exist_ok=True)

    if args.synthetic:
        cap = synth_capture(args.label, args.seed)
    else:
        from hardware import RealSensorHead      # provided by the device build
        from blood_gate import acquire
        print(f"[{args.label}] {PANEL[args.label]}")
        input("Load cartridge and press Enter. 600 s capture starts now...")
        # early_abort=False: calibration wants the full speckle series even for
        # samples that fail on chemistry, so the motion gates can be swept
        # against them too. The device runs with the abort on.
        cap = acquire(RealSensorHead(), Thresholds(), early_abort=False)
        cap["label"] = args.label

    n = len(list(DATA.glob(f"{args.label}_*.npz")))
    path = DATA / f"{args.label}_{n:04d}.npz"
    save_capture(path, cap)

    res = evaluate(cap)
    print(f"saved {path}")
    for g in res.gates:
        print("  ", g)
    print(f"  => {'ACCEPT' if res.accepted else 'REJECT'}")


def load_all() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for p in sorted(DATA.glob("*.npz")):
        cap = load_capture(p)
        out.setdefault(cap["label"], []).append(cap)
    return out


def cmd_enroll_reference(args):
    caps = load_all().get("genuine", [])
    if len(caps) < MIN_PER_CLASS:
        sys.exit(f"Need >={MIN_PER_CLASS} genuine captures, have {len(caps)}.")

    vecs = []
    for c in caps:
        a = absorbance(c["chem"][0], c["white"][0], c["dark"][0])
        vecs.append(a / np.linalg.norm(a))
    # NOTE the enrolled vector keeps all 8 channels, including any at the
    # absorbance clamp. gate4 masks the clamped ones itself via SHAPE_CHANNELS,
    # which is recomputed from whatever reference you paste in — so a reference
    # whose 415 nm entry is below the clamp will bring that channel back into
    # the shape comparison. That is correct, and it is why the mask is derived
    # rather than hardcoded.

    ref = np.mean(vecs, axis=0)
    ref /= np.linalg.norm(ref)
    spread = float(np.mean([np.linalg.norm(v - ref) for v in vecs]))

    print("Replace REFERENCE_OXYHB in blood_gate.py with:\n")
    print("REFERENCE_OXYHB = np.array([")
    print("    " + ", ".join(f"{x:.4f}" for x in ref))
    print("], dtype=float)\n")
    print(f"n={len(vecs)}  mean intra-class spread={spread:.4f}")
    if spread > 0.05:
        print("WARNING: spread >0.05. Check optics fouling, LED aging, cartridge print quality.")


def _metric_table(data: dict[str, list[dict]]) -> dict[str, dict[str, np.ndarray]]:
    """metric -> {class -> values across that class's captures}."""
    out: dict[str, dict[str, np.ndarray]] = {}
    for label, caps in data.items():
        for cap in caps:
            for k, v in metrics(cap).items():
                out.setdefault(k, {}).setdefault(label, []).append(v)
    return {k: {c: np.asarray(v) for c, v in d.items()} for k, d in out.items()}


def _choose(genuine: np.ndarray, spoof: np.ndarray, sense: str,
            per_th_budget: float, drift: float) -> tuple[float, int, float]:
    """Pick one threshold from the genuine distribution, and report what that
    single gate then catches.

    A threshold is set from the GENUINE distribution, not from a gap to the
    spoofs. Each gate is responsible for its own physics and no more: dye is
    rejected on return signal, EDTA blood on arrested motion, deoxyHb on
    spectral shape. Demanding that every threshold separate every spoof class
    is incoherent — it is why the six gates are an AND and not a score.

    So: sit at the genuine quantile the FRR budget allows, optionally back off
    by `drift` standard deviations, then MEASURE the false-accept rate against
    the whole panel through the conjunction. Returns
    (threshold, n_spoof_this_gate_alone_rejects, margin_to_nearest_passing_spoof).
    """
    if len(genuine) == 0:
        return 0.0, 0, float("nan")
    sd = float(np.std(genuine))
    # method="lower"/"higher" lands the threshold ON an observed sample rather
    # than interpolating between two. Interpolation puts it just inside the
    # genuine extreme, so the very capture that defined the edge is rejected —
    # and with ten thresholds each doing that to a different capture, FRR goes
    # to 100% on data that is in fact perfectly consistent.
    if sense == "min":
        thr = float(np.quantile(genuine, per_th_budget, method="lower")) - drift * sd
        rejects = int(np.sum(spoof < thr)) if len(spoof) else 0
        passing = spoof[spoof >= thr] if len(spoof) else np.array([])
        margin = float(thr - np.max(passing)) if len(passing) else float("inf")
    else:
        thr = float(np.quantile(genuine, 1.0 - per_th_budget,
                                method="higher")) + drift * sd
        rejects = int(np.sum(spoof > thr)) if len(spoof) else 0
        passing = spoof[spoof <= thr] if len(spoof) else np.array([])
        margin = float(np.min(passing) - thr) if len(passing) else float("inf")
    return thr, rejects, margin


def cmd_roc(args):
    data = load_all()
    if "genuine" not in data:
        sys.exit("No genuine captures. Run: capture --label genuine")

    n_gen = len(data["genuine"])
    spoof_labels = [k for k in data if k != "genuine"]
    n_spoof = sum(len(data[k]) for k in spoof_labels)
    print(f"genuine n={n_gen}   spoof n={n_spoof} across {len(spoof_labels)} classes")
    if n_gen < MIN_PER_CLASS:
        print(f"WARNING: fewer than {MIN_PER_CLASS} genuine captures. Indicative only.")
    missing = [k for k in PANEL if k not in data]
    if missing:
        print(f"WARNING: panel classes never captured: {', '.join(missing)}")
    print()

    table = _metric_table(data)
    # The FRR budget is for the WHOLE gate, and a capture must clear every
    # threshold. Ten thresholds each independently giving away 5% of the
    # genuine tail rejects most genuine samples, so the budget is divided.
    per_th = args.frr_budget / len(TUNABLE)
    chosen, diag = {}, []
    for name, (metric, sense) in TUNABLE.items():
        per = table.get(metric, {})
        gen = per.get("genuine", np.array([]))
        parts = [per[c] for c in spoof_labels if c in per]
        spf = np.concatenate(parts) if parts else np.array([])
        val, rejects, margin = _choose(gen, spf, sense, per_th, args.drift)
        # Round OUTWARD, never to nearest. A "min" threshold rounded up lands
        # above the very genuine sample that set it and rejects it; the file
        # then reads as calibrated while failing every real capture. Six
        # decimals of slack costs nothing against any of these metrics.
        q = 1e-6
        chosen[name] = (math.floor(val / q) * q if sense == "min"
                        else math.ceil(val / q) * q)
        diag.append((name, sense, val, rejects, margin, len(spf),
                     getattr(Thresholds(), name)))

    print("PER-THRESHOLD")
    print("  catches = spoof captures THIS gate alone rejects. The gates are an")
    print("            AND, so a gate catching 0 is not broken — another gate")
    print("            owns that physics.")
    print("  margin  = distance from the threshold to the nearest spoof that")
    print("            still passes this gate. inf = this gate rejects them all.")
    print(f"\n  {'threshold':<22}{'sense':<6}{'shipped':>10}{'chosen':>11}"
          f"{'catches':>11}{'margin':>10}")
    print("  " + "-" * 70)
    for name, sense, val, rej, margin, n_sp, shipped in diag:
        m = "inf" if margin == float("inf") else f"{margin:.3f}"
        print(f"  {name:<22}{sense:<6}{shipped:>10.3f}{val:>11.3f}"
              f"{rej:>8}/{n_sp:<3}{m:>10}")

    th = replace(Thresholds(), **chosen)
    acc = {lab: [evaluate(c, th).accepted for c in caps] for lab, caps in data.items()}
    frr = 1.0 - float(np.mean(acc["genuine"]))
    n_fa = sum(sum(acc[c]) for c in spoof_labels)
    far = n_fa / max(n_spoof, 1)

    print(f"\nOPERATING POINT   FRR = {frr*100:.1f}%   "
          f"spoof acceptances = {n_fa}/{n_spoof}")
    print("  This FRR is IN-SAMPLE — the thresholds were set from these same")
    print("  genuine captures, so it is optimistic by construction. The honest")
    print("  number comes from captures taken AFTER calibration. Expect worse.")
    if frr > args.frr_budget * 2:
        print(f"  WARNING: FRR is {frr*100:.0f}%, far above the "
              f"{args.frr_budget*100:.0f}% budget. Your genuine captures are "
              f"not consistent enough to set thresholds this tight — look for "
              f"optics fouling or cartridge print variation before loosening.")
    report(n_fa, n_spoof)

    print("\nPER-CLASS (accepted / n) -- every non-genuine row must read 0:")
    for label in sorted(acc):
        a, n = sum(acc[label]), len(acc[label])
        want = (a == n) if label == "genuine" else (a == 0)
        print(f"  {label:<16} {a:>3}/{n:<4}{'' if want else '   <-- LOOK AT THIS'}")

    out = dict(chosen)
    out.update({
        "_comment": "Written by calibrate.py roc. Loaded by "
                    "blood_gate.Thresholds.load(). Values above this line are "
                    "thresholds; the rest is provenance.",
        "measured_frr": frr,
        "measured_far": far,
        "far_upper_bound_pct": (300.0 / n_spoof) if n_fa == 0 and n_spoof else None,
        "n_genuine": n_gen,
        "n_spoof": n_spoof,
        "classes": sorted(data),
        "not_separating": [d[0] for d in diag if d[5] == "OVERLAP"],
    })
    Path("thresholds.json").write_text(json.dumps(out, indent=2, sort_keys=True))
    print("\nwrote thresholds.json")
    print("  blood_gate.Thresholds.load() reads it. Put it beside blood_gate.py")
    print("  on the device, or the device keeps signing on shipped defaults.")
    return 0


def report(n_accepted: int, n: int):
    """Rule of three. State only what the sample size supports."""
    if n == 0:
        print("  No spoof data. You have validated nothing.")
        return
    if n_accepted == 0:
        print(f"  Rule of three: 0 acceptances in {n} trials")
        print(f"  => you may claim FAR <= {300.0/n:.2f}% at 95% confidence.")
        print(f"  => you may NOT claim FAR = 0.")
        if n < GOOD_PER_CLASS * 4:
            print(f"  A FAR <= 0.1% claim needs ~3000 trials. Do not overstate this.")
    else:
        print(f"  {n_accepted} spoof acceptances in {n} trials => FAR ~= {n_accepted/n*100:.2f}%")
        print("  Not ready. Find which class passed and fix that gate.")


def cmd_selftest(args):
    print("Synthetic self-test — 6 gates, 2 sensors.")
    print("Exercises the pipeline only. These are NOT calibration data.\n")
    rows = []
    for label in PANEL:
        acc, fails = 0, {}
        for s in range(args.n):
            res = evaluate(synth_capture(label, seed=s))
            if res.accepted:
                acc += 1
            elif (g := res.first_failure()):
                fails[g.name] = fails.get(g.name, 0) + 1
        rows.append((label, acc, args.n, max(fails, key=fails.get) if fails else "-"))

    print(f"{'class':<16}{'accepted':>10}   first failing gate")
    print("-" * 64)
    ok = True
    for label, a, n, top in rows:
        want = a == n if label == "genuine" else a == 0
        ok &= want
        print(f"{label:<16}{a:>6}/{n:<4}   {top}{'' if want else '   <-- UNEXPECTED'}")
    print("-" * 64)

    # Every gate must be the first failure for at least one class. A gate no
    # class exercises is a gate no test covers: it could be inverted, or always
    # return True, and this panel would still print PASS.
    exercised = {top for _, _, _, top in rows if top != "-"}
    expected = {f"G{i} " for i in range(1, 7)}
    uncovered = sorted(g for g in expected
                       if not any(e.startswith(g) for e in exercised))
    if uncovered:
        ok = False
        print(f"UNCOVERED GATES: {', '.join(g.strip() for g in uncovered)} — no "
              f"panel class rejects there, so nothing tests them.")
    else:
        print(f"Gate coverage: all 6 gates exercised by at least one class.")

    print("PASS: pipeline behaves as designed." if ok else "FAIL: see flagged rows.")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture"); c.add_argument("--label", required=True)
    c.add_argument("--synthetic", action="store_true"); c.add_argument("--seed", type=int, default=0)
    c.set_defaults(fn=cmd_capture)
    sub.add_parser("enroll-reference").set_defaults(fn=cmd_enroll_reference)
    r = sub.add_parser("roc")
    r.add_argument("--frr-budget", type=float, default=0.05,
                   help="fraction of genuine captures the whole gate may "
                        "reject, split across thresholds (default 0.05 = 5%%)")
    r.add_argument("--drift", type=float, default=0.0,
                   help="back every threshold off by N standard deviations of "
                        "the genuine distribution, buying drift tolerance at "
                        "the cost of anti-spoof margin. BUILD.md 13 says bias "
                        "toward rejecting, so this defaults to 0. Raise it "
                        "only if measured FRR is unusable, then re-check that "
                        "the panel still reads 0 everywhere.")
    r.set_defaults(fn=cmd_roc)
    s = sub.add_parser("selftest"); s.add_argument("--n", type=int, default=20)
    s.set_defaults(fn=cmd_selftest)
    a = p.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
