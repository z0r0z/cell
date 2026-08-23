"""CELL calibration harness — see BUILD.md.

The thresholds shipped in blood_gate.py are physically-reasoned starting
points. They are NOT validated on your hardware. This tool fixes that.

    python calibrate.py capture --label genuine        # record one blood sample
    python calibrate.py enroll-reference               # build REFERENCE_OXYHB
    python calibrate.py roc                            # sweep + operating point
    python calibrate.py touch-capture --label genuine  # record one 15 s session
    python calibrate.py touch-roc                      # same, for the touch tier
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
    A_MAX, IDX, REFERENCE_OXYHB, TUNABLE, SensorHead, Thresholds,
    absorbance, evaluate, metrics, speckle_metrics,
)

DATA = Path("captures")
TOUCH_DATA = Path("touch_captures")

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
    "edta":           "EDTA tube blood -- MOST IMPORTANT NEGATIVE",
    # Citrate as drawn behaves like EDTA here. Citrate RECALCIFIED before
    # loading is not in the panel because the gate does not reject it and a
    # panel class that must fail would be a lie -- BUILD.md 16 states the limit
    # in prose instead.
    "citrate":        "Citrate tube blood, loaded as drawn",
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
               "rewarmed", "edta", "citrate", "animal", "hemolyzed", "reference")

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
        edta/citrate/animal: anticoagulated, never clots -> stays liquid
        aged/rewarmed: already clotted before it got here -> starts frozen
        syrups/gels : too viscous to move -> starts frozen
        dye/empty   : no coherent scatterers at all
        """
        if self.label in ("genuine", "deoxygenated"):
            # deoxygenated blood still clots normally — it must reach G4 to be
            # rejected, not be caught early by a motion gate.
            return float(0.05 + 0.90 / (1 + np.exp(-0.014 * (self.t - 300))))
        if self.label in ("edta", "citrate", "animal"):
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

    # Emit the reference in ABSORBANCE units, unnormalised. This is not
    # cosmetic. blood_gate derives SHAPE_CHANNELS by comparing the reference
    # against A_MAX, so a reference scaled to unit length has every entry below
    # the clamp, the mask comes back all-True, and the 415 nm channel — pinned
    # at the clamp for every dark sample — re-enters the shape comparison. That
    # is the exact failure the SHAPE_CHANNELS comment warns about: measured on
    # synthetic panel data it lifts deoxygenated blood from 0.988 to 0.991
    # against a genuine 0.99996, collapsing the margin G4 exists to hold.
    # gate4 normalises internally, so magnitude here costs nothing.
    vecs = [absorbance(c["chem"][0], c["white"][0], c["dark"][0]) for c in caps]

    ref = np.mean(vecs, axis=0)
    # Spread is measured on unit-normalised copies, because it is a question
    # about spectral SHAPE consistency, not about overall sample darkness.
    unit = [v / np.linalg.norm(v) for v in vecs]
    ref_unit = ref / np.linalg.norm(ref)
    spread = float(np.mean([np.linalg.norm(v - ref_unit) for v in unit]))

    # Written into thresholds.json rather than printed for a human to paste
    # into blood_gate.py. Hand-editing source to calibrate means the firmware
    # hash changes when your optics do, so co-signers would have to re-register
    # a build for what is a calibration; it also puts an unchecked copy-paste
    # between the measurement and the device.
    out = Path(args.out) if getattr(args, "out", None) else \
        Path("thresholds.json")
    blob = json.loads(out.read_text()) if out.exists() else {}
    blob["reference_oxyhb"] = [round(float(x), 4) for x in ref]
    blob["reference_n"] = len(vecs)
    blob["reference_spread"] = round(spread, 4)
    out.write_text(json.dumps(blob, indent=2, sort_keys=True) + "\n")
    print(f"reference_oxyhb written to {out}\n")
    print("    " + ", ".join(f"{x:.4f}" for x in ref) + "\n")
    print(f"n={len(vecs)}  mean intra-class spread={spread:.4f}")
    n_clamped = int(np.sum(ref >= A_MAX - 1e-9))
    print(f"channels at the absorbance clamp: {n_clamped} "
          f"(excluded from G4 by SHAPE_CHANNELS)")
    if n_clamped == 0:
        print("WARNING: no channel reached the clamp. Genuine whole blood should "
              "pin 415 nm. Check fill depth and that the well is optically deep.")
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
        # Same quantity as the printed `margin` column, same sign convention:
        # the distance from the chosen threshold to the nearest spoof that
        # STILL PASSES that gate, so it is <=0 whenever any spoof gets through
        # and null when the gate rejects the whole panel alone. Most gates read
        # negative and that is not a fault — the gates are an AND, and dye is
        # not supposed to be caught by the clotting threshold. It is recorded
        # so a margin that moves between calibrations can be seen.
        "margins": {d[0]: (None if d[4] == float("inf") else round(d[4], 6))
                    for d in diag},
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


# --------------------------------------------------------------------------
# Touch tier
#
# The touch tier is the EVERYDAY default — it authorises far more signatures
# than the blood tier ever will — so its thresholds deserve the same treatment
# and the same file-on-the-device ending. Sessions are 15 s rather than 600 s,
# so a full panel is minutes of work rather than an afternoon.
# --------------------------------------------------------------------------

TOUCH_PANEL = {
    "genuine":       "Your own fingertip on the ring, still, 15 s",
    "no_contact":    "Nothing on the ring",
    "static_object": "Wood, a printed photo, a fingertip mould",
    "pump_fake":     "Mechanical pulsator -- the RMSSD negative",
    "dye_fake":      "Dyed silicone finger -- the ratio-of-ratios negative",
    "motion":        "Your finger, moving or tapping",
    "too_slow":      "Out-of-range rate, low",
    "too_fast":      "Out-of-range rate, high",
}


def save_touch(path: Path, red, dark_ir, bore, label: str, fs: float,
               subject: str = "", session: str = "") -> None:
    """Record one touch session.

    `subject` and `session` cost nothing to write and cannot be recovered
    afterwards. Without them a capture set says only WHAT each recording was --
    genuine, pump_fake -- and never who produced it or when. That is enough to
    calibrate the touch gate, which is all these were originally for.

    It is not enough to answer whether the pulse waveform identifies a person,
    because that question is entirely about matching one subject to themselves
    ACROSS sessions. Anyone who collects a panel without these has to collect
    it again to ask it, and the second collection is the expensive one -- it
    needs the same people back, weeks later.

    Free-form on purpose. A pseudonym is fine and preferable; nothing here
    wants a real name.
    """
    np.savez_compressed(path, red=red, ir=dark_ir, bore=np.asarray(bore, float),
                        label=np.array(label), fs=np.array(fs),
                        subject=np.array(subject), session=np.array(session))


def load_touch(path: Path) -> dict:
    z = np.load(path, allow_pickle=False)
    # Older captures predate the subject and session fields; they still load.
    return {"red": z["red"], "ir": z["ir"], "bore": tuple(z["bore"]),
            "label": str(z["label"]), "fs": float(z["fs"]),
            "subject": str(z["subject"]) if "subject" in z else "",
            "session": str(z["session"]) if "session" in z else ""}


def cmd_touch_capture(args):
    import touch_gate as tg
    if args.label not in TOUCH_PANEL:
        sys.exit(f"Unknown label. Valid: {', '.join(TOUCH_PANEL)}")
    TOUCH_DATA.mkdir(exist_ok=True)
    th = tg.TouchThresholds()
    if args.synthetic:
        red, ir, bore = tg._synth(args.label, args.seed, th)
        fs = th.fs
    else:
        # RealTouchSensor shares the spectrometer with the blood head, so it
        # takes that head rather than opening the I2C bus a second time.
        from hardware import RealSensorHead, RealTouchSensor
        print(f"[{args.label}] {TOUCH_PANEL[args.label]}")
        input(f"Press Enter, then hold still for {th.duration_s:.0f} s...")
        sensor = RealTouchSensor(RealSensorHead())
        # fs is a TARGET; the sensor reports what it achieved and that is what
        # gets stored, because every frequency-derived feature scales with it.
        red, ir, fs = sensor.read_ppg(th.duration_s, th.fs)
        bore = sensor.read_bore_reference()
    n = len(list(TOUCH_DATA.glob(f"{args.label}_*.npz")))
    path = TOUCH_DATA / f"{args.label}_{n:04d}.npz"
    save_touch(path, red, ir, bore, args.label, fs,
               subject=args.subject, session=args.session)
    res = tg.evaluate(red, ir, bore, th, fs=fs)
    print(f"saved {path}")
    for g in res.gates:
        print("  ", g)
    print(f"  => {'ACCEPT' if res.accepted else 'REJECT'}")


def cmd_touch_roc(args):
    import touch_gate as tg
    caps: dict[str, list[dict]] = {}
    for p in sorted(TOUCH_DATA.glob("*.npz")):
        c = load_touch(p)
        caps.setdefault(c["label"], []).append(c)
    if "genuine" not in caps:
        sys.exit("No genuine touch captures. Run: touch-capture --label genuine")

    n_gen = len(caps["genuine"])
    spoof_labels = [k for k in caps if k != "genuine"]
    n_spoof = sum(len(caps[k]) for k in spoof_labels)
    print(f"genuine n={n_gen}   spoof n={n_spoof} across {len(spoof_labels)} classes")
    if n_gen < MIN_PER_CLASS:
        print(f"WARNING: fewer than {MIN_PER_CLASS} genuine sessions. Indicative only.")
    missing = [k for k in TOUCH_PANEL if k not in caps]
    if missing:
        print(f"WARNING: panel classes never captured: {', '.join(missing)}")

    table: dict[str, dict[str, list]] = {}
    for label, cs in caps.items():
        for c in cs:
            for k, v in tg.features(c["red"], c["ir"], fs=c["fs"]).items():
                table.setdefault(k, {}).setdefault(label, []).append(v)

    per_th = args.frr_budget / len(tg.TUNABLE)
    chosen, diag = {}, []
    for name, (feat, sense) in tg.TUNABLE.items():
        per = table.get(feat, {})
        gen = np.asarray(per.get("genuine", []))
        parts = [np.asarray(per[c]) for c in spoof_labels if c in per]
        spf = np.concatenate(parts) if parts else np.array([])
        val, rejects, margin = _choose(gen, spf, sense, per_th, args.drift)
        q = 1e-6
        chosen[name] = (math.floor(val / q) * q if sense == "min"
                        else math.ceil(val / q) * q)
        diag.append((name, sense, val, rejects, margin, len(spf),
                     getattr(tg.TouchThresholds(), name)))

    print(f"\n  {'threshold':<18}{'sense':<6}{'shipped':>10}{'chosen':>12}"
          f"{'catches':>11}{'margin':>10}")
    print("  " + "-" * 68)
    for name, sense, val, rej, margin, n_sp, shipped in diag:
        m = "inf" if margin == float("inf") else f"{margin:.3f}"
        print(f"  {name:<18}{sense:<6}{shipped:>10.3f}{val:>12.3f}"
              f"{rej:>8}/{n_sp:<3}{m:>10}")

    th = replace(tg.TouchThresholds(), **chosen)
    acc = {lab: [tg.evaluate(c["red"], c["ir"], c["bore"], th, fs=c["fs"]).accepted
                 for c in cs] for lab, cs in caps.items()}
    frr = 1.0 - float(np.mean(acc["genuine"]))
    n_fa = sum(sum(acc[c]) for c in spoof_labels)

    print(f"\nOPERATING POINT   FRR = {frr*100:.1f}%   "
          f"spoof acceptances = {n_fa}/{n_spoof}")
    print("  In-sample, and optimistic by construction for the same reason the")
    print("  blood sweep is: these are the sessions the thresholds were fitted to.")
    report(n_fa, n_spoof)

    print("\nPER-CLASS (accepted / n) -- every non-genuine row must read 0:")
    for label in sorted(acc):
        a, n = sum(acc[label]), len(acc[label])
        want = (a == n) if label == "genuine" else (a == 0)
        print(f"  {label:<16} {a:>3}/{n:<4}{'' if want else '   <-- LOOK AT THIS'}")

    out = dict(chosen)
    out.update({
        "_comment": "Written by calibrate.py touch-roc. Loaded by "
                    "touch_gate.TouchThresholds.load().",
        "measured_frr": frr,
        "measured_far": n_fa / max(n_spoof, 1),
        "far_upper_bound_pct": (300.0 / n_spoof) if n_fa == 0 and n_spoof else None,
        "n_genuine": n_gen,
        "n_spoof": n_spoof,
        "classes": sorted(caps),
    })
    Path("touch_thresholds.json").write_text(json.dumps(out, indent=2, sort_keys=True))
    print("\nwrote touch_thresholds.json")
    print("  touch_gate.TouchThresholds.load() reads it. Put it beside")
    print("  touch_gate.py on the device, or the touch tier keeps signing on")
    print("  shipped defaults — and the touch tier is the everyday one.")
    return 0


PUF_DIR = DATA / "chamber"


def cmd_puf_capture(args):
    """One burst of the chamber, filed with the conditions it was taken in.

    The conditions are the point. A PUF panel that is twenty bursts taken in
    one sitting answers nothing: it measures shot noise, which was never the
    risk. What decides whether this ships is whether a diffuser reads the same
    after a cold night and six months of the resin settling, so every burst
    carries the temperature and the session it belongs to and the panel is
    only worth as much as their spread.
    """
    import numpy as np

    PUF_DIR.mkdir(parents=True, exist_ok=True)
    if args.synthetic:
        rng = np.random.default_rng(args.seed)
        size = 512
        e = rng.normal(size=(size, size)) + 1j * rng.normal(size=(size, size))
        fy, fx = np.fft.fftfreq(size)[:, None], np.fft.fftfreq(size)[None, :]
        e = np.fft.ifft2(np.fft.fft2(e)
                         * np.exp(-0.5 * (fy ** 2 + fx ** 2) * (2 * np.pi * 4) ** 2))
        burst = np.repeat((np.abs(e) ** 2)[None], 16, axis=0).astype(np.float32)
        burst += rng.normal(0, 0.02, burst.shape)
    else:
        from hardware import RealSensorHead
        head = RealSensorHead()
        try:
            input("Close the bay and press Enter...")
            burst = head.read_chamber_burst()
        finally:
            head.close()

    n = len(list(PUF_DIR.glob("*.npy")))
    path = PUF_DIR / f"chamber_{n:04d}.npy"
    np.save(path, burst)
    (PUF_DIR / f"chamber_{n:04d}.txt").write_text(
        f"temp_c={args.temp_c}\nsession={args.session}\n")
    print(f"saved {path}  ({args.temp_c} C, session {args.session})")


def cmd_puf_panel(args):
    """What the panel says about stability, and whether it clears the code.

    Reports the bit error rate ACROSS SESSIONS, because that is the number
    that matters -- within one sitting a diffuser will always look perfect.
    Enrols on the earliest session and measures every later one against it,
    which is what a device does: enrol once, live with it.
    """
    import numpy as np

    import optical_puf as puf

    paths = sorted(PUF_DIR.glob("*.npy"))
    if len(paths) < 3:
        sys.exit(f"Need >=3 bursts, have {len(paths)}. "
                 f"`calibrate.py puf-capture` takes them.")

    meta = []
    for p in paths:
        t = p.with_suffix(".txt")
        d = dict(ln.split("=", 1) for ln in t.read_text().split()) if t.exists() else {}
        meta.append((p, d.get("session", "?"), d.get("temp_c", "?")))

    sessions = sorted({m[1] for m in meta})
    print(f"{len(paths)} bursts over {len(sessions)} session(s), "
          f"temps {sorted({m[2] for m in meta})}")
    if len(sessions) < 2:
        print("\nOne session. This will look better than it is -- the question "
              "is\nwhether the chamber survives being left alone, and a panel "
              "taken in\none sitting cannot answer it.")

    first = [m for m in meta if m[1] == sessions[0]]
    if len(first) < 2:
        sys.exit("Enrolment needs >=2 bursts in the earliest session.")

    reads = [puf.speckle_features(np.load(p)) for p, _, _ in first]
    try:
        helper, key = puf.enroll(reads, m=args.m, t=args.t)
    except puf.PufError as e:
        sys.exit(f"Did not enrol: {e}")

    b = puf.budget(args.m, args.t)
    print(f"\nBCH(n={b['n']}, k={b['k']}, t={b['corrects']}) "
          f"corrects {b['max_ber']:.2%}")
    print(f"{'burst':<28}{'session':>9}{'temp':>7}{'BER':>9}{'key':>10}")
    print("-" * 63)

    worst, reproduced, total = 0.0, 0, 0
    for path, sess, temp in meta:
        bits, _ = puf.speckle_features(np.load(path))
        # Against the enrolled reading, on the positions enrolment kept --
        # the bits the device will actually decode.
        ber = float((bits[helper.mask] != reads[0][0][helper.mask]).mean())
        try:
            same = puf.reproduce(bits, helper) == key
        except puf.PufError:
            same = False
        total += 1
        reproduced += same
        worst = max(worst, ber)
        print(f"{path.name:<28}{sess:>9}{temp:>7}{ber:>8.2%}"
              f"{'ok' if same else 'LOST':>10}")

    print("-" * 63)
    print(f"worst BER {worst:.2%} against a {b['max_ber']:.2%} budget; "
          f"{reproduced}/{total} reproduced")
    if reproduced == total and worst < b["max_ber"] / 2:
        print("\nComfortable. The margin filter is doing its job and there is "
              "room\nleft for conditions this panel has not seen yet.")
    elif reproduced == total:
        print("\nReproduces, but inside half the budget rather than clear of "
              "it.\nTake more sessions before binding a seed to this chamber.")
    else:
        print("\nA burst failed to reproduce, so this chamber would have "
              "refused to\nsign. Either the diffuser is moving or the bay is "
              "not closing the\nsame way twice; fix that before enrolling.")


def cmd_selftest(args):
    print(f"Synthetic self-test — 6 gates, 2 sensors, {len(PANEL)} classes.")
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
    p_enroll = sub.add_parser("enroll-reference")
    p_enroll.add_argument("--out", help="thresholds.json to update")
    p_enroll.set_defaults(fn=cmd_enroll_reference)
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
    tc = sub.add_parser("touch-capture"); tc.add_argument("--label", required=True)
    tc.add_argument("--subject", default="",
                    help="who this recording is of. A pseudonym is fine and "
                         "preferred. Needed only to ask whether the waveform "
                         "identifies a person; the gate itself does not use it.")
    tc.add_argument("--session", default="",
                    help="a sitting label, e.g. a date. Identity questions are "
                         "about matching someone to themselves across sessions, "
                         "so captures from one sitting cannot answer them.")
    tc.add_argument("--synthetic", action="store_true")
    tc.add_argument("--seed", type=int, default=0)
    tc.set_defaults(fn=cmd_touch_capture)
    tr = sub.add_parser("touch-roc")
    tr.add_argument("--frr-budget", type=float, default=0.05)
    tr.add_argument("--drift", type=float, default=0.0)
    tr.set_defaults(fn=cmd_touch_roc)
    pc = sub.add_parser("puf-capture",
                        help="one burst of the chamber diffuser")
    pc.add_argument("--temp-c", default="?", help="ambient, so drift is attributable")
    pc.add_argument("--session", default="1",
                    help="bump it when the device has been left alone since")
    pc.add_argument("--synthetic", action="store_true")
    pc.add_argument("--seed", type=int, default=0)
    pc.set_defaults(fn=cmd_puf_capture)
    pp = sub.add_parser("puf-panel",
                        help="does the chamber reproduce across sessions")
    pp.add_argument("--m", type=int, default=12)
    pp.add_argument("--t", type=int, default=180)
    pp.set_defaults(fn=cmd_puf_panel)

    s = sub.add_parser("selftest"); s.add_argument("--n", type=int, default=20)
    s.set_defaults(fn=cmd_selftest)
    a = p.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
