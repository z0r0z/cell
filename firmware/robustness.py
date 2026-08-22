#!/usr/bin/env python3
"""CELL robustness sweep — how much margin the thresholds actually have.

The spoof panel answers "does the gate separate blood from ketchup". It does
not answer "how far can this device drift before it stops working", and that is
the question that decides whether a build survives contact with a real
workshop: an aging LED, a printer that lays down a slightly different white, a
chamber that leaks a little ambient, a sensor with read noise.

Two different things are measured here, and they are not the same claim.

  INVARIANCE. The design asserts that some disturbances are cancelled outright.
    LED aging and integration-time drift are divided out by the cartridge's own
    white patch; ambient leak and dark current are subtracted by the LEDs-off
    read. Those are claims about the code, and they are testable without any
    hardware: perturb the capture and the gate scores must not move. A sweep
    that finds a "tolerance" here has found a BUG, because the answer is
    supposed to be infinity.

  MARGIN. Everything else has a finite budget. Print variation moves the white
    patch alone. Fill volume and alignment move the sample alone. Read noise
    moves everything independently. For those the useful number is the largest
    disturbance at which the panel still reads correctly, found by bisection.

What this is NOT: evidence about physics. The panel comes from a synthetic
head whose spectra were written to be plausible, so it cannot tell you the
Soret gate discriminates in the real world. It tells you how much slack the
IMPLEMENTATION has around whatever the true numbers turn out to be — which is
exactly what you want to know before spending money on optics.

    python robustness.py            # the sweep
    python robustness.py --quick    # fewer seeds, for CI
"""

from __future__ import annotations

import argparse
import copy
from functools import lru_cache

import numpy as np

import blood_gate as bg
from calibrate import SyntheticHead, synth_capture

@lru_cache(maxsize=None)
def _base(label: str, seed: int) -> dict:
    """One synthetic capture, generated once.

    Every perturbation is applied to a copy afterwards, so the same base is
    reused across the whole bisection. Without this the sweep regenerates a
    600 s speckle series thousands of times and takes minutes to say nothing
    new.
    """
    return synth_capture(label, seed)


# Genuine plus the spoofs that sit closest to it. deoxygenated is G4's negative
# and edta is G6's, so a drift that breaks either shows up here first.
GENUINE = "genuine"
SPOOFS = ("deoxygenated", "edta", "ketchup", "dye", "hemolyzed")


# --------------------------------------------------------------------------
# Perturbations. Each takes a capture and a magnitude, and returns a new one.
#
# WHERE a disturbance lands is the whole point. LED aging dims the sample and
# the white patch together, because one lamp lights both; print variation moves
# the patch alone, because it is a property of the part. Applying either to the
# wrong term would manufacture a result.
# --------------------------------------------------------------------------


def _scaled(cap: dict, key: str, factor) -> dict:
    out = copy.deepcopy(cap)
    f8, clear, nir = out[key]
    out[key] = (np.asarray(f8) * factor, clear * np.mean(factor),
                nir * np.mean(factor))
    return out


def led_aging(cap: dict, m: float) -> dict:
    """Both lamps dim by m. Sample and white patch are lit by the same source,
    so both fall together — this is exactly what the patch exists to cancel."""
    out = _scaled(cap, "chem", 1.0 - m)
    return _scaled(out, "white", 1.0 - m)


def spectral_tilt(cap: dict, m: float) -> dict:
    """LEDs do not age uniformly across the band. A linear tilt of +-m across
    the eight channels, again applied to sample and patch together.

    Divides out exactly while every channel is below the absorbance clamp,
    which is why the tolerated tilt is enormous rather than infinite: past that
    point a clamped channel holds A_MAX no matter what the tilt did, and the
    shape the SAM gate compares is no longer the shape that was normalised.
    """
    tilt = 1.0 + m * np.linspace(-1.0, 1.0, 8)
    out = _scaled(cap, "chem", tilt)
    return _scaled(out, "white", tilt)


def integration_drift(cap: dict, m: float) -> dict:
    """Integration time or gain moves by m. Scales every lit reading."""
    out = _scaled(cap, "chem", 1.0 + m)
    return _scaled(out, "white", 1.0 + m)


def ambient_leak(cap: dict, m: float) -> dict:
    """A constant leak into the chamber, present in every read INCLUDING the
    dark one. The LEDs-off subtraction is supposed to remove it."""
    add = m * 65535.0
    out = copy.deepcopy(cap)
    for key in ("chem", "white", "dark"):
        f8, clear, nir = out[key]
        out[key] = (np.asarray(f8) + add, clear + add, nir + add)
    return out


def print_variation(cap: dict, m: float) -> dict:
    """The printed white patch is m brighter or darker than nominal. A property
    of the cartridge, so it moves the reference and NOT the sample. This is the
    one BUILD.md section 13 milestone 3 budgets at 3%."""
    return _scaled(cap, "white", 1.0 + m)


def sample_return(cap: dict, m: float) -> dict:
    """Fill volume, meniscus, alignment: the sample returns m more or less
    light. Moves the sample alone."""
    return _scaled(cap, "chem", 1.0 + m)


def read_noise(cap: dict, m: float, rng=None) -> dict:
    """Independent gaussian noise on every count, as a fraction of full scale.
    Nothing cancels this; it is the sensor's own floor."""
    rng = rng or np.random.default_rng(0)
    out = copy.deepcopy(cap)
    for key in ("chem", "white", "dark"):
        f8, clear, nir = out[key]
        # A noise magnitude has no sign; the bisection tries both directions
        # and would otherwise hand this a negative standard deviation.
        s = abs(m) * 65535.0
        out[key] = (np.asarray(f8) + rng.normal(0, s, 8),
                    clear + rng.normal(0, s), nir + rng.normal(0, s))
    return out


CHEM_AXES = {
    "LED aging (both lamps)":      (led_aging, "invariant"),
    # Cancelled exactly in the linear regime — the same tilt divides out of
    # sample and patch alike. The finite answer comes from the absorbance
    # clamp: a large enough tilt pushes different channels onto A_MAX, and a
    # clamped channel no longer carries the tilt it was supposed to cancel. So
    # this is a budget, and the measured one is far past any real LED.
    "LED spectral tilt":           (spectral_tilt, "margin"),
    "integration / gain drift":    (integration_drift, "invariant"),
    "ambient leak into chamber":   (ambient_leak, "invariant"),
    "white patch print variation": (print_variation, "margin"),
    "sample return (fill, aim)":   (sample_return, "margin"),
    "sensor read noise":           (read_noise, "margin"),
}


# --------------------------------------------------------------------------
# Speckle disturbances, applied to the frames themselves
# --------------------------------------------------------------------------


def speckle_series(label: str, seed: int, th: bg.Thresholds,
                   cam_noise: float = 0.0, envelope: float = 0.0):
    """Regenerate a decorrelation series with camera noise and a beam envelope.

    The envelope is the interesting one. It is static frame to frame, so it
    inflates raw correlation and would read as a frozen speckle field — a
    genuine sample looking clotted from the first second. blood_gate high-passes
    each frame to remove it, and this is what tests that the high-pass works at
    a realistic envelope depth rather than in principle.
    """
    h = SyntheticHead(label, seed)
    rng = np.random.default_rng(seed + 991)
    yy, xx = np.mgrid[0:64, 0:64]
    env = 1.0 + envelope * np.exp(-(((xx - 26) ** 2 + (yy - 38) ** 2) / (2 * 22.0 ** 2)))
    out, t = [], 0.0
    while t < th.duration_s:
        h.t = t
        fr = h.read_speckle_burst() * env
        if cam_noise:
            fr = fr + rng.normal(0, cam_noise, fr.shape)
        D, K = bg.speckle_metrics(fr, th)
        out.append((t, D, K))
        t += th.speckle_period_s
    return out


def speckle_capture(label: str, seed: int, th: bg.Thresholds,
                    cam_noise: float, envelope: float) -> dict:
    cap = copy.deepcopy(_base(label, seed))
    cap["speckle"] = speckle_series(label, seed, th, cam_noise, envelope)
    return cap


# --------------------------------------------------------------------------
# Sweep
# --------------------------------------------------------------------------


def panel_correct(caps: list[tuple[str, dict]], th: bg.Thresholds) -> bool:
    """Genuine accepted, every spoof rejected. The whole panel, not a score."""
    for label, cap in caps:
        if bg.evaluate(cap, th).accepted != (label == GENUINE):
            return False
    return True


def _caps(seeds: int, perturb, m: float, th: bg.Thresholds):
    out = []
    for s in range(seeds):
        out.append((GENUINE, perturb(_base(GENUINE, s), m)))
        for sp in SPOOFS:
            out.append((sp, perturb(_base(sp, s), m)))
    return out


def tolerance(perturb, th: bg.Thresholds, seeds: int, hi: float = 0.60,
              signed: bool = True) -> float:
    """Largest |m| at which the panel still reads correctly, by bisection.

    Both signs are tried at every step and the worse one decides, because a
    disturbance that is harmless in one direction is rarely harmless in both:
    a dimmer sample walks toward G1's floor, a brighter one toward its ceiling.
    """
    def ok(m: float) -> bool:
        mags = (m, -m) if signed else (m,)
        return all(panel_correct(_caps(seeds, perturb, x, th), th) for x in mags)

    if not ok(1e-4):
        return 0.0
    lo = 1e-4
    if ok(hi):
        return hi
    for _ in range(12):
        mid = (lo + hi) / 2
        if ok(mid):
            lo = mid
        else:
            hi = mid
    return lo


def first_failure(perturb, th: bg.Thresholds, m: float) -> str:
    """Which gate gives way first at magnitude m. Where to spend bench time."""
    cap = perturb(_base(GENUINE, 0), m)
    g = bg.evaluate(cap, th).first_failure()
    if g:
        return g.name
    for sp in SPOOFS:
        r = bg.evaluate(perturb(_base(sp, 0), m), th)
        if r.accepted:
            return f"{sp} accepted"
    return "-"


def sweep(seeds: int = 3, th: bg.Thresholds | None = None) -> dict:
    th = th or bg.Thresholds()
    rows = []
    for name, (fn, kind) in CHEM_AXES.items():
        tol = tolerance(fn, th, seeds)
        gate = first_failure(fn, th, min(tol * 1.6 + 0.02, 0.9)) if tol < 0.6 else "-"
        rows.append((name, kind, tol, gate))
    return {"chem": rows, "seeds": seeds}


def speckle_sweep(th: bg.Thresholds | None = None, seeds: int = 2) -> list:
    """Camera noise and beam envelope, swept over the frames themselves."""
    th = th or bg.Thresholds()
    rows = []
    for label, kind, grid in (
            ("camera read noise", "margin", (0.0, 0.05, 0.1, 0.2, 0.4, 0.8)),
            ("beam envelope depth", "invariant", (0.0, 0.5, 1.0, 2.0, 4.0, 8.0))):
        worst = None
        for m in grid:
            good = True
            for s in range(seeds):
                kw = ({"cam_noise": m} if "noise" in label else {"envelope": m})
                gen = speckle_capture(GENUINE, s, th, kw.get("cam_noise", 0.0),
                                      kw.get("envelope", 0.0))
                edta = speckle_capture("edta", s, th, kw.get("cam_noise", 0.0),
                                       kw.get("envelope", 0.0))
                if not bg.evaluate(gen, th).accepted or bg.evaluate(edta, th).accepted:
                    good = False
                    break
            if good:
                worst = m
            else:
                break
        rows.append((label, kind, worst, grid[-1]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="fewer seeds, for CI")
    a = ap.parse_args()
    seeds = 1 if a.quick else 3
    th = bg.Thresholds()

    print("CELL robustness sweep — margin around the shipped thresholds")
    print("Synthetic panel: this measures the implementation's slack, not the "
          "physics.\n")

    res = sweep(seeds, th)
    print("CHEMISTRY")
    print(f"  {'disturbance':<30}{'claim':<11}{'tolerated':>11}   first to give way")
    print("  " + "-" * 74)
    ok = True
    budgets: list[tuple[float, str, str]] = []
    for name, kind, tol, gate in res["chem"]:
        if kind == "invariant":
            # The design says the patch or the dark read removes this outright,
            # so anything short of the sweep ceiling means it does not.
            good = tol >= 0.60
            verdict = "cancelled" if good else f"BREAKS at {tol*100:.1f}%"
        else:
            # A margin is a measurement, not a verdict. The only failure here
            # is a threshold set that does not work even undisturbed, which
            # would mean the shipped defaults are broken outright.
            good = tol > 0.0
            verdict = f"{tol*100:.1f}%"
            budgets.append((tol, name, gate))
        ok &= good
        print(f"  {name:<30}{kind:<11}{verdict:>11}   {gate}")

    print("\nSPECKLE")
    print(f"  {'disturbance':<30}{'claim':<11}{'tolerated':>11}")
    print("  " + "-" * 56)
    for name, kind, tol, ceiling in speckle_sweep(th, seeds=max(1, seeds - 1)):
        if kind == "invariant":
            good = tol is not None and tol >= ceiling
            verdict = "cancelled" if good else f"BREAKS at {tol}"
        else:
            good = tol is not None and tol > 0.0
            verdict = f"{tol}" if tol is not None else "0"
        ok &= good
        print(f"  {name:<30}{kind:<11}{verdict:>11}")

    if budgets:
        tol, name, gate = min(budgets)
        print(f"\nTIGHTEST BUDGET   {name}: {tol*100:.2f}% of full scale, "
              f"and {gate} is what gives way.")
        print("  This is the number the reader kit should be built to measure")
        print("  first. Everything else has an order of magnitude more slack.")

    print("\n  invariant = the design claims this is divided or subtracted out,")
    print("              so a finite tolerance here is a BUG, not a budget.")
    print("  margin    = a real budget. The smallest one is what the reader kit")
    print("              should be instrumented to measure first.")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
