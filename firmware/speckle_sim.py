#!/usr/bin/env python3
"""CELL speckle simulator — can the camera resolve clotting at all?

`calibrate.SyntheticHead` fakes the speckle series as a linear blend of a
frozen field and fresh noise, with the blend driven by a logistic in time. That
is enough to exercise the pipeline and it is useless for answering the question
that decides whether the optical path works, because the blend has no exposure
time, no frame interval and no correlation time in it. It cannot tell you the
camera is too slow, because it has no camera.

This model has the physics that matters:

  The scattered field decorrelates with a characteristic time TAU_C. Red cells
  in liquid plasma move, so tau_c is short; as fibrin locks them in place
  tau_c rises by orders of magnitude. That rise IS clotting, as the speckle
  sees it.

  Each frame integrates intensity over the EXPOSURE. If the exposure is long
  compared with tau_c, the frame is already a time-average of many independent
  speckle patterns: contrast collapses toward zero and every frame looks like
  every other one. A blurred frame is a correlated frame, so a too-long
  exposure makes moving blood look ARRESTED. That is the failure this file
  exists to find, and it fails toward false accept.

  Consecutive frames are separated by the FRAME INTERVAL. Frame-to-frame
  correlation is set by how much the field has decorrelated in that gap, so a
  clot is only visible as "arrested" if tau_c has risen to be comparable with
  the interval. A camera that is too slow sees everything as decorrelated.

The field is an Ornstein-Uhlenbeck process: complex Gaussian, spatially
filtered to a chosen grain size, relaxing with tau_c. Intensity is |E|^2, so
the model reproduces fully developed speckle (contrast 1 at zero exposure)
without that being put in by hand.

    python speckle_sim.py             # the sweep
    python speckle_sim.py --quick     # coarser, for CI
"""

from __future__ import annotations

import argparse

import numpy as np
from scipy.ndimage import gaussian_filter

import blood_gate as bg

ROI = 64
FRAMES = 16


# The field is built on a finer grid than the sensor and then binned down, so
# a grain SMALLER than a pixel is representable. That is the whole point of
# BUILD.md section 9's 3-5 px autocorrelation check: if several grains land
# inside one pixel, the pixel averages them, contrast falls as 1/sqrt(grains
# per pixel), and G5's contrast floor is what catches it. Filtering directly on
# the sensor grid cannot show this — sub-pixel grain just looks like white
# noise at full contrast, and the sweep reports "resolved" at every grain size.
SUPERSAMPLE = 4


def _field(rng, roi: int, grain_px: float) -> np.ndarray:
    """A complex Gaussian speckle field, sampled the way the sensor samples it.

    Returned as the FIELD on the fine grid; binning to sensor pixels happens on
    intensity, because that is where the averaging physically occurs.
    """
    fine = roi * SUPERSAMPLE
    sigma = max(grain_px * SUPERSAMPLE / 2.355, 1e-6)
    a = gaussian_filter(rng.normal(0, 1, (fine, fine)), sigma)
    b = gaussian_filter(rng.normal(0, 1, (fine, fine)), sigma)
    e = a + 1j * b
    return e / np.sqrt(np.mean(np.abs(e) ** 2))


def _bin(img: np.ndarray, roi: int) -> np.ndarray:
    """Average the fine grid down onto sensor pixels."""
    return img.reshape(roi, SUPERSAMPLE, roi, SUPERSAMPLE).mean(axis=(1, 3))


# Sub-samples per exposure. This is the model's time resolution and it is not
# a free parameter: the exposure averages exposure/tau_c independent speckle
# patterns, and averaging N of them takes contrast to 1/sqrt(N). Fix `sub` too
# low and the model cannot average past 1/sqrt(sub), which floors K and hides
# exactly the failure this file was written to look for. Measured: at sub=12 a
# 50 ms exposure reported K=0.27 and looked safe, when the real answer is
# closer to 0.08 and fails G5.
SUB_MIN, SUB_MAX = 12, 220


def _sub_steps(exposure_s: float, tau_c_s: float) -> int:
    return int(np.clip(8.0 * exposure_s / tau_c_s, SUB_MIN, SUB_MAX))


def burst(tau_c_s: float, exposure_s: float, interval_s: float,
          grain_px: float = 4.0, roi: int = ROI, frames: int = FRAMES,
          read_noise: float = 0.0, seed: int = 0,
          sub: int | None = None) -> np.ndarray:
    """Frames from a field with correlation time tau_c.

    Each frame integrates across the exposure, then the field is advanced
    across the rest of the frame interval. Both matter: the first sets
    contrast, the second sets frame-to-frame correlation. The number of
    sub-samples follows the exposure-to-tau_c ratio — see SUB_MAX.
    """
    sub = sub or _sub_steps(exposure_s, tau_c_s)
    rng = np.random.default_rng(seed)
    e = _field(rng, roi, grain_px)
    dt = exposure_s / sub
    a_sub = np.exp(-dt / tau_c_s)
    gap = max(interval_s - exposure_s, 0.0)
    a_gap = np.exp(-gap / tau_c_s)

    def step(e, a):
        if a >= 1.0 - 1e-12:
            return e
        fresh = _field(rng, roi, grain_px)
        return a * e + np.sqrt(max(1.0 - a * a, 0.0)) * fresh

    out = np.empty((frames, roi, roi))
    fine = roi * SUPERSAMPLE
    for k in range(frames):
        acc = np.zeros((fine, fine))
        for _ in range(sub):
            acc += np.abs(e) ** 2
            e = step(e, a_sub)
        out[k] = _bin(acc / sub, roi)
        e = step(e, a_gap)
    if read_noise:
        out = out + rng.normal(0, read_noise, out.shape)
    return out


def measure(tau_c_s: float, exposure_s: float, interval_s: float, **kw):
    """(D, K) as blood_gate would compute them from such a burst."""
    return bg.speckle_metrics(burst(tau_c_s, exposure_s, interval_s, **kw))


# --------------------------------------------------------------------------
# Sweeps. Each answers one question the linear-blend model cannot.
# --------------------------------------------------------------------------


def operating_window(exposure_s: float, interval_s: float, th: bg.Thresholds,
                     grain_px: float = 4.0, seed: int = 1,
                     grid=None) -> tuple[float, float]:
    """(longest tau_c still read as LIQUID, shortest read as ARRESTED).

    The gap between them is the transition the sample has to cross for the two
    motion gates to both fire. A sample whose tau_c lands inside the gap reads
    as neither: not moving freely, not arrested. That is a rejection, so the
    gap costs false rejects rather than false accepts — but it has to be
    crossable, or no real clot ever satisfies G6.
    """
    grid = grid or np.logspace(-5, 1.3, 26)
    liquid_max, clot_min = None, None
    for tau in grid:
        D, K = measure(tau, exposure_s, interval_s, grain_px=grain_px, seed=seed)
        if D >= th.d_liquid_min and K >= th.speckle_contrast_min:
            liquid_max = tau
        if D <= th.d_clot_max and clot_min is None:
            clot_min = tau
    return liquid_max, clot_min


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    th = bg.Thresholds()
    ok = True

    print("CELL speckle simulator — what the optical path can actually resolve")
    print("Ornstein-Uhlenbeck field, exposure-integrated. Physics, not a blend.\n")

    # The model must reproduce known limits, or nothing below means anything.
    print("MODEL SANITY")
    d_frozen, k_frozen = measure(1e6, 2e-3, 33e-3, seed=3)
    d_fast, k_fast = measure(1e-6, 2e-3, 33e-3, seed=3)
    checks = [
        ("a frozen field does not decorrelate", d_frozen < 0.05, f"D={d_frozen:.3f}"),
        ("a frozen field has full speckle contrast", k_frozen > 0.5, f"K={k_frozen:.3f}"),
        ("fast motion decorrelates between frames", d_fast > 0.6, f"D={d_fast:.3f}"),
        ("fast motion is blurred by the exposure", k_fast < k_frozen / 2,
         f"K={k_fast:.3f} vs {k_frozen:.3f}"),
    ]
    for label, good, detail in checks:
        ok &= good
        print(f"  {label:<44}{detail:>18}  {'PASS' if good else 'FAIL'}")

    # 1. Exposure. Too long and every frame is a time-average: contrast dies,
    #    frames look alike, and MOVING blood reads as arrested — a false accept.
    print("\nEXPOSURE  (interval 33 ms, tau_c 0.3 ms — liquid blood)")
    print(f"  {'exposure':>10} {'K':>7} {'D':>7}   verdict")
    worst_exposure = None
    for exp_ms in ([1, 5, 20] if a.quick else [0.5, 1, 2, 5, 10, 20, 50]):
        D, K = measure(3e-4, exp_ms * 1e-3, 33e-3, seed=2)
        good = K >= th.speckle_contrast_min and D >= th.d_liquid_min
        if good:
            worst_exposure = exp_ms
        print(f"  {exp_ms:>8.1f}ms {K:>7.3f} {D:>7.3f}   "
              f"{'liquid blood still reads liquid' if good else 'FAILS G5'}")
    print(f"  -> the 2 ms specified in BUILD.md section 9 has room; liquid still "
          f"reads correctly at {worst_exposure} ms")
    ok &= worst_exposure is not None and worst_exposure >= 2

    # 2. Frame interval. Arrest is only visible once tau_c is comparable with
    #    the gap between frames, so the camera's rate sets how still a clot has
    #    to be before G6 will call it still.
    print("\nFRAME INTERVAL  (exposure 2 ms)")
    print(f"  {'interval':>10} {'liquid up to':>14} {'arrest needs':>14}")
    for fps in ([30] if a.quick else [10, 30, 60, 120]):
        iv = 1.0 / fps
        lo, hi = operating_window(2e-3, iv, th, seed=1)
        lo_s = f"{lo*1e3:.1f} ms" if lo else "-"
        hi_s = f"{hi*1e3:.0f} ms" if hi else "never"
        print(f"  {fps:>7} fps {lo_s:>14} {hi_s:>14}")

    # 3. Grain. BUILD.md section 9 checks 3-5 px by autocorrelation at bring-up.
    #    Undersample it and the field decorrelates below the pixel pitch, so a
    #    clot never looks still.
    # Grain has to be checked on a LIQUID sample. A frozen field is frozen at
    # any grain, so an arrested sample cannot show undersampling; what it
    # breaks is contrast, and contrast is what G5 tests before it looks at
    # anything else.
    print("\nSPECKLE GRAIN  (exposure 2 ms, 30 fps, liquid sample tau_c = 0.3 ms)")
    print(f"  {'grain':>8} {'K':>7} {'D':>7}   verdict")
    for g in ([0.7, 4.0] if a.quick else [0.5, 0.7, 1.0, 2.0, 4.0, 8.0]):
        D, K = measure(3e-4, 2e-3, 33e-3, grain_px=g, seed=4)
        good = K >= th.speckle_contrast_min
        print(f"  {g:>6.1f}px {K:>7.3f} {D:>7.3f}   "
              f"{'resolved' if good else 'UNDERSAMPLED — K below the G5 floor'}")

    lo, hi = operating_window(2e-3, 33e-3, th, seed=1)
    print(f"\nOPERATING WINDOW at the specified 2 ms / 30 fps / 4 px:")
    print(f"  reads LIQUID   for tau_c up to {lo*1e3:.0f} ms")
    print(f"  reads ARRESTED for tau_c from  {hi*1e3:.0f} ms")
    print(f"  so clotting must raise tau_c by at least {hi/lo:.0f}x, through a")
    print(f"  band where the sample reads as neither and is rejected.")
    print("\n  This is a requirement on the SAMPLE, and it is the one number")
    print("  the reader kit should measure first on the speckle path: record")
    print("  tau_c against time for one genuine clot and check it crosses.")
    ok &= lo is not None and hi is not None and hi > lo

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
