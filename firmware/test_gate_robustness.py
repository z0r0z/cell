#!/usr/bin/env python3
"""Two properties the gate must hold that no other suite covers.

1. ENROLMENT PRESERVES THE CLAMP MASK. gate4 restricts its comparison to the
   channels not pinned at the absorbance clamp, and derives that mask from
   REFERENCE_OXYHB itself. So the reference `calibrate.py enroll-reference`
   prints has to be in the same units the mask is derived in — absorbance,
   unnormalised. Emit a unit-normalised vector instead and every entry falls
   below the clamp, the mask silently widens to all eight channels, and the
   415 nm channel (identical for every dark sample, by construction) drags
   every cosine toward 1. That is not a hypothetical: it shipped, and it cost
   the deoxyHb margin the gate exists to hold.

2. HOSTILE CAPTURES REJECT, THEY DO NOT RAISE. The unlock chain fails closed
   either way — an exception propagates and no key is derived — but a raise
   gives the owner a stack trace where a rejection would have named the gate.
   A sensor returning zeros, NaNs or a single frame is a loose connector, not
   an attack, and the device has to say so.
"""

from __future__ import annotations

import io
import contextlib
import tempfile
from pathlib import Path

import numpy as np

import blood_gate as bg
import calibrate as cal


def check(label: str, cond: bool) -> bool:
    print(f"  {label:<54}{'PASS' if cond else 'FAIL'}")
    return cond


def enrolment_preserves_the_mask() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        cal.DATA = Path(d)
        for s in range(cal.MIN_PER_CLASS):
            cal.save_capture(cal.DATA / f"genuine_{s:04d}.npz",
                             cal.synth_capture("genuine", s))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cal.cmd_enroll_reference(None)
        printed = buf.getvalue()

    body = printed.split("np.array([")[1].split("]")[0]
    ref = np.array([float(x) for x in body.split(",")])

    ok &= check("enrolled reference has all 8 channels", len(ref) == 8)
    # The load-bearing assertion: the mask this reference would produce is the
    # mask the shipped one produces. Anything that rescales the vector — a
    # normalisation, a unit change, a stray divide — breaks exactly here.
    mask = ref < bg.A_MAX - 1e-9
    ok &= check("mask derived from it matches the shipped mask",
                bool(np.array_equal(mask, bg.SHAPE_CHANNELS)))
    ok &= check("415 nm is still excluded from the shape comparison",
                not bool(mask[bg.IDX[415]]))
    ok &= check("enrolment reports exactly one clamped channel",
                "channels at the absorbance clamp: 1" in printed)
    return ok


def _capture(**over) -> dict:
    cap = cal.synth_capture("genuine", 0)
    cap.update(over)
    return cap


def hostile_captures_reject_without_raising() -> bool:
    ok = True
    z8 = np.zeros(8)
    sp = _capture()["speckle"]
    cases = {
        "all-zero sample":      _capture(chem=(z8, 0.0, 0.0)),
        "all-zero white ref":   _capture(white=(z8, 0.0, 0.0)),
        "white equals dark":    _capture(white=(z8, 0.0, 0.0), dark=(z8, 0.0, 0.0)),
        "negative counts":      _capture(chem=(-np.ones(8) * 1e4, -1e4, -1e4)),
        "NaN in the spectrum":  _capture(chem=(np.full(8, np.nan), np.nan, np.nan)),
        "no speckle at all":    _capture(speckle=[]),
        "one speckle point":    _capture(speckle=sp[:1]),
        "four speckle points":  _capture(speckle=sp[:4]),
        "flat speckle series":  _capture(speckle=[(t, 0.5, 0.5) for t, _, _ in sp]),
    }
    for label, cap in cases.items():
        try:
            res = bg.evaluate(cap)
            # Rejected, and able to say WHERE. An accepted hostile capture or a
            # rejection with no named gate are both failures.
            good = not res.accepted and res.first_failure() is not None
            good &= bool(res.user_message())
        except Exception as e:                                   # noqa: BLE001
            print(f"    {label}: RAISED {type(e).__name__}: {e}")
            good = False
        ok &= check(f"rejects, does not raise: {label}", good)

    # metrics() feeds the calibration sweep and must survive the same inputs —
    # a sweep that dies on one bad capture loses the whole panel.
    for label, cap in cases.items():
        try:
            m = bg.metrics(cap)
            good = set(m) >= {v[0] for v in bg.TUNABLE.values()}
        except Exception as e:                                   # noqa: BLE001
            print(f"    metrics({label}): RAISED {type(e).__name__}: {e}")
            good = False
        ok &= check(f"metrics survives: {label}", good)
    return ok


def run() -> int:
    print("Gate robustness — enrolment invariant, hostile captures.\n")
    print(" Enrolment")
    ok = enrolment_preserves_the_mask()
    print("\n Hostile captures")
    ok &= hostile_captures_reject_without_raising()
    print("\n" + "-" * 60)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
