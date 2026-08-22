#!/usr/bin/env python3
"""Two properties the gate must hold that no other suite covers.

1. ENROLMENT PRESERVES THE CLAMP MASK. gate4 restricts its comparison to the
   channels not pinned at the absorbance clamp, and derives that mask from
   REFERENCE_OXYHB itself. So the reference `calibrate.py enroll-reference`
   prints has to be in the same units the mask is derived in — absorbance,
   unnormalised. Emit a unit-normalised vector instead and every entry falls
   below the clamp, the mask silently widens to all eight channels, and the
   415 nm channel (identical for every dark sample, by construction) drags
   every cosine toward 1. It shipped, and it cost the deoxyHb margin the gate
   exists to hold.

2. HOSTILE CAPTURES REJECT, THEY DO NOT RAISE. The unlock chain fails closed
   either way — an exception propagates and no key is derived — but a raise
   gives the owner a stack trace where a rejection would have named the gate.
   A sensor returning zeros, NaNs or a single frame is a loose connector, not
   an attack, and the device has to say so.
"""

from __future__ import annotations

import io
import argparse
import contextlib
import json
import tempfile
from pathlib import Path

import numpy as np
from dataclasses import replace

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
        # Enrolment writes the reference into thresholds.json, so point it at
        # the temporary directory rather than letting it touch the repo's.
        out = Path(d) / "thresholds.json"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cal.cmd_enroll_reference(argparse.Namespace(out=str(out)))
        printed = buf.getvalue()
        ref = np.array(json.loads(out.read_text())["reference_oxyhb"], dtype=float)

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

    # And the enrolled vector must be the one gate 4 actually compares
    # against, or calibration writes a file the device ignores.
    th = bg.Thresholds(reference_oxyhb=tuple(float(x) for x in ref))
    ok &= check("the gate uses the enrolled reference, not the shipped one",
                bool(np.array_equal(bg.shape_mask(th.reference_oxyhb), mask)))
    ok &= check("a genuine capture still passes against it",
                bg.evaluate(cal.synth_capture("genuine", 0), th).accepted)
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


def acquire_visits_both_cartridge_stops() -> bool:
    """The white patch and the well are at different insertion depths, so the
    ORDER of calls is the only thing that puts each read at the right stop.

    White and dark are read at stop 1, then the cartridge moves to stop 2, and
    everything after that reads the sample. Get it wrong and the white
    reference is a reading of the sample against itself: absorbance goes to
    zero and genuine blood is rejected at G1 as "far too bright". hardware.py
    refuses both mistakes, but nothing there runs off-device, so the ordering
    contract is pinned here.
    """
    order: list[str] = []

    class RecordingHead(bg.SensorHead):
        def __init__(self):
            self.real = cal.SyntheticHead("genuine", 0)

        def read_white_reference(self):
            order.append("white")
            return self.real.read_white_reference()

        def read_dark(self):
            order.append("dark")
            return self.real.read_dark()

        def await_sample_position(self):
            order.append("stop2")

        def read_channels(self):
            order.append("chem")
            return self.real.read_channels()

        def read_speckle_burst(self):
            order.append("speckle")
            return self.real.read_speckle_burst()

    th = bg.Thresholds()
    # A short capture: the ordering is what matters, not ten minutes of it.
    short = replace(th, duration_s=0.4, chemistry_at_s=0.1, speckle_period_s=0.15)
    bg.acquire(RecordingHead(), short, early_abort=False)

    def before(a: str, b: str) -> bool:
        """a happens, b happens, and a comes first.

        Membership is checked rather than assumed: with the hook missing
        entirely, .index() raised and the suite died with a traceback instead
        of reporting a failure. A test that crashes tells you less than one
        that fails.
        """
        return a in order and b in order and order.index(a) < order.index(b)

    ok = True
    ok &= check("white is read before dark", before("white", "dark"))
    ok &= check("both stop-1 reads happen before the cartridge moves",
                before("dark", "stop2"))
    ok &= check("the cartridge reaches stop 2 before the sample is read",
                before("stop2", "chem"))
    ok &= check("no speckle is captured at stop 1", before("stop2", "speckle"))
    ok &= check("the sample position is awaited exactly once",
                order.count("stop2") == 1)
    return ok


def run() -> int:
    print("Gate robustness — enrolment invariant, hostile captures.\n")
    print(" Enrolment")
    ok = enrolment_preserves_the_mask()
    print("\n Hostile captures")
    ok &= hostile_captures_reject_without_raising()
    print("\n Cartridge stops")
    ok &= acquire_visits_both_cartridge_stops()
    print("\n" + "-" * 60)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
