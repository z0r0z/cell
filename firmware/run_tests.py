#!/usr/bin/env python3
"""Run every self-test in the firmware. No hardware required.

    python firmware/run_tests.py

This is what CI runs and what a reviewer should run first: the gate logic, the
tier policy, the attestation format, and the full calibration round trip.

Sensing thresholds are calibrated against physical samples at first build —
see BUILD.md section 13. VALIDATION.md is the verification status record.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

SUITES = [
    ("blood tier — 6 gates, 17 sample classes",
     [sys.executable, "calibrate.py", "selftest", "--n", "8"]),
    ("touch tier — 7 gates, 9 sample classes",
     [sys.executable, "touch_gate.py"]),
    ("tier policy — escalation and the floor",
     [sys.executable, "policy.py"]),
    ("attestation — BIP-340 vectors, quorum, malformed input",
     [sys.executable, "attest.py"]),
    ("secure element — PIN counter, KDF binding, wipe",
     [sys.executable, "se.py"]),
    ("unlock chain — step order, refusals, key binding",
     [sys.executable, "test_signer.py"]),
    ("gate robustness — enrolment invariant, hostile captures",
     [sys.executable, "test_gate_robustness.py"]),
]


def calibration_round_trip() -> bool:
    """capture -> roc -> thresholds.json -> Thresholds.load().

    The loop that matters most and is easiest to break silently — the
    thresholds measured on your hardware have to be the ones the device loads.
    """
    sys.path.insert(0, str(HERE))
    from blood_gate import Thresholds, evaluate           # noqa: E402
    import calibrate                                       # noqa: E402

    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        calibrate.DATA = work / "captures"
        calibrate.DATA.mkdir()
        labels = ["genuine", "dye", "ketchup", "edta", "animal",
                  "deoxygenated", "null_cartridge", "empty"]
        for lab in labels:
            for seed in range(4):
                cap = calibrate.synth_capture(lab, seed)
                calibrate.save_capture(calibrate.DATA / f"{lab}_{seed:04d}.npz", cap)

        # npz round trip must be exact — a lossy capture format silently
        # changes what the thresholds were fitted to.
        one = calibrate.load_capture(calibrate.DATA / "genuine_0000.npz")
        ref = calibrate.synth_capture("genuine", 0)
        if evaluate(one).accepted != evaluate(ref).accepted:
            print("    capture round trip changed the verdict")
            return False

        import argparse
        cwd = Path.cwd()
        try:
            import os
            os.chdir(work)
            rc = calibrate.cmd_roc(argparse.Namespace(frr_budget=0.05, drift=0.0))
        finally:
            os.chdir(cwd)
        if rc != 0:
            return False

        out = work / "thresholds.json"
        if not out.exists():
            print("    roc did not write thresholds.json")
            return False
        th = Thresholds.load(out)
        if th == Thresholds():
            print("    thresholds.json loaded but changed nothing")
            return False
        if "calibrated" not in th.provenance(out):
            print("    provenance did not report the file")
            return False
        # And the calibrated thresholds must still separate the panel.
        for lab in labels:
            for seed in range(4):
                acc = evaluate(calibrate.synth_capture(lab, seed), th).accepted
                if acc != (lab == "genuine"):
                    print(f"    calibrated thresholds misclassify {lab}")
                    return False
    return True


def touch_calibration_round_trip() -> bool:
    """touch-capture -> touch-roc -> touch_thresholds.json -> load().

    The touch tier authorises far more signatures than the blood tier, so its
    calibration deserves the same guarantee: the numbers measured on your
    hardware are the numbers the device runs.
    """
    sys.path.insert(0, str(HERE))
    import calibrate                                       # noqa: E402
    import touch_gate as tg                                # noqa: E402
    import argparse, os                                    # noqa: E402

    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        calibrate.TOUCH_DATA = work / "touch_captures"
        calibrate.TOUCH_DATA.mkdir()
        th0 = tg.TouchThresholds()
        for lab in calibrate.TOUCH_PANEL:
            for seed in range(8):
                red, ir, bore = tg._synth(lab, seed, th0)
                calibrate.save_touch(calibrate.TOUCH_DATA / f"{lab}_{seed:04d}.npz",
                                     red, ir, bore, lab, th0.fs)
        cwd = Path.cwd()
        try:
            os.chdir(work)
            rc = calibrate.cmd_touch_roc(argparse.Namespace(frr_budget=0.05, drift=0.0))
        finally:
            os.chdir(cwd)
        if rc != 0:
            return False
        out = work / "touch_thresholds.json"
        if not out.exists():
            print("    touch-roc did not write touch_thresholds.json")
            return False
        th = tg.TouchThresholds.load(out)
        if th == tg.TouchThresholds():
            print("    touch_thresholds.json loaded but changed nothing")
            return False
        # The calibrated thresholds must still separate the panel. A threshold
        # that is also an analysis parameter breaks exactly here: it is fitted
        # under one detector and then judged under another.
        for lab in calibrate.TOUCH_PANEL:
            for seed in range(8):
                red, ir, bore = tg._synth(lab, seed, th0)
                acc = tg.evaluate(red, ir, bore, th, fs=th0.fs).accepted
                if acc != (lab == "genuine"):
                    print(f"    calibrated touch thresholds misclassify {lab}")
                    return False
    return True


def main() -> int:
    failures = []
    for name, cmd in SUITES:
        print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
        r = subprocess.run(cmd, cwd=HERE)
        if r.returncode != 0:
            failures.append(name)

    name = "calibration round trip — capture, sweep, load"
    print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
    try:
        good = calibration_round_trip()
    except Exception as e:                                   # noqa: BLE001
        print(f"    raised {type(e).__name__}: {e}")
        good = False
    print("PASS" if good else "FAIL")
    if not good:
        failures.append(name)

    name = "touch calibration round trip — capture, sweep, load"
    print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
    try:
        good = touch_calibration_round_trip()
    except Exception as e:                                   # noqa: BLE001
        print(f"    raised {type(e).__name__}: {e}")
        good = False
    print("PASS" if good else "FAIL")
    if not good:
        failures.append(name)

    print("\n" + "=" * 66)
    if failures:
        print(f"FAIL — {len(failures)} suite(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS — {len(SUITES) + 2} suites.")
    print("\nUnlock chain, gate logic, tier policy, attestation and the")
    print("calibration round trip all verified. Sensing thresholds are")
    print("calibrated to your hardware at first build — BUILD.md section 13.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
