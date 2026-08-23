#!/usr/bin/env python3
"""Bench checks — the things only the built device can answer.

`run_tests.py` proves the firmware is right about itself. It cannot tell you
whether this chip enforces what its datasheet says, whether these switches
settle inside the debounce window, or whether this panel starts drawing at the
pixel the driver thinks it does. Each of those is a real failure mode, each
one is invisible until it bites, and each takes under a minute to settle with
the parts in front of you.

    tools/bench.py atecc     the gate chip's PIN counter, tested by behaviour
    tools/bench.py buttons   how long your switches actually bounce
    tools/bench.py display   whether the panel's origin matches the driver's

VALIDATION.md lists these as open. This is how they close.

WHY BEHAVIOUR RATHER THAN CONFIGURATION, for the ATECC608B. The guarantee that
matters is "the wrapping key cannot be derived without spending a PIN
attempt". That is configuration — slot 0's ReqAuth binding — and the obvious
check is to read the config zone back and decode the bits. This tool does not
do that, deliberately. Decoding those bits means hard-coding a layout, being
wrong about it is silent, and the config zone locks permanently. Asking the
chip to misbehave and watching it refuse tests the property itself and cannot
be wrong about the encoding.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

RESULTS: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  {label:<52}{'PASS' if ok else 'FAIL'}")
    if detail:
        print(f"      {detail}")
    RESULTS.append((label, ok, detail))
    return ok


# --------------------------------------------------------------------------
# The gate chip
# --------------------------------------------------------------------------


def cmd_atecc(args) -> int:
    """Test the PIN counter by trying to walk around it.

    THIS WIPES THE CHIP. Ten wrong PINs is the whole point of the exercise, and
    a counter that survives being tested is a counter that was never tested. Do
    it on a chip that holds nothing, before the device is provisioned.
    """
    from se import PinLockout
    from se_atecc import ATECC608B, DeviceError
    import signer

    if not args.i_can_wipe_this_chip:
        print("This test spends every PIN attempt the chip has and wipes it.")
        print("Run it on a chip that holds no seed, then re-provision:")
        print("\n    tools/bench.py atecc --i-can-wipe-this-chip\n")
        return 1

    print("ATECC608B — the PIN counter, tested by behaviour\n")
    try:
        se = ATECC608B()
    except DeviceError as e:
        print(f"  no usable chip: {e}")
        return 1

    check("the chip answers and both zones are locked", True)
    start = se.attempts_remaining()
    check("it reports a PIN budget", start > 0, f"{start} attempts remaining")

    # THE ONE THAT MATTERS. If the wrapping key can be derived without a PIN,
    # the counter is decoration: an attacker never calls verify_pin, they
    # derive once per candidate PIN and let AES-GCM's tag tell them when they
    # guessed right. That is slot 0's ReqAuth binding, and this is the only
    # honest way to ask whether it is really there.
    denied = False
    try:
        se.kdf(signer.unwrap_context(args.pin))
    except (PinLockout, DeviceError):
        denied = True
    check("the wrapping key CANNOT be derived without a PIN", denied,
          "" if denied else
          "SLOT 0 IS NOT BOUND TO THE PIN SLOT. The attempt counter does not "
          "protect the seed. Reconfigure before provisioning:\n"
          "        python3 tools/atecc_config.py plan")

    ok_pin = se.verify_pin(args.pin)
    if not check("the correct PIN is accepted", ok_pin,
                 "" if ok_pin else "wrong --pin, or the verifier was never written"):
        return 1
    check("a correct PIN restores the budget", se.attempts_remaining() == start)

    key1 = se.kdf(signer.unwrap_context(args.pin))
    check("...and authorises a derive", len(key1) == 32)

    second = False
    try:
        se.kdf(signer.unwrap_context(args.pin))
    except (PinLockout, DeviceError):
        second = True
    check("one PIN authorises exactly one derive", second)

    before = se.counter()
    se.verify_pin("0" * len(args.pin) if args.pin != "0" * len(args.pin) else "1" * len(args.pin))
    check("a wrong PIN spends an attempt", se.attempts_remaining() < start)
    check("the operation counter only moves forward", se.counter() >= before)

    print("\n  spending the rest of the budget — the chip should wipe\n")
    wiped = False
    for i in range(start + 2):
        try:
            if se.verify_pin("9" * len(args.pin)):
                break
        except PinLockout:
            wiped = True
            check(f"wiped after {i + 2} wrong PINs", True)
            break
    if not wiped:
        check("the chip wipes when the budget is exhausted", False,
              "It kept accepting attempts. The counter is not enforcing a limit.")

    inert = False
    try:
        se.verify_pin(args.pin)
        se.kdf(signer.unwrap_context(args.pin))
    except (PinLockout, DeviceError):
        inert = True
    check("a wiped chip derives nothing", inert)

    print("\n  This asks whether the chip BEHAVES. For whether its config zone")
    print("  says what it should, and whether the two PIN slots are")
    print("  indistinguishable, run this before you lock the data zone:")
    print("        python3 tools/atecc_config.py verify --behaviour")
    print("\n  Re-provision before use: tools/provision.py new --out /boot/cell")
    return 0 if all(ok for _, ok, _ in RESULTS) else 1


# --------------------------------------------------------------------------
# The switches
# --------------------------------------------------------------------------


def cmd_buttons(args) -> int:
    """Measure how long each switch actually bounces.

    buttons.py debounces at 30 ms, which is a common figure and not a
    measurement of YOUR switches. A switch that rings longer produces phantom
    presses; on CONFIRM that is a signature the owner did not give. Cheap
    tactile switches vary, and they get worse with age.
    """
    try:
        from gpiozero import Button
    except ImportError:
        print("gpiozero is not installed: apt install python3-gpiozero")
        return 1
    import buttons as btn

    pins = {"UP": btn.PIN_UP, "DOWN": btn.PIN_DOWN,
            "BACK": btn.PIN_BACK, "CONFIRM": btn.PIN_CONFIRM}
    print("Switch bounce — press each button when prompted\n")
    print(f"  the firmware debounces at {btn.DEBOUNCE_S * 1000:.0f} ms\n")

    worst = 0.0
    for name, pin in pins.items():
        # bounce_time=None so we see the raw edges rather than the filtered
        # ones. That is the whole measurement.
        b = Button(pin, pull_up=True, bounce_time=None)
        edges: list[float] = []
        b.when_pressed = lambda: edges.append(time.monotonic())
        b.when_released = lambda: edges.append(time.monotonic())

        print(f"  press {name} ({args.presses}x) ", end="", flush=True)
        spans = []
        for _ in range(args.presses):
            edges.clear()
            deadline = time.monotonic() + 15
            while not edges and time.monotonic() < deadline:
                time.sleep(0.002)
            if not edges:
                print("  timed out")
                break
            time.sleep(0.5)                 # let the ringing finish
            spans.append((edges[-1] - edges[0]) * 1000 if len(edges) > 1 else 0.0)
            print(".", end="", flush=True)
        b.close()

        if not spans:
            check(f"{name}: measured", False, "no press seen")
            continue
        peak = max(spans)
        worst = max(worst, peak)
        detail = (f"worst {peak:.1f} ms, median {statistics.median(spans):.1f} ms, "
                  f"{len(spans)} presses")
        print()
        check(f"{name}: settles inside the debounce window",
              peak < btn.DEBOUNCE_S * 1000, detail)

    if worst >= btn.DEBOUNCE_S * 1000:
        print(f"\n  Raise buttons.DEBOUNCE_S above {worst / 1000:.3f} s, or replace")
        print("  the switch. CONFIRM is the one to care about.")
    return 0 if all(ok for _, ok, _ in RESULTS) else 1


# --------------------------------------------------------------------------
# The panel
# --------------------------------------------------------------------------


def cmd_display(args) -> int:
    """Draw a frame the width of the panel, so a wrong origin is visible.

    Many 1.3" 240x240 ST7789 modules do not start at (0, 0): the controller
    addresses a 240x320 area and the glass is a window into it, so a driver
    with the wrong offset silently loses a row or a column. On this device
    that is the bottom line of a confirmation screen — which is where the tier
    disclosure sits.
    """
    from display import CELL_H, CELL_W, HEIGHT, WIDTH, open_display
    from ops import DISPLAY_COLS, DISPLAY_ROWS

    print("Panel origin and extent\n")
    print(f"  driver expects {WIDTH}x{HEIGHT}, {DISPLAY_COLS}x{DISPLAY_ROWS} "
          f"characters at {CELL_W}x{CELL_H} px")
    if args.x_offset or args.y_offset:
        print(f"  trying x_offset={args.x_offset} y_offset={args.y_offset}")

    d = open_display(console=args.console)
    if hasattr(d, "set_offsets"):
        d.set_offsets(args.x_offset, args.y_offset)

    ruler = "".join(str(i % 10) for i in range(DISPLAY_COLS))
    lines = [ruler]
    lines += [f"{i:<2}" + " " * (DISPLAY_COLS - 4) + f"{i:>2}"
              for i in range(1, DISPLAY_ROWS - 1)]
    lines.append(ruler)
    d.show(lines)

    print("\n  Look at the panel. All four edges must be fully visible:")
    print(f"    top and bottom    a 0-9 ruler, all {DISPLAY_COLS} digits")
    print(f"    left and right    row numbers 1 to {DISPLAY_ROWS - 2}")
    print("\n  A missing edge means the origin is wrong. Re-run with")
    print("  --x-offset / --y-offset until every edge shows, then set those")
    print("  in display.ST7789Display. 0/0 works on most modules; some")
    print("  1.3\" boards want 0/80.")
    return 0


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("atecc", help="the PIN counter, tested by behaviour")
    p.add_argument("--pin", default="12345678")
    p.add_argument("--i-can-wipe-this-chip", action="store_true")
    p.set_defaults(fn=cmd_atecc)

    p = sub.add_parser("buttons", help="measure switch bounce")
    p.add_argument("--presses", type=int, default=5)
    p.set_defaults(fn=cmd_buttons)

    p = sub.add_parser("display", help="check the panel's origin")
    p.add_argument("--x-offset", type=int, default=0)
    p.add_argument("--y-offset", type=int, default=0)
    p.add_argument("--console", action="store_true")
    p.set_defaults(fn=cmd_display)

    args = ap.parse_args()
    rc = args.fn(args)
    failed = [label for label, ok, _ in RESULTS if not ok]
    if failed:
        print(f"\n{len(failed)} check(s) failed:")
        for f in failed:
            print(f"  - {f}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
