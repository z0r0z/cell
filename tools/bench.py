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
    tools/bench.py thermal   what a sealed case does to the SoC over a run

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
    from se import MAX_PIN_ATTEMPTS, PinLockout
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
    # Against the FULL budget, not against whatever the chip happened to show
    # when this started. A correct PIN moves the baseline to the counter, so
    # the answer afterwards is always MAX_PIN_ATTEMPTS -- while `start` is
    # lower on any chip that has ever seen a wrong PIN, which includes every
    # chip this tool has been run on before. Comparing the two reported a
    # failure for behaviour that was correct.
    check("a correct PIN restores the budget",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS,
          f"{se.attempts_remaining()} of {MAX_PIN_ATTEMPTS}")

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


# A gap longer than this ends the burst of edges belonging to one transition.
# Far above any switch's ringing and far below how long a finger stays down,
# which is the whole reason it can separate the two.
SETTLE_GAP_S = 0.05


def _bounce_ms(edges: list[float]) -> float:
    """How long the FIRST transition rang, in milliseconds.

    Every edge inside the capture window used to count, so the span ran from
    the press through the release: `edges[-1] - edges[0]` is how long a finger
    was on the button, typically 100-300 ms. Against a 30 ms debounce that
    fails every switch ever made, and the advice printed underneath is to
    raise DEBOUNCE_S past a fifth of a second -- on CONFIRM, the button that
    means consent.

    Bounce is a property of ONE transition, so only the first burst counts.
    """
    if len(edges) < 2:
        return 0.0
    last = edges[0]
    for t in edges[1:]:
        if t - last > SETTLE_GAP_S:
            break                       # the burst ended; the rest is release
        last = t
    return (last - edges[0]) * 1000.0


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
            spans.append(_bounce_ms(list(edges)))
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
# The sealed case
# --------------------------------------------------------------------------

# Where the SoC reports its own temperature. Present on every Pi OS image and
# readable without vcgencmd, which the read-only rootfs may not carry.
THERMAL_ZONE = Path("/sys/class/thermal/thermal_zone0/temp")

# The Pi caps the ARM clock at 80 C. Below that nothing is wrong; above it a
# blood run gets slower rather than incorrect, but a capture that misses its
# frame rate is a T0 fault (see touch_gate) and reads as a sensor problem.
THROTTLE_C = 80.0
# PETG softens from about 80 C, and the shells carry screw preload through six
# heat-set inserts. 70 C leaves headroom for a hot room on top of a hot run.
CREEP_MARGIN_C = 70.0


def _soc_temp_c() -> float | None:
    try:
        return int(THERMAL_ZONE.read_text().strip()) / 1000.0
    except (OSError, ValueError):
        return None


def _throttled_flags() -> int | None:
    """vcgencmd get_throttled, as an int. None if vcgencmd is unavailable."""
    import subprocess
    try:
        out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True,
                             text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    _, _, value = out.partition("=")
    try:
        return int(value, 0)
    except ValueError:
        return None


def cmd_thermal(args) -> int:
    """Watch the SoC temperature and the supply through a full-length run.

    The enclosure has no ventilation and cannot be given any: section 10
    requires the fifteen vents to stay blind pockets, because a through-hole
    lets ambient light into the optical chamber and the 415 nm gate stops
    working. So the Pi sits in a sealed PETG box, and nothing in the design
    has ever measured what that does over the ten minutes a blood capture
    takes.

    A rough energy balance says it is fine -- about 3 W across 0.0275 m2 of
    shell gives a 12-14 C rise, so a 25 C room puts the SoC near 55-60 C,
    clear of the 80 C cap. Do not lean on that figure. It lumps convection and
    radiation into a single coefficient and ignores the air gap between die
    and shell, so the junction can sit above it, and it is arithmetic with no
    measurement behind it. The case it does not cover at all is a device left
    somewhere hot: 45 C ambient starts the same run 20 C higher.

    Which is the point of this command. If the estimate were trustworthy there
    would be nothing to run.

    This also reads the under-voltage flags, which answer a separate question
    the bill of materials raises. Section 11 budgets 5 V at 2 A because the
    Zero 2 W peaks near 0.5 A and a blood run has the webcam, the laser and
    the LEDs drawing at once. An undersized supply shows up here as bit 0 or
    bit 16, and nowhere else until something behaves strangely.

    Run it with the case CLOSED and the shells screwed down. An open case
    measures a different instrument.
    """
    start = _soc_temp_c()
    if start is None:
        print(f"cannot read {THERMAL_ZONE} -- this check only runs on the Pi")
        return 1

    seconds = args.minutes * 60
    print(f"Sealed-case thermal — {args.minutes:g} minutes, "
          f"the length of a blood capture\n")
    print("  Run this with the case CLOSED and screwed down.")
    if args.load:
        print(f"  Loading {args.load} core(s) to stand in for a capture.")
    else:
        print("  No synthetic load: start a real capture now, or pass --load 4")
        print("  for the worst case the device can actually reach.")
    print(f"\n  start {start:.1f} C\n")

    workers = []
    if args.load:
        import multiprocessing

        def _spin():
            while True:
                pass
        for _ in range(args.load):
            p = multiprocessing.Process(target=_spin, daemon=True)
            p.start()
            workers.append(p)

    peak = start
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(min(10.0, max(0.0, deadline - time.monotonic())))
            t = _soc_temp_c()
            if t is None:
                continue
            peak = max(peak, t)
            left = max(0.0, deadline - time.monotonic())
            print(f"    {t:5.1f} C   peak {peak:5.1f} C   {left / 60:4.1f} min left")
    except KeyboardInterrupt:
        print("\n  interrupted -- reporting what was measured so far")
    finally:
        for p in workers:
            p.terminate()

    print()
    check("SoC stays below the 80 C throttle point", peak < THROTTLE_C,
          f"peak {peak:.1f} C, rose {peak - start:.1f} C from {start:.1f} C")
    check(f"peak leaves PETG margin (under {CREEP_MARGIN_C:.0f} C)",
          peak < CREEP_MARGIN_C,
          "the shells hold screw preload through heat-set inserts; PETG "
          "softens from about 80 C")

    flags = _throttled_flags()
    if flags is None:
        print("\n  vcgencmd unavailable -- supply flags not read")
    else:
        # Bits 0-3 are live, 16-19 latch since boot. The latched ones are the
        # useful half: a sag during the run is still visible afterwards.
        check("no under-voltage since boot", not (flags & (1 << 16)),
              f"get_throttled={flags:#x}")
        check("ARM clock never capped since boot", not (flags & (1 << 17)),
              f"get_throttled={flags:#x}")
        if flags & ((1 << 16) | (1 << 0)):
            print("\n  Under-voltage is the supply, not the heat. Section 11 wants")
            print("  5 V at 2 A, and a USB-C breakout with no CC pulldowns or a")
            print("  thin cable will sag under the webcam and the laser together.")

    if peak >= CREEP_MARGIN_C:
        print("\n  The vents cannot be opened -- see section 10, constraint 1.")
        print("  What can change: a heatsink on the SoC, or moving the Pi bay")
        print("  wall thinner so the shell conducts. Measure again after.")
    return 0 if all(ok for _, ok, _ in RESULTS) else 1

# --------------------------------------------------------------------------


def cmd_selftest(args) -> int:
    """The arithmetic in this file, without any of the hardware.

    Both bench checks shipped giving false alarms, and neither could have been
    caught by running the tool -- you need the parts, and the parts are what
    the tool exists to test. The pure functions underneath them do not need
    the parts, so they get checked here on every commit.
    """
    print("Bench arithmetic — no hardware required\n")
    ms = 0.001
    cases = [
        # A real press: 4 ms of ring, held 180 ms, 3 ms of ring on release.
        # The whole capture used to be measured, reporting 183 ms and telling
        # the builder to raise the debounce past a fifth of a second.
        ("a press separates from its release",
         [0, 1 * ms, 2 * ms, 4 * ms, 180 * ms, 181 * ms, 183 * ms], 4.0),
        ("a clean edge is zero bounce", [0.0], 0.0),
        ("a single pair still measures", [0.0, 6 * ms], 6.0),
        ("a long ring is reported in full",
         [0, 10 * ms, 20 * ms, 30 * ms, 45 * ms, 300 * ms], 45.0),
        ("nothing seen is zero", [], 0.0),
    ]
    ok = True
    for label, edges, want in cases:
        got = _bounce_ms(list(edges))
        good = abs(got - want) < 0.01
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}"
              + ("" if good else f"   got {got:.1f} ms, want {want:.1f}"))

    # The budget a correct PIN restores is the FULL one, never whatever the
    # chip showed when the tool started.
    from se import MAX_PIN_ATTEMPTS, SoftSE
    se = SoftSE(pin="12345678")
    se.verify_pin("00000000")                       # spend one
    started_at = se.attempts_remaining()
    se.verify_pin("12345678")                       # then get it right
    good = (started_at < MAX_PIN_ATTEMPTS
            and se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    ok &= good
    print(f"  {'a correct PIN restores the full budget':<52}"
          f"{'PASS' if good else 'FAIL'}")

    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe checks that need the parts are still open — see VALIDATION.md.")
    return 0 if ok else 1


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

    sub.add_parser("selftest", help="the arithmetic, without the hardware"
                   ).set_defaults(fn=cmd_selftest)
    p = sub.add_parser("thermal", help="SoC temperature in the sealed case")
    p.add_argument("--minutes", type=float, default=10.0,
                   help="default 10, the length of a blood capture")
    p.add_argument("--load", type=int, default=0,
                   help="busy this many cores to stand in for a capture")
    p.set_defaults(fn=cmd_thermal)

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
