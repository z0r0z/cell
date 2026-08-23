"""Four buttons, and the one that is different from the others.

UP, DOWN and BACK are navigation. CONFIRM is consent, and it is wired
differently on purpose: its own GPIO, its own RC debounce, sharing no bus with
anything. BUILD.md section 11 states the reason and this file enforces the
consequence — an attacker who owns the SPI bus, the display, or the I2C line
still cannot assert CONFIRM, because nothing on those buses is in its path.

WHAT THIS FILE GUARDS AGAINST beyond wiring:

  CONTACT BOUNCE.  A mechanical switch closes several times in a few
      milliseconds. Debouncing is normally a cosmetic concern; here one stray
      edge on CONFIRM is a signature the owner did not give, so it is a
      correctness concern.

  QUEUED PRESSES.  A press that arrived while the device was busy computing
      must not be delivered to the confirmation screen that appears
      afterwards. Consent has to be given to a screen the owner has actually
      seen, so the queue is drained before a confirmation is asked for, and
      `confirm()` refuses anything that arrives implausibly fast.

  A HELD BUTTON.  Tape over CONFIRM would otherwise confirm everything. A
      press only counts on the edge, and a button already down when the
      confirmation appears is not a press.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

# BCM numbering, from BUILD.md section 11.
PIN_UP = 5
PIN_DOWN = 13
PIN_BACK = 19
PIN_CONFIRM = 26                        # dedicated, RC-debounced, shares no bus

UP, DOWN, BACK, CONFIRM = "UP", "DOWN", "BACK", "CONFIRM"

DEBOUNCE_S = 0.030

# A confirmation that arrives faster than a person can read the screen is not
# a confirmation. This is not an anti-robot measure — nothing here can tell a
# fast human from a script — it is a guard against a press that was already in
# flight when the screen changed under it.
MIN_READ_S = 0.400


class ButtonError(Exception):
    """The button hardware is missing or misbehaving."""


@runtime_checkable
class Buttons(Protocol):
    def poll(self) -> str | None:
        """The next press, or None. Never blocks."""

    def wait(self, timeout: float | None = None) -> str | None:
        """Block for the next press."""

    def drain(self) -> None:
        """Discard anything queued. Called before asking for consent."""


@dataclass
class FakeButtons:
    """Scripted presses, for the tests and the console runner."""

    script: list[str] = field(default_factory=list)
    clock: Callable[[], float] = time.monotonic
    delay: float = MIN_READ_S + 0.1     # by default, presses look considered

    def __post_init__(self):
        self._t = 0.0

    def poll(self) -> str | None:
        if not self.script:
            return None
        self._t += self.delay
        return self.script.pop(0)

    def wait(self, timeout: float | None = None) -> str | None:
        return self.poll()

    def drain(self) -> None:
        pass

    def now(self) -> float:
        return self._t


class GPIOButtons:
    """The real buttons. Untested until they are on a bench."""

    def __init__(self):
        try:
            from gpiozero import Button
        except ImportError:                                     # pragma: no cover
            raise ButtonError(
                "gpiozero is not installed. On Raspberry Pi OS:\n"
                "    apt install python3-gpiozero") from None

        self._queue: list[tuple[str, float]] = []
        self._buttons = {}
        for name, pin in ((UP, PIN_UP), (DOWN, PIN_DOWN),
                          (BACK, PIN_BACK), (CONFIRM, PIN_CONFIRM)):
            b = Button(pin, pull_up=True, bounce_time=DEBOUNCE_S)
            # `when_pressed` fires on the falling edge only, so a button that
            # is already held when we start listening produces nothing. That
            # is the behaviour we want for CONFIRM.
            b.when_pressed = self._make_handler(name)
            self._buttons[name] = b

    def _make_handler(self, name: str):
        def handler():
            self._queue.append((name, time.monotonic()))
        return handler

    def poll(self) -> str | None:
        return self._queue.pop(0)[0] if self._queue else None

    def wait(self, timeout: float | None = None) -> str | None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self._queue:
                return self._queue.pop(0)[0]
            if deadline is not None and time.monotonic() > deadline:
                return None
            time.sleep(0.01)

    def drain(self) -> None:
        self._queue.clear()

    def held(self, name: str) -> bool:
        return bool(self._buttons[name].is_pressed)


def confirm(buttons: Buttons, present: Callable[[], None],
            clock: Callable[[], float] = time.monotonic,
            min_read_s: float = MIN_READ_S) -> bool:
    """Show a screen and wait for CONFIRM or BACK. Everything else is ignored.

    `present` is called AFTER the queue is drained, so the screen the owner
    reacts to is the screen they were shown. Returning False is a decline, and
    a decline is the default for anything ambiguous — a timeout, a BACK, or a
    press too fast to have followed a reading.
    """
    buttons.drain()
    present()
    shown_at = clock()
    while True:
        press = buttons.wait(timeout=120.0)
        if press is None:
            return False                    # walked away; that is a decline
        if press == BACK:
            return False
        if press == CONFIRM:
            if clock() - shown_at < min_read_s:
                # In flight before the screen existed. Ignore it and keep
                # waiting rather than counting it or aborting: aborting would
                # let a stray edge cancel a legitimate signing.
                continue
            return True
        # UP and DOWN do nothing here. There is nothing to scroll: the screen
        # is guaranteed to fit, so movement keys would only add ways to be
        # somewhere other than where you think you are.


def pin_entry(buttons: Buttons, display, length: int = 8,
              prompt: str = "ENTER PIN") -> str | None:
    """Digit picker on four buttons. Returns None if the owner backs out.

    UP and DOWN change the current digit, CONFIRM accepts it and moves on,
    BACK removes the last one — and BACK on an empty PIN abandons the entry
    entirely, which is the only way out that does not spend an attempt.

    The digits are shown as they are chosen. Masking them would be theatre on
    a device you hold in your own hand, and it would stop the owner noticing
    that a button is bouncing.
    """
    digits: list[int] = []
    current = 0
    while True:
        shown = "".join(str(d) for d in digits)
        display.show([
            prompt, "",
            f"  {shown}{current}{'_' * (length - len(digits) - 1)}",
            "",
            "  UP/DOWN  change the digit",
            "  CONFIRM  accept it",
            "  BACK     delete, or cancel",
            "",
            f"  {len(digits)} of {length}",
        ])
        press = buttons.wait(timeout=300.0)
        if press is None:
            return None
        if press == UP:
            current = (current + 1) % 10
        elif press == DOWN:
            current = (current - 1) % 10
        elif press == BACK:
            if not digits:
                return None
            digits.pop()
            current = 0
        elif press == CONFIRM:
            digits.append(current)
            current = 0
            if len(digits) == length:
                return "".join(str(d) for d in digits)


def open_buttons(console: bool = False, script: list[str] | None = None) -> Buttons:
    if console:
        return FakeButtons(script or [])
    try:
        return GPIOButtons()
    except ButtonError as e:
        print(f"No buttons: {e}\nFalling back to a scripted stub.")
        return FakeButtons(script or [])


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Buttons — debounce, consent, PIN entry\n")
    checks = []
    from display import ConsoleDisplay

    checks.append(("FakeButtons satisfies the protocol",
                   isinstance(FakeButtons(), Buttons)))
    checks.append(("GPIOButtons satisfies the protocol",
                   all(hasattr(GPIOButtons, m) for m in ("poll", "wait", "drain"))))
    checks.append(("CONFIRM is on its own pin",
                   PIN_CONFIRM not in (PIN_UP, PIN_DOWN, PIN_BACK)))
    checks.append(("CONFIRM is GPIO26, as BUILD.md wires it", PIN_CONFIRM == 26))

    # ---- consent ----
    shown = []

    def present():
        shown.append(True)

    b = FakeButtons([CONFIRM])
    checks.append(("CONFIRM confirms", confirm(b, present, clock=b.now) is True))
    checks.append(("the screen was shown before the press", len(shown) == 1))

    b = FakeButtons([BACK])
    checks.append(("BACK declines", confirm(b, present, clock=b.now) is False))
    checks.append(("walking away declines",
                   confirm(FakeButtons([]), present, clock=lambda: 0.0) is False))

    # Navigation keys must not confirm.
    b = FakeButtons([UP, DOWN, UP, CONFIRM])
    checks.append(("UP and DOWN do not confirm", confirm(b, present, clock=b.now) is True))
    b = FakeButtons([UP, DOWN, BACK])
    checks.append(("...and BACK after them still declines",
                   confirm(b, present, clock=b.now) is False))

    # A press already in flight when the screen appeared must not count.
    fast = FakeButtons([CONFIRM, CONFIRM], delay=0.001)
    got = confirm(fast, present, clock=fast.now)
    checks.append(("a press faster than a read is ignored once", got is False))

    # The same press, given time to have been read, is accepted. Both halves
    # matter: a guard that rejected everything would pass the test above and
    # make the device unusable.
    considered = FakeButtons([CONFIRM], delay=MIN_READ_S + 0.05)
    checks.append(("but a considered press is accepted",
                   confirm(considered, present, clock=considered.now) is True))

    # And a stray fast edge must not cancel a signing the owner then confirms.
    recovered = FakeButtons([CONFIRM, CONFIRM])
    recovered.delay = 0.001
    seq = iter([0.0, 0.001, 5.0])
    checks.append(("a stray edge does not cancel a later real press",
                   confirm(recovered, present, clock=lambda: next(seq)) is True))

    # The queue must be drained before consent is asked for.
    drained = []

    class Recording(FakeButtons):
        def drain(self):
            drained.append(len(self.script))
            self.script.clear()

    r = Recording([CONFIRM, CONFIRM, CONFIRM])
    checks.append(("queued presses are discarded, then it waits",
                   confirm(r, present, clock=r.now) is False and drained == [3]))

    # ---- PIN entry ----
    d = ConsoleDisplay(out=open("/dev/null", "w"))
    # 1, then 2, then six zeros. Eight digits by default -- see app.PIN_LENGTH.
    script = ([UP, CONFIRM] + [UP, UP, CONFIRM] + [CONFIRM] * 6)
    checks.append(("PIN entry assembles the digits",
                   pin_entry(FakeButtons(script), d) == "12000000"))
    checks.append(("BACK on an empty PIN cancels",
                   pin_entry(FakeButtons([BACK]), d) is None))
    checks.append(("BACK deletes a digit",
                   pin_entry(FakeButtons([UP, CONFIRM, BACK, CONFIRM] + [CONFIRM] * 7),
                             d) == "00000000"))
    checks.append(("DOWN wraps to nine",
                   pin_entry(FakeButtons([DOWN, CONFIRM] + [CONFIRM] * 7), d)
                   == "90000000"))
    checks.append(("a timeout cancels rather than submitting",
                   pin_entry(FakeButtons([UP, CONFIRM]), d) is None))
    checks.append(("PIN length is honoured",
                   len(pin_entry(FakeButtons([CONFIRM] * 6), d, length=6)) == 6))
    # The default has to match what the device actually asks for, or a build
    # ships a screen that collects six digits for a PIN of eight.
    import app
    checks.append(("...and the default is the device's PIN length",
                   len(pin_entry(FakeButtons([CONFIRM] * app.PIN_LENGTH), d))
                   == app.PIN_LENGTH))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe switches themselves are unverified until they are on a bench.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
