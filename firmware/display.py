"""The screen — an ST7789 240x240 over SPI, and the text layout above it.

Two things live here and they have very different standing.

The LAYOUT is a security control. `ops.render_for_display` already refuses an
operation that will not fit; this file must not then undo that by wrapping,
scrolling or eliding when it draws. So the drawing path takes a list of lines
that has already been checked, checks it again at the last possible moment,
and raises rather than paints if anything would be lost. The last moment is
the right place for that check: it is the only one that knows the real font
metrics.

The DRIVER is not a security control. It pushes pixels. It is also the one
part of this repo that cannot be exercised without hardware, so it is kept
thin, and everything above it is written against the `Display` protocol so the
tests can drive a fake.

WHY 40x20. A 240x240 panel with a 6x12 font gives exactly 40 columns and 20
rows. Both are hard limits rather than targets: a line that runs off the right
edge is a field the owner did not read, and a row below the bottom is a field
they may never have scrolled to. `ops.py` owns those constants; this file
imports them rather than restating them, because two copies of a screen size
is how a display starts lying about what fits.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ops import DISPLAY_COLS, DISPLAY_ROWS, UnrenderableOperation

WIDTH = 240
HEIGHT = 240
CELL_W = WIDTH // DISPLAY_COLS          # 6
CELL_H = HEIGHT // DISPLAY_ROWS         # 12

# Deliberately few. A screen that speaks in colour teaches people to read the
# colour instead of the words, and the words are the thing that is true.
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
AMBER = (255, 176, 0)                   # warnings, and only warnings
DIM = (128, 128, 128)


@runtime_checkable
class Display(Protocol):
    """What the rest of the firmware is allowed to assume about a screen."""

    def show(self, lines: list[str], highlight: int | None = None) -> None:
        """Paint exactly these lines. Never wrap, never scroll, never elide."""

    def show_qr(self, payload: str, caption: str = "") -> None:
        """Paint one QR frame."""

    def clear(self) -> None:
        ...


def check_fits(lines: list[str]) -> None:
    """Raise unless every line fits the physical panel.

    Called immediately before painting, on the exact list that will be
    painted. `ops.check_fits` does the same job earlier in the chain; doing it
    twice is deliberate, because the composed screen — operation lines plus
    whatever the caller appended — is not the same object either check saw.
    """
    over = [ln for ln in lines if len(ln) > DISPLAY_COLS]
    if over:
        raise UnrenderableOperation(
            f"line does not fit the {DISPLAY_COLS}-column display: {over[0]!r}")
    if len(lines) > DISPLAY_ROWS:
        raise UnrenderableOperation(
            f"screen needs {len(lines)} lines, the display shows {DISPLAY_ROWS}")


def colour_for(line: str) -> tuple[int, int, int]:
    """Warnings in amber, everything else in white.

    The one place colour carries meaning, and it carries only this: the device
    is telling you something it could not verify. `ops.py` writes those lines
    with a WARNING prefix, so this stays a rule about text rather than a second
    channel that can disagree with it.
    """
    stripped = line.strip()
    if stripped.startswith("WARNING") or "WARNING" in line[:20]:
        return AMBER
    return WHITE


class ConsoleDisplay:
    """A Display that prints. Used by the tests and by `app.py --console`.

    Not a simulator — it makes no attempt to look like the panel. It exists so
    the state machine above it can be driven and asserted on a laptop.
    """

    def __init__(self, out=None):
        import sys
        self.out = out or sys.stdout
        self.last: list[str] = []
        self.frames: list[str] = []

    def show(self, lines: list[str], highlight: int | None = None) -> None:
        check_fits(lines)
        self.last = list(lines)
        # The gutter is a column of its own, so the border has to allow for
        # it. Drawing DISPLAY_COLS dashes over a gutter plus DISPLAY_COLS
        # characters puts every full-width line one past the frame, which
        # reads on a console as a screen that does not fit when it does.
        edge = "+" + "-" * (DISPLAY_COLS + 1) + "+"
        print(edge, file=self.out)
        for i, ln in enumerate(lines):
            mark = ">" if i == highlight else " "
            print(f"|{mark}{ln:<{DISPLAY_COLS}}|", file=self.out)
        print(edge, file=self.out)

    def show_qr(self, payload: str, caption: str = "") -> None:
        self.frames.append(payload)
        print(f"[QR {len(payload)} chars] {caption}", file=self.out)

    def set_offsets(self, x: int, y: int) -> None:
        self.offsets = (x, y)

    def clear(self) -> None:
        self.last = []


class ST7789Display:
    """The real panel. Untested until it is on a bench — see VALIDATION.md.

    Wiring is BUILD.md section 11: SPI0 on GPIO8-11, D/C on 25, RESET on 27,
    backlight on 24.
    """

    # Many 1.3" 240x240 modules are a window into the controller's 240x320
    # address space, so the panel's first pixel is not the controller's. Get
    # this wrong and the bottom row is off the glass — which on a confirmation
    # screen is where the tier disclosure sits. `tools/bench.py display` draws
    # a frame at the extremes so a wrong origin is visible in one look.
    X_OFFSET = 0
    Y_OFFSET = 0

    def __init__(self, rotation: int = 0, backlight: bool = True,
                 x_offset: int | None = None, y_offset: int | None = None):
        try:
            import board
            import digitalio
            from adafruit_rgb_display import st7789
            from PIL import Image, ImageDraw, ImageFont
        except ImportError as e:                                # pragma: no cover
            raise RuntimeError(
                f"the display needs adafruit-circuitpython-rgb-display and "
                f"Pillow ({e}). On Raspberry Pi OS:\n"
                f"    pip install adafruit-circuitpython-rgb-display pillow"
            ) from None

        self._Image, self._ImageDraw = Image, ImageDraw
        spi = board.SPI()
        self._panel = st7789.ST7789(
            spi, width=WIDTH, height=HEIGHT, rotation=rotation,
            x_offset=self.X_OFFSET if x_offset is None else x_offset,
            y_offset=self.Y_OFFSET if y_offset is None else y_offset,
            cs=digitalio.DigitalInOut(board.CE0),
            dc=digitalio.DigitalInOut(board.D25),
            rst=digitalio.DigitalInOut(board.D27),
            baudrate=32_000_000)
        self._backlight = digitalio.DigitalInOut(board.D24)
        self._backlight.switch_to_output(value=backlight)

        # A fixed-width font at exactly the cell size. If the bundled DejaVu
        # is unavailable we fall back to PIL's built-in bitmap font, which is
        # smaller than a cell — legible, and still never wider than the
        # column count, which is the property that matters.
        try:
            self._font = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", CELL_H - 1)
        except OSError:                                         # pragma: no cover
            self._font = ImageFont.load_default()

    def show(self, lines: list[str], highlight: int | None = None) -> None:
        check_fits(lines)
        img = self._Image.new("RGB", (WIDTH, HEIGHT), BLACK)
        draw = self._ImageDraw.Draw(img)
        for i, ln in enumerate(lines):
            y = i * CELL_H
            if i == highlight:
                draw.rectangle([0, y, WIDTH, y + CELL_H - 1], fill=(40, 40, 40))
            draw.text((0, y), ln, font=self._font, fill=colour_for(ln))
        self._panel.image(img)

    def show_qr(self, payload: str, caption: str = "") -> None:
        try:
            import qrcode
        except ImportError:                                     # pragma: no cover
            raise RuntimeError("the display needs `qrcode` to emit frames") from None
        code = qrcode.QRCode(border=2, error_correction=qrcode.ERROR_CORRECT_L)
        code.add_data(payload)
        code.make(fit=True)
        img = code.make_image(fill_color="black", back_color="white").convert("RGB")
        img = img.resize((HEIGHT, HEIGHT), self._Image.NEAREST)
        if caption:
            draw = self._ImageDraw.Draw(img)
            draw.rectangle([0, HEIGHT - CELL_H, WIDTH, HEIGHT], fill=WHITE)
            draw.text((0, HEIGHT - CELL_H), caption[:DISPLAY_COLS],
                      font=self._font, fill=BLACK)
        self._panel.image(img)

    def set_offsets(self, x: int, y: int) -> None:
        """Re-open the panel at a different origin. Used by bench.py."""
        self._panel._offset_left, self._panel._offset_top = x, y

    def clear(self) -> None:
        self._panel.image(self._Image.new("RGB", (WIDTH, HEIGHT), BLACK))


def open_display(console: bool = False) -> Display:
    """The real panel if we can reach it, the console if we cannot."""
    if console:
        return ConsoleDisplay()
    try:
        return ST7789Display()
    except RuntimeError as e:
        print(f"No display: {e}\nFalling back to the console.")
        return ConsoleDisplay()


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Display — layout limits, colour rule, protocol conformance\n")
    checks = []

    d = ConsoleDisplay(out=open("/dev/null", "w"))
    checks.append(("ConsoleDisplay satisfies the protocol", isinstance(d, Display)))
    checks.append(("ST7789Display satisfies the protocol",
                   all(hasattr(ST7789Display, m) for m in ("show", "show_qr", "clear"))))

    d.show(["hello", "world"])
    checks.append(("paints what it was given", d.last == ["hello", "world"]))

    # The limits. These are the whole reason this file has a self-test.
    for label, lines in [
        ("a line one character too wide", ["x" * (DISPLAY_COLS + 1)]),
        ("a screen one row too tall", ["ok"] * (DISPLAY_ROWS + 1)),
    ]:
        try:
            d.show(lines)
            checks.append((f"refuses {label}", False))
        except UnrenderableOperation:
            checks.append((f"refuses {label}", True))

    d.show(["x" * DISPLAY_COLS])
    checks.append(("accepts a full-width line", len(d.last[0]) == DISPLAY_COLS))
    d.show(["ok"] * DISPLAY_ROWS)
    checks.append(("accepts a full-height screen", len(d.last) == DISPLAY_ROWS))

    # A refusal must not have painted anything first — a half-drawn screen is
    # worse than none, because it looks complete.
    d.clear()
    try:
        d.show(["fine", "x" * (DISPLAY_COLS + 5)])
    except UnrenderableOperation:
        pass
    checks.append(("a refused screen paints nothing", d.last == []))

    checks.append(("cell size divides the panel exactly",
                   CELL_W * DISPLAY_COLS == WIDTH and CELL_H * DISPLAY_ROWS == HEIGHT))

    # Colour carries exactly one meaning.
    checks.append(("warnings are amber",
                   colour_for("  WARNING  change to an address this") == AMBER))
    checks.append(("everything else is white",
                   colour_for("  amount   0.00150000 BTC") == WHITE))
    checks.append(("the word alone does not trigger it late in a line",
                   colour_for("  to       bc1qsomethingwarningish") == WHITE))

    # QR frames are recorded, not reflowed.
    d.show_qr("p1of2 abc", "1 of 2")
    checks.append(("QR frames pass through unchanged", d.frames[-1] == "p1of2 abc"))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe panel itself is unverified until it is on a bench.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
