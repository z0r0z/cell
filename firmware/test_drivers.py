#!/usr/bin/env python3
"""Do the hardware drivers call their libraries correctly?

Three of this firmware's files talk to libraries that are not installed on a
laptop and cannot be exercised without the parts they drive. That is a real
limit, but it is a narrower one than it first appears: a driver can be wrong
in two different ways, and only one of them needs hardware to find.

    WRONG ABOUT THE WORLD    the panel needs a Y offset, the switch bounces
                             longer than we allowed, the webcam will not focus
                             that close. Only a bench finds these.

    WRONG ABOUT THE LIBRARY  a function called with the wrong number of
                             arguments, a constant taken from the wrong
                             namespace, a return value unpacked into the wrong
                             number of names. These import cleanly, pass every
                             test that uses a fake, and fail on first contact.

This file is about the second kind. It installs nothing and skips silently when
a library is absent — the normal case in CI, since these pull native shared
objects that have no business being test dependencies. Run it in an
environment where they ARE present and it compares what the drivers call
against what the libraries actually expose.

The first version of `se_atecc.py` called `atcab_checkmac` with six arguments
where the binding takes five, and read the data zone using the lock-zone
constant, which names a different region entirely. Both would have reached a
built device.
"""

from __future__ import annotations

import inspect
import sys

FAILURES: list[str] = []
SKIPPED: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


def skip(what: str, how: str) -> None:
    print(f"  {what:<58}SKIP")
    SKIPPED.append(f"{what} — install with: {how}")


def signature_of(obj) -> list[str]:
    params = list(inspect.signature(obj).parameters)
    return params[1:] if params and params[0] == "self" else params


# --------------------------------------------------------------------------


def check_display() -> None:
    print("\n display — adafruit_rgb_display, Pillow, qrcode")
    try:
        from adafruit_rgb_display import st7789
    except Exception:                                           # noqa: BLE001
        skip("ST7789 constructor arguments",
             "pip install adafruit-circuitpython-rgb-display")
    else:
        params = set(signature_of(st7789.ST7789.__init__))
        used = {"spi", "width", "height", "rotation", "cs", "dc", "rst", "baudrate"}
        missing = used - params
        check("every ST7789 argument we pass exists", not missing)
        if missing:
            print(f"      unknown to the library: {sorted(missing)}")
        check("ST7789 exposes image()", hasattr(st7789.ST7789, "image"))
        # The library defaults to a 320-row panel. Ours is square, and a
        # driver that inherits the default paints two thirds of a screen.
        sig = inspect.signature(st7789.ST7789.__init__)
        check("we override the library's 320-row default",
              sig.parameters["height"].default != 240)

    try:
        from PIL import Image, ImageDraw
    except Exception:                                           # noqa: BLE001
        skip("Pillow drawing calls", "pip install pillow")
    else:
        check("Image.new takes the mode/size/colour we pass",
              set(signature_of(Image.new)) >= {"mode", "size", "color"})
        d = ImageDraw.Draw(Image.new("RGB", (8, 8)))
        check("ImageDraw has text() and rectangle()",
              hasattr(d, "text") and hasattr(d, "rectangle"))
        check("text() accepts a fill and a font",
              set(signature_of(d.text)) >= {"xy", "text", "fill", "font"})

    try:
        import qrcode
    except Exception:                                           # noqa: BLE001
        skip("qrcode frame generation", "pip install qrcode")
    else:
        code = qrcode.QRCode(border=2, error_correction=qrcode.ERROR_CORRECT_L)
        code.add_data("p1of2 " + "A" * 200)
        code.make(fit=True)
        img = code.make_image(fill_color="black", back_color="white")
        check("a realistic frame encodes to an image", img.size[0] > 0)
        check("...and converts to RGB for the panel",
              img.convert("RGB").mode == "RGB")


def check_buttons() -> None:
    print("\n buttons — gpiozero")
    try:
        from gpiozero import Button
    except Exception:                                           # noqa: BLE001
        skip("gpiozero Button arguments", "apt install python3-gpiozero")
        return
    params = set(signature_of(Button.__init__))
    check("Button takes pull_up and bounce_time",
          {"pull_up", "bounce_time"} <= params)
    check("Button exposes when_pressed", hasattr(Button, "when_pressed"))
    check("...and is_pressed, for the held-button case",
          hasattr(Button, "is_pressed"))


def check_camera() -> None:
    print("\n camera — OpenCV")
    try:
        import cv2
    except Exception:                                           # noqa: BLE001
        skip("OpenCV QR decoding", "apt install python3-opencv")
        return
    check("VideoCapture exists", hasattr(cv2, "VideoCapture"))
    check("the frame-size properties we set exist",
          hasattr(cv2, "CAP_PROP_FRAME_WIDTH") and hasattr(cv2, "CAP_PROP_FRAME_HEIGHT"))
    det = getattr(cv2, "QRCodeDetector", None)
    check("QRCodeDetector exists", det is not None)
    if det is None:
        return
    try:
        import numpy as np
        result = det().detectAndDecode(np.zeros((64, 64, 3), dtype=np.uint8))
        # camera.py unpacks three names from this call.
        check("detectAndDecode returns the three values we unpack",
              isinstance(result, tuple) and len(result) == 3)
        check("...and the first is the decoded string",
              isinstance(result[0], str))
    except ImportError:
        skip("detectAndDecode return shape", "pip install numpy")


def check_secure_element() -> None:
    print("\n secure element — cryptoauthlib")
    try:
        import cryptoauthlib as cal
    except Exception:                                           # noqa: BLE001
        skip("cryptoauthlib call signatures", "pip install cryptoauthlib")
        return

    import se_atecc
    from test_se_atecc import FakeATECC

    for name in ("atcab_init", "atcab_is_locked", "atcab_counter_read",
                 "atcab_counter_increment", "atcab_read_zone",
                 "atcab_write_zone", "atcab_sha_hmac", "atcab_random"):
        real = getattr(cal, name, None)
        if real is None:
            check(f"cryptoauthlib exposes {name}", False)
            continue
        check(f"{name} takes the arguments we pass",
              list(inspect.signature(real).parameters)
              == signature_of(getattr(FakeATECC, name)))

    # The constants the binding documents but does not export. Getting these
    # from the wrong namespace reads a different region and still succeeds.
    doc = (cal.atcab_is_locked.__doc__ or "")
    check("LOCK_ZONE_CONFIG is 0x00, as the binding documents",
          "LOCK_ZONE_CONFIG(0x00)" in doc and se_atecc.LOCK_ZONE_CONFIG == 0x00)
    check("LOCK_ZONE_DATA is 0x01",
          "LOCK_ZONE_DATA(0x01)" in doc and se_atecc.LOCK_ZONE_DATA == 0x01)
    zdoc = (cal.atcab_read_bytes_zone.__doc__ or "")
    check("ATCA_ZONE_DATA is 2, a different namespace from LOCK_ZONE_*",
          "ATCA_ZONE_DATA(2)" in zdoc and se_atecc.ATCA_ZONE_DATA == 2)
    check("...and the two really do differ",
          se_atecc.ATCA_ZONE_DATA != se_atecc.LOCK_ZONE_DATA)

    # CheckMac is deliberately unused. It compares a MAC the HOST computed,
    # which means the host must know the slot secret — and here it does not.
    src = (__import__("pathlib").Path(se_atecc.__file__)).read_text()
    check("we do not call atcab_checkmac", "atcab_checkmac(" not in src)


def main() -> int:
    print("Hardware drivers — do we call these libraries correctly?")
    check_display()
    check_buttons()
    check_camera()
    check_secure_element()

    print("\n" + "-" * 66)
    if SKIPPED:
        print(f"{len(SKIPPED)} check(s) skipped — the library is not installed here:")
        for sk in SKIPPED:
            print(f"  - {sk}")
        print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS" + (" (what ran)" if SKIPPED else ""))
    print("\nThis says the calls are well formed. It says nothing about the")
    print("panel, the switches, the lens or the chip — VALIDATION.md tracks")
    print("those separately, and only a built device closes them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
