"""The camera, and the only way data gets into this device.

There is no wifi, no bluetooth and no USB data path, so everything the device
learns about the outside world arrives as pixels through a lens. That makes
this file the entire attack surface for input, and it is written accordingly:
it decodes QR codes and hands the bytes to `qr.Collector`, which is where the
paranoia about substituted frames lives.

TWO CAMERAS, ONE CSI PORT. The Pi Zero has a single CSI connector and the
speckle path owns it — that camera has its lens removed and its exposure,
gain and white balance pinned, because auto-adjustment destroys the
correlation measurement the blood gate depends on. So QR capture uses a USB
webcam, where auto-exposure is not merely tolerable but wanted. BOM.csv says
the same thing in the sourcing notes; getting this backwards means a device
that either cannot read a QR code or cannot run its own gate.

WHAT THIS FILE DOES NOT DO. It does not decide anything. It returns bytes.
Every judgement about those bytes — is it a PSBT, is it ours, does it pay who
it says — happens above, against the device's own keys. A camera that could
be made to lie is assumed; the design's answer is that nothing downstream
believes it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

import qr

# How long to keep the camera running before giving up on a transfer. Long
# enough for an animated loop of a few dozen frames to come round twice.
SCAN_TIMEOUT_S = 180.0


class CameraError(Exception):
    """The camera is missing, or cannot be configured the way we need it."""


@runtime_checkable
class Camera(Protocol):
    def frames(self):
        """Yield decoded QR strings as they are seen. May yield duplicates."""

    def close(self) -> None:
        ...


@dataclass
class FakeCamera:
    """Plays back a scripted list of decoded strings, for the tests."""

    script: list[str] = field(default_factory=list)
    repeats: int = 1

    def frames(self):
        for _ in range(self.repeats):
            for s in self.script:
                yield s

    def close(self) -> None:
        pass


class USBCamera:
    """A cheap USB webcam plus a QR decoder. Untested until it is on a bench."""

    def __init__(self, index: int = 0):
        try:
            import cv2
        except ImportError:                                     # pragma: no cover
            raise CameraError(
                "QR capture needs OpenCV. On Raspberry Pi OS:\n"
                "    apt install python3-opencv") from None
        self._cv2 = cv2
        self._cap = cv2.VideoCapture(index)
        if not self._cap.isOpened():
            raise CameraError(
                f"no camera at index {index}. The QR camera is the USB webcam; "
                f"the CSI port belongs to the speckle path.")
        # Modest resolution on purpose: a Pi Zero decoding 1080p spends its
        # time on pixels rather than on frames, and QR wants frames.
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self._detector = cv2.QRCodeDetector()

    def frames(self):
        while True:
            ok, frame = self._cap.read()
            if not ok:
                raise CameraError("the camera stopped returning frames")
            try:
                data, points, _ = self._detector.detectAndDecode(frame)
            except Exception:                                   # noqa: BLE001
                # A decoder that throws on a garbage frame must not take the
                # device down mid-transfer. Drop the frame and keep looking.
                continue
            if data:
                yield data

    def close(self) -> None:
        self._cap.release()


def scan(camera: Camera, display=None, timeout_s: float = SCAN_TIMEOUT_S,
         clock: Callable[[], float] = time.monotonic,
         on_progress: Callable[[str], None] | None = None) -> bytes:
    """Collect one complete transfer, or raise.

    Progress is reported because an animated transfer that is missing one
    frame looks identical to one that is not working at all, and the owner
    needs to know which — the fix for the first is to keep the camera still,
    and for the second it is to start again.
    """
    collector = qr.Collector()
    deadline = clock() + timeout_s
    for frame in camera.frames():
        if clock() > deadline:
            raise CameraError(
                f"gave up after {timeout_s:.0f}s with {collector.progress()}; "
                f"missing {collector.missing}")
        try:
            payload = collector.feed(frame)
        except qr.BadFrame as e:
            # A frame from a different transfer, or one that changed under us.
            # Report it and keep scanning — the owner may simply have panned
            # across another screen.
            if on_progress:
                on_progress(str(e))
            continue
        if on_progress:
            on_progress(collector.progress())
        if display is not None:
            display.show(["SCANNING", "", f"  {collector.progress()}", "",
                          "  BACK to stop"])
        if payload is not None:
            return payload
    raise CameraError(f"the camera ran out of frames with {collector.progress()}")


def emit(display, payload: bytes, caption: str = "", loops: int = 3,
         chunk: int = qr.DEFAULT_CHUNK,
         sleep: Callable[[float], None] = time.sleep,
         frame_s: float = 0.4) -> int:
    """Show a payload as an animated QR loop. Returns the frame count.

    It loops rather than showing each frame once, because the reader on the
    other side will miss frames and there is no back channel to ask again.
    """
    frames = qr.encode(payload, chunk=chunk)
    for _ in range(loops):
        for i, f in enumerate(frames, 1):
            display.show_qr(f, caption or f"{i} of {len(frames)}  ·  "
                                          f"{qr.digest(payload)}")
            sleep(frame_s)
    return len(frames)


def open_camera(console: bool = False, script: list[str] | None = None) -> Camera:
    if console:
        return FakeCamera(script or [])
    try:
        return USBCamera()
    except CameraError as e:
        print(f"No camera: {e}\nFalling back to a scripted stub.")
        return FakeCamera(script or [])


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Camera — transfer collection, hostile frames, emission\n")
    checks = []
    from display import ConsoleDisplay

    payload = bytes(range(256)) * 3
    frames = qr.encode(payload, chunk=100)

    checks.append(("FakeCamera satisfies the protocol",
                   isinstance(FakeCamera(), Camera)))
    checks.append(("USBCamera satisfies the protocol",
                   all(hasattr(USBCamera, m) for m in ("frames", "close"))))

    checks.append(("collects a transfer in order",
                   scan(FakeCamera(frames)) == payload))
    checks.append(("collects it out of order",
                   scan(FakeCamera(list(reversed(frames)))) == payload))
    checks.append(("tolerates the duplicates an animated loop produces",
                   scan(FakeCamera(frames, repeats=3)) == payload))

    # Junk in the field of view must be stepped over, not fatal.
    noisy = ["https://example.com", "hello"] + frames + ["not a frame"]
    checks.append(("ignores non-CELL QR codes in view",
                   scan(FakeCamera(noisy)) == payload))

    notes: list[str] = []
    scan(FakeCamera(noisy), on_progress=notes.append)
    checks.append(("...and says so rather than failing silently",
                   any("pNofM" in n for n in notes)))

    # A frame swapped mid-scan is the attack this path exists to survive. The
    # collector refuses it, and scan() keeps going rather than accepting it.
    swapped = [frames[0], "p1of%d %s" % (len(frames), "AAAA")] + frames[1:]
    checks.append(("a substituted frame does not corrupt the payload",
                   scan(FakeCamera(swapped)) == payload))

    # Incomplete transfers must raise, never return a partial payload.
    for label, script in [("an incomplete transfer", frames[:-1]),
                          ("an empty field of view", [])]:
        try:
            scan(FakeCamera(script))
            checks.append((f"refuses {label}", False))
        except CameraError:
            checks.append((f"refuses {label}", True))

    # And a transfer that never completes must time out rather than hang.
    ticks = iter([0.0] + [1000.0] * 50)
    try:
        scan(FakeCamera(frames[:1], repeats=50), clock=lambda: next(ticks))
        checks.append(("times out rather than hanging", False))
    except CameraError as e:
        checks.append(("times out rather than hanging", "gave up" in str(e)))

    # Emission.
    d = ConsoleDisplay(out=open("/dev/null", "w"))
    n = emit(d, payload, loops=2, chunk=100, sleep=lambda _s: None)
    checks.append(("emits every frame, every loop", len(d.frames) == n * 2))
    checks.append(("the emitted frames reassemble",
                   qr.decode(d.frames[:n]) == payload))

    d2 = ConsoleDisplay(out=open("/dev/null", "w"))
    emit(d2, b"short", loops=1, sleep=lambda _s: None)
    checks.append(("a short payload is a single frame", len(d2.frames) == 1))

    # A round trip through both halves, which is what the airgap actually is.
    d3 = ConsoleDisplay(out=open("/dev/null", "w"))
    emit(d3, payload, loops=1, chunk=64, sleep=lambda _s: None)
    checks.append(("emit then scan round trips",
                   scan(FakeCamera(d3.frames)) == payload))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe webcam and the panel are unverified until they are on a bench.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
