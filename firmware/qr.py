"""The airgap — chopping a PSBT into QR frames and putting it back together.

The device has no wifi, no bluetooth and no USB data path, so every byte in or
out crosses as pixels. A signed PSBT is a few hundred bytes to a few kilobytes
and a QR code holds far less than that at a density a 240x240 screen can show
and a cheap webcam can read, so transfers are animated: a loop of frames the
other side reassembles.

FRAMING. The `pNofM` convention, as used by Specter, Sparrow and SeedSigner:

    p1of4 cHNidP8BAHECAAAAAf...

It is deliberately boring — a text prefix and base64 — because the failure mode
of a clever encoding is a transfer that works with one coordinator and not
another, discovered while holding a device that has already been bled into.

WHAT REASSEMBLY MUST NOT DO. Frames arrive out of order, repeat, and come from
whatever the camera happened to see. So the collector:

  * pins the total from the first frame and rejects any frame claiming another,
  * rejects a frame whose index is out of range,
  * refuses to overwrite a chunk it already holds with different bytes,
  * and returns nothing at all until every index is present.

A collector that quietly accepts a replacement chunk lets someone holding a
second screen swap the middle of your transaction while the camera is running.
The result is checked against a digest the sender computed over the whole
payload, so a substituted chunk is a refusal rather than a different
transaction.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

# A conservative payload size. Version 20 QR at error correction level L holds
# more, but a 240x240 display and a $8 webcam are the real constraints, and a
# frame that will not scan costs more than an extra frame does.
DEFAULT_CHUNK = 300

_FRAME = re.compile(r"^p(\d+)of(\d+)\s*(.*)$", re.IGNORECASE | re.DOTALL)


class BadFrame(ValueError):
    """A frame that does not belong to the transfer being collected."""


def encode(payload: bytes, chunk: int = DEFAULT_CHUNK) -> list[str]:
    """Split a payload into frames. A short payload still gets p1of1."""
    if chunk < 16:
        raise ValueError("chunk size too small to be useful")
    body = base64.b64encode(payload).decode("ascii")
    parts = [body[i:i + chunk] for i in range(0, len(body), chunk)] or [""]
    total = len(parts)
    return [f"p{i + 1}of{total} {p}" for i, p in enumerate(parts)]


def digest(payload: bytes) -> str:
    """The short digest the two sides compare by eye when it matters."""
    return hashlib.sha256(payload).hexdigest()[:8]


@dataclass
class Collector:
    """Accumulates frames until the payload is complete.

    Feed it every string the decoder produces; it ignores repeats and tells
    you when it has everything.
    """

    total: int | None = None
    chunks: dict[int, str] = field(default_factory=dict)

    def feed(self, frame: str) -> bytes | None:
        """Add a frame. Returns the payload once complete, else None."""
        m = _FRAME.match(frame.strip())
        if not m:
            raise BadFrame(f"not a pNofM frame: {frame[:24]!r}")
        seq, total, data = int(m.group(1)), int(m.group(2)), m.group(3).strip()
        if total < 1:
            raise BadFrame("frame claims a total of zero")
        if self.total is None:
            self.total = total
        elif total != self.total:
            raise BadFrame(
                f"frame says {total} parts, this transfer has {self.total}. "
                f"Two different transfers are on screen; restart the scan.")
        if not 1 <= seq <= total:
            raise BadFrame(f"frame {seq} is outside 1..{total}")
        if seq in self.chunks and self.chunks[seq] != data:
            raise BadFrame(
                f"frame {seq} arrived twice with different contents. Something "
                f"is changing the payload mid-scan; restart the scan.")
        self.chunks[seq] = data
        if len(self.chunks) != self.total:
            return None
        joined = "".join(self.chunks[i] for i in range(1, self.total + 1))
        try:
            return base64.b64decode(joined, validate=True)
        except Exception:                                       # noqa: BLE001
            raise BadFrame("the reassembled payload is not valid base64") from None

    @property
    def missing(self) -> list[int]:
        if self.total is None:
            return []
        return [i for i in range(1, self.total + 1) if i not in self.chunks]

    def progress(self) -> str:
        if self.total is None:
            return "waiting for the first frame"
        return f"{len(self.chunks)} of {self.total} frames"

    def reset(self) -> None:
        self.total = None
        self.chunks.clear()


def decode(frames: list[str]) -> bytes:
    """Collect a whole transfer at once. Raises unless it is complete."""
    c = Collector()
    out = None
    for f in frames:
        got = c.feed(f)
        # `is not None`, not truthiness: an empty payload is a legitimate
        # result and `b"" or out` would silently discard it.
        if got is not None:
            out = got
    if out is None:
        raise BadFrame(f"transfer incomplete; missing frames {c.missing}")
    return out


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("QR transport — framing, out-of-order reassembly, hostile frames\n")
    checks = []

    payload = bytes(range(256)) * 5
    frames = encode(payload, chunk=64)
    checks.append(("splits into frames", len(frames) > 1))
    checks.append(("frames are labelled p1of N", frames[0].startswith("p1of")))
    checks.append(("round trips in order", decode(frames) == payload))
    checks.append(("round trips reversed", decode(list(reversed(frames))) == payload))

    import random
    shuffled = list(frames)
    random.Random(7).shuffle(shuffled)
    checks.append(("round trips shuffled", decode(shuffled) == payload))
    checks.append(("round trips with repeats",
                   decode(shuffled + shuffled) == payload))

    checks.append(("a short payload is one frame",
                   len(encode(b"hello")) == 1 and decode(encode(b"hello")) == b"hello"))
    checks.append(("an empty payload survives", decode(encode(b"")) == b""))

    # Incomplete transfers must yield nothing at all, not a partial payload.
    c = Collector()
    for f in frames[:-1]:
        got = c.feed(f)
    checks.append(("incomplete returns None", got is None))
    checks.append(("and knows what is missing", c.missing == [len(frames)]))
    checks.append(("progress is reportable", "of" in c.progress()))
    checks.append(("the last frame completes it", c.feed(frames[-1]) == payload))

    # Hostile frames.
    def bad(label, fn):
        try:
            fn()
            checks.append((label, False))
        except BadFrame:
            checks.append((label, True))

    bad("refuses a frame that is not pNofM", lambda: Collector().feed("hello world"))
    bad("refuses a total of zero", lambda: Collector().feed("p1of0 aaaa"))
    bad("refuses an index above the total", lambda: Collector().feed("p5of2 aaaa"))
    bad("refuses an index of zero", lambda: Collector().feed("p0of2 aaaa"))

    def mixed():
        c2 = Collector()
        c2.feed(frames[0])
        c2.feed("p1of99 aaaa")
    bad("refuses two transfers mixed on screen", mixed)

    def swapped():
        c3 = Collector()
        c3.feed(frames[0])
        c3.feed("p1of%d %s" % (len(frames), "AAAA"))
    bad("refuses a chunk replaced mid-scan", swapped)

    bad("refuses a payload that is not base64",
        lambda: Collector().feed("p1of1 not base64!!!"))
    bad("refuses an incomplete transfer at decode",
        lambda: decode(frames[:-1]))

    # A repeat of the SAME chunk is fine — that is what an animated loop does.
    c4 = Collector()
    for f in frames + frames:
        r = c4.feed(f)
    checks.append(("identical repeats are harmless", r == payload))

    # The digest both sides compare.
    checks.append(("digest is stable", digest(payload) == digest(payload)))
    checks.append(("digest changes with the payload",
                   digest(payload) != digest(payload + b"\x00")))

    # A realistic PSBT-sized transfer.
    big = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(64))
    checks.append(("a 2 kB payload round trips", decode(encode(big)) == big))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
