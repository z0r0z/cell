#!/usr/bin/env python3
"""Seed entropy from the chamber, as a third term nobody else can audit for you.

WHY BOTHER. `tools/provision.py` draws the seed from the kernel CSPRNG XORed
with the ATECC608B's hardware RNG. Both are sound and both are black boxes:
one is Broadcom's ring oscillator behind Linux's pool, the other is
Microchip's behind a datasheet paragraph. Neither can be measured by the
person whose coins depend on it, and a hardware wallet that cannot show you
where your seed came from is asking for the same trust every other one asks
for.

The laser and the lensless camera that watch blood clot can be measured. This
takes a third term from them, states a min-entropy bound it measured on the
sample it actually drew, and XORs it in.

THE THING THAT MAKES THIS NOT A GIMMICK, AND THE EASIEST WAY TO GET IT WRONG.
A single speckle image is the PUF. It is REPRODUCIBLE BY CONSTRUCTION -- that
is the whole point of optical_puf.py, and a device that derived seed entropy
from one frame would derive the same "entropy" on every power cycle for the
rest of its life. The randomness is not in the pattern. It is in what changes
between frames: photon shot noise, sensor read noise, and the laser's own
amplitude wander.

So the source here is the DIFFERENCE between disjoint pairs of frames. The
static field cancels in the subtraction, which is exactly what leaves the
noise behind. Disjoint pairs rather than successive differences, because
d1 = f2 - f1 and d2 = f3 - f2 share f2, and a shared term is a correlation an
entropy estimate will not see.

NICE SYMMETRY, AND IT IS LOAD-BEARING. optical_puf selects the cells that are
stable and discards the rest. This wants the part that was discarded. Same
capture, orthogonal halves, and no conflict between them: the PUF's key comes
from where the pattern sits, and this comes from how much the reading of it
wobbles.

WHAT IT MUST NEVER DO. Replace either existing source. The output is XORed, so
a chamber that is broken, blocked, dark, or dishonest cannot reduce the
entropy below what the other two already supplied. A source that fails its
health tests contributes nothing and says so; it never silently degrades.

HEALTH TESTS. The two continuous tests from NIST SP 800-90B section 4.4, plus
the same min-entropy estimators optical_puf.py uses on the PUF's own bits:

  repetition count (4.4.1)     a stuck sensor, a dark chamber, a dead laser
  adaptive proportion (4.4.2)  a source that is alive and badly biased
  min-entropy (6.3.1, 6.3.3)   what the sample is actually worth

The output is SHA-256 over the raw residual, and it is refused unless the
measured min-entropy of the input exceeds twice the bits being asked for.
Twice, because per-bit min-entropy does not compose to joint min-entropy under
correlation the estimators cannot see, and the margin is what stands in for a
proof this cannot give.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

import numpy as np

import optical_puf as puf

# Twice the requested bits, in measured min-entropy, before a sample is used.
ENTROPY_MARGIN = 2.0

# SP 800-90B 4.4.1. The standard's C = 1 + ceil(-log2(alpha) / H) buys a false
# alarm rate of alpha PER SAMPLE. A fixed 21 (alpha = 2^-20, H = 1) is right
# for a source read one sample at a time and wrong for a one-shot draw: the
# 64x96x96 burst this module harvests is ~295k samples, each getting its own
# chance at the alarm, so a perfectly healthy chamber was refused about a
# quarter of the time -- with a message blaming a dead laser. Size the cutoff
# for the number of samples actually drawn.
REPETITION_ALPHA = 2.0 ** -20                   # per DRAW, not per sample


def repetition_cutoff(n_bits: int, h: float = 1.0,
                      alpha: float = REPETITION_ALPHA) -> int:
    """SP 800-90B 4.4.1's C, sized for a draw of `n_bits` samples."""
    return 1 + math.ceil(-math.log2(alpha / max(n_bits, 1)) / h)

# SP 800-90B 4.4.2, binary: a 1024-sample window, and a cutoff a fair source
# clears with room to spare. 650/1024 is about 8.8 sigma from balanced.
PROPORTION_WINDOW = 1024
PROPORTION_CUTOFF = 650


class NotEnoughEntropy(Exception):
    """The chamber did not produce a sample worth mixing in.

    Always survivable. The caller XORs whatever it has, so this costs the
    third term and nothing else.
    """


@dataclass
class Report:
    """What the sample measured, so the claim travels with the seed."""

    frames: int
    pairs: int
    bits: int
    per_bit: float                  # measured min-entropy, bits per bit
    total: float                    # per_bit * bits
    wanted: int                     # bits of output asked for
    ones: float                     # fraction, for a human to sanity-check
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures and self.total >= self.wanted * ENTROPY_MARGIN

    def lines(self) -> list[str]:
        out = [f"  frames            {self.frames} ({self.pairs} disjoint pairs)",
               f"  raw bits          {self.bits}",
               f"  ones              {self.ones:.4f}",
               f"  min-entropy/bit   {self.per_bit:.4f}",
               f"  min-entropy total {self.total:.0f} bits, against "
               f"{self.wanted * ENTROPY_MARGIN:.0f} required",
               f"  verdict           {'usable' if self.ok else 'REFUSED'}"]
        return out + [f"  failed            {f}" for f in self.failures]


def residuals(frames: np.ndarray) -> np.ndarray:
    """Disjoint frame differences. The static field cancels; the noise does not.

    Pairs are (0,1), (2,3), ... so no frame appears in two differences. Sharing
    one would correlate the results in a way the estimators below cannot see.
    """
    f = np.asarray(frames, dtype=np.float64)
    if f.ndim != 3:
        raise NotEnoughEntropy(
            f"expected a burst of frames shaped (n, h, w), got {f.shape}")
    n = f.shape[0]
    if n < 2:
        raise NotEnoughEntropy(
            "a difference needs two frames; one frame is the PUF, not a source")
    pairs = n // 2
    return f[0:2 * pairs:2] - f[1:2 * pairs:2]


def bits_from(residual: np.ndarray) -> np.ndarray:
    """One bit per pixel: is this difference above its own frame's median.

    The median rather than zero, because a frame pair taken while the laser
    was settling has a DC offset between them, and a fixed threshold would
    read that offset as a long run of ones. Sign against the median is
    invariant to it.

    It is invariant to more than that, and the invariance is worth stating so
    nobody reads it as a weakness. Any strictly monotone distortion of the
    residual leaves every bit unchanged, so a noise distribution that is
    one-sided, skewed or oddly scaled is still a source. What the median
    cannot rescue is a residual with mass piled at one VALUE -- an overexposed
    chamber whose pixels all clip to the same number leaves ties, ties all
    fall on one side of a threshold, and the proportion test below is what
    catches it.
    """
    r = np.asarray(residual, dtype=np.float64)
    if r.ndim == 2:
        r = r[None, ...]
    out = []
    for plane in r:
        flat = plane.ravel()
        out.append((flat > np.median(flat)).astype(np.uint8))
    return np.concatenate(out) if out else np.zeros(0, dtype=np.uint8)


def repetition_count(bits: np.ndarray) -> int:
    """The longest run. SP 800-90B 4.4.1 catches a source that has stopped.

    The cutoff is not a parameter here because it depends on how many samples
    were drawn — see `repetition_cutoff`, which `assess` sizes per draw.
    """
    b = np.asarray(bits, dtype=np.uint8).ravel()
    if b.size == 0:
        return 0
    edges = np.flatnonzero(np.diff(b)) + 1
    starts = np.concatenate(([0], edges))
    ends = np.concatenate((edges, [b.size]))
    return int((ends - starts).max())


def adaptive_proportion(bits: np.ndarray, window: int = PROPORTION_WINDOW
                        ) -> int:
    """The commonest value's count in the worst window. SP 800-90B 4.4.2."""
    b = np.asarray(bits, dtype=np.uint8).ravel()
    if b.size < window:
        # -1, not 0. Zero is well under the cutoff, so assess() read "the test
        # could not run" as "the test passed" for every sample shorter than
        # one window.
        return -1
    n = b.size // window
    blocks = b[:n * window].reshape(n, window)
    ones = blocks.sum(axis=1)
    return int(np.maximum(ones, window - ones).max())


def assess(bits: np.ndarray, want_bits: int, frames: int, pairs: int) -> Report:
    """Measure a sample and say whether it may be used."""
    b = np.asarray(bits, dtype=np.uint8).ravel()
    per_bit = puf.min_entropy(b) if b.size >= 2 else 0.0
    rep = repetition_count(b)
    prop = adaptive_proportion(b)
    failures = []
    rep_cut = repetition_cutoff(b.size)
    if rep >= rep_cut:
        failures.append(
            f"repetition count: a run of {rep} identical bits, cutoff "
            f"{rep_cut}. A dark chamber, a dead laser or a stuck "
            f"sensor looks exactly like this")
    if prop < 0:
        failures.append(
            f"adaptive proportion: {b.size} bits is less than one "
            f"{PROPORTION_WINDOW}-bit window, so the test could not run")
    elif prop >= PROPORTION_CUTOFF:
        failures.append(
            f"adaptive proportion: {prop} of {PROPORTION_WINDOW} in one "
            f"window, cutoff {PROPORTION_CUTOFF}")
    r = Report(frames=frames, pairs=pairs, bits=int(b.size), per_bit=per_bit,
               total=per_bit * b.size, wanted=want_bits,
               ones=float(b.mean()) if b.size else 0.0, failures=failures)
    if not failures and r.total < want_bits * ENTROPY_MARGIN:
        r.failures.append(
            f"min-entropy: {r.total:.0f} bits measured against "
            f"{want_bits * ENTROPY_MARGIN:.0f} required. Capture more frames")
    return r


def harvest(frames: np.ndarray, want_bytes: int = 32
            ) -> "tuple[bytes, Report]":
    """-> (bytes, report). Raises NotEnoughEntropy rather than returning weak bytes.

    The output is a hash of the raw residual, not of the extracted bits: the
    bits are what gets measured, and the residual is what carries everything
    the measurement had to throw away in order to be conservative.
    """
    res = residuals(frames)
    bits = bits_from(res)
    report = assess(bits, want_bytes * 8, int(np.asarray(frames).shape[0]),
                    int(res.shape[0]))
    if not report.ok:
        raise NotEnoughEntropy("; ".join(report.failures))
    # Quantised before hashing so the digest does not depend on float
    # formatting, and salted so this cannot collide with any other use of the
    # same capture.
    q = np.rint(res * 256.0).astype(np.int32)
    # SHAKE, not SHA-256: the health check is run against the number of bytes
    # ASKED FOR, and a fixed 32-byte digest silently returned fewer than that
    # for any larger request -- so a future 48- or 64-byte seed would have
    # taken no chamber contribution at all past byte 32, with report.ok True.
    h = hashlib.shake_256(b"CELL/chamber-trng-v1" + q.tobytes())
    return h.digest(want_bytes), report


def _selftest() -> int:                                     # pragma: no cover
    import test_chamber_trng
    return test_chamber_trng.main()


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(_selftest())
