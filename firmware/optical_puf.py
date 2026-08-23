"""CELL optical PUF — the chamber as the tamper boundary.

WHAT THIS IS FOR. A Pi has no secure boot, so an attacker who opens the case
can replace the firmware, return the device, and let the owner type the PIN
into it. That is the one attack the ATECC608B does not bound: its monotonic
counter caps a blind guesser at 2,097,151 attempts against a 10^8 keyspace,
but it cannot help when the owner supplies the PIN willingly.

A secure element answers this with a mesh over the die: disturb the package
and the key is destroyed. This module builds the same property out of parts
already in the BOM.

THE IDEA. Epoxy a diffuser into the optical chamber. Laser speckle from a
rough surface is fixed by microstructure at the sub-micron scale -- chaotic,
unrepeatable, and not manufacturable to a copy. It is the oldest studied
physical unclonable function (Pappu et al., Physical One-Way Functions,
Science 2002). The 650 nm diode and the lensless camera that measure clotting
already form the reader; between transactions they sit idle.

So make the speckle response an INPUT to the key derivation:

    wrapping_key = KDF(PIN, ATECC secret, optical_puf)

Not a check the firmware performs. Malicious firmware can skip a boolean; it
cannot skip a term in a KDF. Put the SD card inside the sealed volume and
reflashing requires opening the chamber, which changes the speckle, which
means the key is not wrong -- it no longer exists. Tamper-evident becomes
tamper-responsive, which is the property class the mesh is bought for.

Failure is toward a brick, not toward a loss: the seed is BIP39 on steel.

WHY THIS NEEDS A FUZZY EXTRACTOR. Speckle drifts. Laser wavelength moves with
temperature (~0.25 nm/K on a bare diode), the mount creeps, dust lands. A raw
read never repeats bit for bit, so a naive implementation bricks itself on a
cold morning. The standard construction is code-offset (Dodis et al.): store
public helper data that snaps a noisy read back onto the enrolled value, and
hash the result.

    enrol:      w  <- read           helper = w XOR C(r)      key = H(w)
    reproduce:  w' <- read           C(r)' = helper XOR w'
                decode to C(r), then w = helper XOR C(r),     key = H(w)

The helper is XORed with a random codeword, so it reveals nothing about the
key beyond the code's redundancy -- which is why the code matters.

WHY NOT A REPETITION CODE, which is the obvious way to get a high correction
rate cheaply. Code-offset helper data for an (n,1) repetition code discloses
the XOR of every bit in a block with the first, i.e. n-1 of the n bits. At a
per-bit min-entropy of 0.9 a 128-bit block carries 115 bits and leaks 127. The
construction eats more than it protects. This module uses BCH, whose leakage
is bounded by n-k.

THE LEVER IS BER, NOT THE CODE. BCH cannot correct 15% at any useful rate --
k = n - m*t runs out first. The fix is reliability masking, which is standard
PUF practice: enrol across several reads, keep only the bit positions that
agreed every time, discard the rest. The mask is public and names positions,
not values. It converts a soft problem into an easy one, and it is what makes
the code parameters here comfortable rather than marginal.

AND THE MASK IS WHERE THE ENTROPY GOES, IF NOTHING WATCHES IT. Selecting the
most reliable bits is selecting on the measurement, so it can select on the
value too. Speckle intensity is exponential: the bright tail is long, the dark
side stops at zero, and a raw margin therefore prefers bright cells. Measured,
that gave 81% ones -- 0.69 bits each against a helper disclosing n-k -- with
adjacent survivors agreeing 97% of the time because bright speckle clusters.
bits_from_image ranks cells to a quantile before taking the sign, which makes
the two sides of the boundary mean the same thing, and enrolment refuses to
take two touching grains. Selected bias is now near one half and the checks in
test_optical_puf fail if it drifts.

WHAT IS NOT ANSWERED HERE. Whether a real epoxied diffuser holds its pattern
across months and temperature, which is the only question that decides whether
this ships. This module makes that question answerable -- `calibrate.py` grows
a puf-panel once hardware exists. Everything below is validated against a
simulated field with a drift model, which proves the mathematics and proves
nothing about the optics.

Dependencies: numpy.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import numpy as np

# --------------------------------------------------------------------------
# GF(2^m)
# --------------------------------------------------------------------------

# Primitive polynomials, as integers with the x^m term included.
_PRIM = {4: 0b10011, 5: 0b100101, 6: 0b1000011, 7: 0b10001001,
         8: 0b100011101, 9: 0b1000010001, 10: 0b10000001001,
         11: 0b100000000101, 12: 0b1000001010011, 13: 0b10000000011011}


class GF:
    """GF(2^m) with exp/log tables. Elements are ints in [0, 2^m)."""

    def __init__(self, m: int):
        if m not in _PRIM:
            raise ValueError(f"no primitive polynomial for m={m}")
        self.m = m
        self.n = (1 << m) - 1
        self.exp = [0] * (2 * self.n)
        self.log = [0] * (self.n + 1)
        x = 1
        for i in range(self.n):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x > self.n:
                x ^= _PRIM[m]
        for i in range(self.n, 2 * self.n):
            self.exp[i] = self.exp[i - self.n]

    def mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("inverse of 0 in GF(2^m)")
        return self.exp[self.n - self.log[a]]

    def pow(self, a: int, e: int) -> int:
        if a == 0:
            return 0
        return self.exp[(self.log[a] * e) % self.n]


def _polymul(gf: GF, a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    out[i + j] ^= gf.mul(ai, bj)
    return out


# --------------------------------------------------------------------------
# BCH
# --------------------------------------------------------------------------

class BCH:
    """Binary BCH over GF(2^m), correcting up to t errors in n = 2^m - 1 bits.

    Bit vectors are numpy uint8 arrays, index 0 = coefficient of x^0.
    """

    def __init__(self, m: int, t: int):
        self.gf = GF(m)
        self.m, self.t, self.n = m, t, (1 << m) - 1

        # Generator = LCM of the minimal polynomials of alpha^1 .. alpha^2t.
        gf = self.gf
        seen: set[int] = set()
        g = [1]
        for i in range(1, 2 * t + 1):
            if i in seen:
                continue
            # Conjugate set of alpha^i under Frobenius.
            conj, c = [], i
            while c not in seen:
                seen.add(c)
                conj.append(c)
                c = (c * 2) % self.n
            minpoly = [1]
            for c in conj:
                minpoly = _polymul(gf, minpoly, [gf.exp[c], 1])
            g = _polymul(gf, g, minpoly)
        if any(x not in (0, 1) for x in g):
            raise ArithmeticError("generator polynomial left GF(2)")
        self.g = np.array(g, dtype=np.uint8)
        self.k = self.n - (len(g) - 1)
        if self.k <= 0:
            raise ValueError(f"m={m}, t={t} leaves no message space")

    # -- encoding ------------------------------------------------------

    def encode(self, msg: np.ndarray) -> np.ndarray:
        """Systematic: parity in the low positions, message in the high ones."""
        msg = np.asarray(msg, dtype=np.uint8)
        if msg.size != self.k:
            raise ValueError(f"message must be {self.k} bits, got {msg.size}")
        shifted = np.zeros(self.n, dtype=np.uint8)
        shifted[self.n - self.k:] = msg
        rem = self._mod_g(shifted)
        out = shifted.copy()
        out[:len(rem)] ^= rem
        return out

    def _mod_g(self, poly: np.ndarray) -> np.ndarray:
        r = poly.astype(np.uint8).copy()
        deg_g = len(self.g) - 1
        for i in range(len(r) - 1, deg_g - 1, -1):
            if r[i]:
                r[i - deg_g:i + 1] ^= self.g
        return r[:deg_g]

    def message(self, codeword: np.ndarray) -> np.ndarray:
        return np.asarray(codeword, dtype=np.uint8)[self.n - self.k:]

    # -- decoding ------------------------------------------------------

    def _syndromes(self, r: np.ndarray) -> list[int]:
        gf, out = self.gf, []
        nz = np.flatnonzero(r)
        for i in range(1, 2 * self.t + 1):
            s = 0
            for j in nz:
                s ^= gf.exp[(i * int(j)) % self.n]
            out.append(s)
        return out

    def _berlekamp_massey(self, S: list[int]) -> list[int]:
        gf = self.gf
        C, B = [1], [1]
        L, mshift, b = 0, 1, 1
        for i in range(len(S)):
            d = S[i]
            for j in range(1, L + 1):
                if j < len(C):
                    d ^= gf.mul(C[j], S[i - j])
            if d == 0:
                mshift += 1
            elif 2 * L <= i:
                T = list(C)
                coef = gf.mul(d, gf.inv(b))
                shifted = [0] * mshift + [gf.mul(coef, x) for x in B]
                if len(shifted) > len(C):
                    C = C + [0] * (len(shifted) - len(C))
                for j, x in enumerate(shifted):
                    C[j] ^= x
                L, B, b, mshift = i + 1 - L, T, d, 1
            else:
                coef = gf.mul(d, gf.inv(b))
                shifted = [0] * mshift + [gf.mul(coef, x) for x in B]
                if len(shifted) > len(C):
                    C = C + [0] * (len(shifted) - len(C))
                for j, x in enumerate(shifted):
                    C[j] ^= x
                mshift += 1
        return C

    def decode(self, recv: np.ndarray) -> Optional[np.ndarray]:
        """Correct up to t errors. None if the word is beyond the radius."""
        r = np.asarray(recv, dtype=np.uint8).copy()
        if r.size != self.n:
            raise ValueError(f"codeword must be {self.n} bits, got {r.size}")
        S = self._syndromes(r)
        if not any(S):
            return r
        sigma = self._berlekamp_massey(S)
        deg = len(sigma) - 1
        while deg > 0 and sigma[deg] == 0:
            deg -= 1
        if deg == 0 or deg > self.t:
            return None
        # Chien search: roots of sigma are inverses of error locators.
        gf, positions = self.gf, []
        for i in range(self.n):
            v = 0
            for j in range(deg + 1):
                if sigma[j]:
                    v ^= gf.exp[(gf.log[sigma[j]] + j * i) % self.n]
            if v == 0:
                positions.append((self.n - i) % self.n)
        if len(positions) != deg:
            return None
        for p in positions:
            r[p] ^= 1
        if any(self._syndromes(r)):
            return None
        return r


# --------------------------------------------------------------------------
# Feature extraction
# --------------------------------------------------------------------------

def _highpass(img: np.ndarray, sigma: float) -> np.ndarray:
    """Remove the illumination envelope with a separable box-blur estimate.

    A Gaussian would be better and would pull in scipy; the blood path already
    depends on it, but this module runs at boot and on a Pi Zero the import
    cost is real. Two box passes approximate a Gaussian well enough for a
    high-pass whose only job is to kill a slow envelope.
    """
    w = max(3, int(round(sigma * 2)) | 1)
    pad = w // 2
    a = img.astype(np.float64)
    for _ in range(2):
        for axis in (1, 0):
            padding = ((0, 0), (pad, pad)) if axis == 1 else ((pad, pad), (0, 0))
            q = np.pad(a, padding, mode="reflect")
            # Prepend a zero so a width-w window is c[i + w] - c[i] and the
            # result keeps the input's length rather than losing a row.
            c = np.cumsum(q, axis=axis)
            zeros = np.zeros_like(np.take(c, [0], axis=axis))
            c = np.concatenate([zeros, c], axis=axis)
            hi = np.take(c, range(w, c.shape[axis]), axis=axis)
            lo = np.take(c, range(0, c.shape[axis] - w), axis=axis)
            a = (hi - lo) / w
    return img.astype(np.float64) - a


# The outer corner reserved for registration. Its speckle is stored in the
# clear inside the helper and is NEVER key material, which is what makes
# publishing it free: speckle decorrelates over one grain, so a patch here says
# nothing about a grain over there.
FIDUCIAL_PX = 128
MAX_SHIFT_PX = 24
# The fiducial is INSET by the search radius rather than sitting in the very
# corner. At the corner a pattern that moved up or left takes the reference
# off the edge of the frame, so only half the shifts are findable -- and the
# unfindable half is not the rare one.
FIDUCIAL_ORIGIN = MAX_SHIFT_PX


def prepare(frames: np.ndarray, envelope_px: float = 12.0) -> np.ndarray:
    """One speckle burst -> the high-passed image everything else works from.

    The diffuser is static, so unlike the blood path we AVERAGE the burst: the
    pattern does not move and averaging buys shot-noise SNR. Removing the
    illumination envelope is what lets the sign of what is left mean
    something, and sign is what makes this survive exposure and gain drift.
    """
    f = np.asarray(frames, dtype=np.float64)
    if f.ndim == 2:
        f = f[None, ...]
    return _highpass(f.mean(axis=0), envelope_px)


def estimate_shift(img: np.ndarray, fiducial: np.ndarray,
                   max_shift: int = MAX_SHIFT_PX,
                   origin: "tuple[int, int] | None" = None) -> tuple[int, int]:
    """How far the pattern has moved since enrolment, in whole pixels.

    THIS IS NOT AN OPTIMISATION. A speckle grain here is about 4 px, so the
    features are destroyed by a shift of one grain -- measured, 4 px takes the
    error rate past 17% and the key is gone. The mount does not have to fail
    for that to happen: PETG over the 20 mm standoff moves roughly a pixel per
    kelvin, so a device enrolled in a warm room and opened on a cold morning
    would refuse its owner and call it tampering. Registration is the
    difference between a tamper detector and a thermometer.

    Normalised cross-correlation of one reference patch against the region of
    the fresh read it could have moved to, searched over +/-max_shift. Whole
    pixels only: sub-pixel resampling would blur the grains it is trying to
    preserve. estimate_rotation calls this once per patch; a single patch
    cannot separate a twist from a slide.
    """
    f = np.asarray(fiducial, dtype=np.float64)
    n = f.shape[0]
    oy, ox = origin or (FIDUCIAL_ORIGIN, FIDUCIAL_ORIGIN)
    h, w = img.shape

    # The search window: everywhere the patch could have moved to, clipped to
    # the frame. Brute force over it costs (2s+1)^2 patch correlations, which
    # on a Pi Zero is most of the time a signature takes. One FFT gives every
    # offset at once.
    y0, x0 = max(0, oy - max_shift), max(0, ox - max_shift)
    y1, x1 = min(h, oy + n + max_shift), min(w, ox + n + max_shift)
    region = img[y0:y1, x0:x1]
    if region.shape[0] < n or region.shape[1] < n:
        return (0, 0)

    fz = f - f.mean()
    fz_energy = float(np.sqrt((fz * fz).sum())) or 1.0

    rh, rw = region.shape
    num = np.fft.irfft2(np.fft.rfft2(region, s=(rh, rw))
                        * np.conj(np.fft.rfft2(fz, s=(rh, rw))),
                        s=(rh, rw))

    # Normalise by the energy under each placement, or a bright patch wins on
    # brightness rather than on matching. Box sums via the summed-area table.
    ones = np.ones((n, n))
    s1 = _box(region, n)
    s2 = _box(region * region, n)
    var = s2 - s1 * s1 / (n * n)
    denom = np.sqrt(np.clip(var, 1e-12, None)) * fz_energy

    valid_h, valid_w = rh - n + 1, rw - n + 1
    score = num[:valid_h, :valid_w] / denom[:valid_h, :valid_w]
    idx = int(np.argmax(score))
    py, px = divmod(idx, valid_w)
    dy, dx = (y0 + py) - oy, (x0 + px) - ox
    if abs(dy) > max_shift or abs(dx) > max_shift:
        return (0, 0)
    return (int(dy), int(dx))


def _box(a: np.ndarray, n: int) -> np.ndarray:
    """Sums of every n x n window, via a summed-area table."""
    c = np.cumsum(np.cumsum(
        np.pad(a, ((1, 0), (1, 0))), axis=0), axis=1)
    return (c[n:, n:] - c[:-n, n:] - c[n:, :-n] + c[:-n, :-n])


def bits_from_image(img: np.ndarray, grain_px: int = 4,
                    fid_b: "tuple[int, int] | None" = None
                    ) -> tuple[np.ndarray, np.ndarray]:
    """-> (bit per grain, how far that bit is from flipping).

    One bit per grain, not per pixel: neighbouring pixels inside a grain are
    the same measurement, and counting them again would inflate the entropy
    estimate without adding any.

    RANK, NOT INTENSITY. Each cell is replaced by its quantile among all cells
    before the sign is taken. This is not cosmetic and it is the second thing
    that had to be got right. Speckle intensity is exponentially distributed:
    the bright tail runs a long way and the dark side stops at zero, so
    "far from the median" almost always means "bright". Selecting on a raw
    margin therefore selects ones -- measured, 81% of the chosen bits were 1,
    worth 0.69 bits each instead of 1.0, and adjacent survivors agreed 97% of
    the time because bright speckle clusters. The margin filter that buys the
    error budget was quietly spending the entropy budget it protects.

    The quantile transform is monotone, so it changes no bit's value; it only
    makes the distance from the boundary mean the same thing on both sides.
    After it, a dark cell is as selectable as a bright one and the selection
    is unbiased by construction.

    Cells inside either reference patch are given a margin of -inf so
    enrolment never selects them. Their values are published for
    registration, and a published bit is not key material.
    """
    h, w = img.shape
    gh, gw = h // grain_px, w // grain_px
    if gh == 0 or gw == 0:
        raise ValueError("ROI smaller than one speckle grain")
    cells = img[:gh * grain_px, :gw * grain_px]
    cells = cells.reshape(gh, grain_px, gw, grain_px).mean(axis=(1, 3))

    flat = cells.ravel()
    q = np.empty(flat.size, dtype=np.float64)
    q[np.argsort(flat, kind="stable")] = np.arange(flat.size)
    q = (q + 0.5) / flat.size - 0.5           # -> (-0.5, 0.5), symmetric
    margin = np.abs(q).reshape(gh, gw) * 2.0

    for oy, ox in [(FIDUCIAL_ORIGIN, FIDUCIAL_ORIGIN)] + ([fid_b] if fid_b else []):
        ylo, xlo = oy // grain_px, ox // grain_px
        yhi = -(-(oy + FIDUCIAL_PX) // grain_px)          # round outward
        xhi = -(-(ox + FIDUCIAL_PX) // grain_px)
        margin[ylo:yhi, xlo:xhi] = -np.inf
    return (q > 0).astype(np.uint8), margin.ravel()


def _spaced(order: np.ndarray, want: int, gw: int) -> np.ndarray:
    """Take `want` positions from `order`, never two that touch.

    Adjacent grains are not independent -- they share the tail of one speckle
    lobe -- and selecting on margin makes that worse, because a lobe that is
    far from the boundary is far from it across its whole width. Refusing the
    eight neighbours of anything already taken is a cheap way to stop the key
    being drawn from a handful of blobs. Measured separation d>=2 cells is
    where the correlation disappears, so one cell of exclusion is enough.
    """
    taken = np.zeros(int(order.max()) + gw + 2, dtype=bool)
    out = []
    for i in order:
        i = int(i)
        r, c = divmod(i, gw)
        if any(taken[(r + dr) * gw + (c + dc)]
               for dr in (-1, 0, 1) for dc in (-1, 0, 1)
               if 0 <= (r + dr) * gw + (c + dc) < taken.size):
            continue
        taken[i] = True
        out.append(i)
        if len(out) == want:
            break
    return np.array(sorted(out), dtype=np.int64)


def speckle_features(frames: np.ndarray, envelope_px: float = 12.0,
                     grain_px: int = 4) -> tuple[np.ndarray, np.ndarray]:
    """Burst -> (bits, margin), for callers that do their own registration."""
    return bits_from_image(prepare(frames, envelope_px), grain_px)


def speckle_bits(frames: np.ndarray, envelope_px: float = 12.0,
                 grain_px: int = 4) -> np.ndarray:
    return speckle_features(frames, envelope_px, grain_px)[0]


# --------------------------------------------------------------------------
# Fuzzy extractor
# --------------------------------------------------------------------------

@dataclass
class Helper:
    """Public. Stored in the clear beside the encrypted seed.

    `mask` names which bit positions were stable at enrolment and `offset` is
    the codeword XOR the stable reading. Neither reveals the key: positions
    are not values, and the codeword is uniformly random.
    """

    mask: np.ndarray          # indices of the stable positions, sorted
    offset: np.ndarray        # n bits
    m: int
    t: int
    salt: bytes
    # The enrolment fiducial, in the clear. Registration needs a reference and
    # this is it; it is excluded from key material by bits_from_image, so
    # publishing it costs nothing. See estimate_shift.
    fiducial: np.ndarray = None
    grain_px: int = 4
    # A second fiducial, along a known baseline from the first. Two are what
    # separate a twist from a slide -- see estimate_rotation.
    fiducial_b: np.ndarray = None
    fid_a: tuple = (FIDUCIAL_ORIGIN, FIDUCIAL_ORIGIN)
    fid_b: tuple = (FIDUCIAL_ORIGIN, FIDUCIAL_ORIGIN)

    def leakage_bits(self) -> int:
        """Upper bound on what the offset discloses: the code's redundancy."""
        return BCH(self.m, self.t).n - BCH(self.m, self.t).k


class PufError(Exception):
    """The chamber did not answer as enrolled."""


def _key(bits: np.ndarray, salt: bytes) -> bytes:
    packed = np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()
    return hashlib.sha256(b"CELL-puf-v1" + salt + packed).digest()


def enroll(images: list[np.ndarray], m: int = 12, t: int = 180,
           salt: bytes = b"", grain_px: int = 4,
           rng: Optional[np.random.Generator] = None) -> tuple[Helper, bytes]:
    """Several prepared images of an undisturbed chamber -> helper, key.

    Images should span whatever conditions the device will see -- cold, warm,
    after a knock. Two filters run here and they do different jobs. A position
    that disagreed between reads is already known to be bad. A position that
    agreed but sits close to the sign boundary has not failed YET, and is the
    one that will fail in six months. Ranking the survivors by their weakest
    margin and taking the strongest n is what buys the error budget.

    Later images are registered against the first before they are compared, so
    a mount that moved between enrolment reads costs nothing. Without that the
    agreement filter would discard almost every position and enrolment would
    fail with a misleading complaint about the ROI being too small.

    The mask is public. It names positions, not values, and a position being
    reliable says nothing about which way it reads.
    """
    if len(images) < 2:
        raise ValueError("enrolment needs at least two reads")
    imgs = [np.asarray(i, dtype=np.float64) for i in images]
    o, n = FIDUCIAL_ORIGIN, FIDUCIAL_PX
    width = imgs[0].shape[1]
    bx = width - MAX_SHIFT_PX - n
    if bx <= o + n:
        raise PufError(
            f"ROI {width} px is too narrow for two fiducials; needs "
            f"> {2 * n + MAX_SHIFT_PX + o} px")
    fid_a, fid_b = (o, o), (o, bx)
    fiducial = imgs[0][o:o + n, o:o + n].copy()
    fiducial_b = imgs[0][o:o + n, bx:bx + n].copy()
    ref = Helper(np.array([], dtype=np.int64), np.array([], dtype=np.uint8),
                 m, t, salt, fiducial, grain_px, fiducial_b, fid_a, fid_b)

    stack, margins = [], []
    for i, img in enumerate(imgs):
        if i:
            img = _shift_to(img, ref)
        b, g = bits_from_image(img, grain_px, fid_b=fid_b)
        stack.append(b)
        margins.append(g)
    bits = np.stack(stack)
    worst = np.stack(margins).min(axis=0)
    worst[~(bits == bits[0]).all(axis=0)] = -np.inf

    code = BCH(m, t)
    gw = imgs[0].shape[1] // grain_px
    order = np.argsort(worst)[::-1]
    order = order[np.isfinite(worst[order])]
    mask = _spaced(order, code.n, gw)
    if mask.size < code.n:
        raise PufError(
            f"only {mask.size} usable non-adjacent bits, code needs {code.n}. "
            f"Enlarge the ROI: with one cell of exclusion you want at least "
            f"{6 * code.n} grains so the margin filter has something to cut.")
    w = bits[0][mask]

    rng = rng or np.random.default_rng()
    msg = rng.integers(0, 2, code.k, dtype=np.uint8)
    offset = code.encode(msg) ^ w
    return (Helper(mask, offset, m, t, salt, fiducial, grain_px,
                   fiducial_b, fid_a, fid_b),
            _key(w, salt))


def _rotate(img: np.ndarray, theta: float) -> np.ndarray:
    """Rotate about the centre by `theta` radians, nearest neighbour.

    Nearest neighbour on purpose. Interpolation would average across the grain
    boundary and blur exactly the structure being measured; at the angles this
    corrects, a whole-pixel resample is close to a permutation.
    """
    n, m = img.shape
    cy, cx = (n - 1) / 2.0, (m - 1) / 2.0
    y, x = np.mgrid[0:n, 0:m]
    yc, xc = y - cy, x - cx
    ct, st = np.cos(theta), np.sin(theta)
    sy = np.rint(ct * yc - st * xc + cy).astype(int)
    sx = np.rint(st * yc + ct * xc + cx).astype(int)
    return img[np.clip(sy, 0, n - 1), np.clip(sx, 0, m - 1)]


def estimate_rotation(img: np.ndarray, helper: "Helper") -> float:
    """Radians, from how differently the two fiducials moved.

    One fiducial cannot tell rotation from translation. Two, separated along a
    known baseline, can: a twist moves the far one across the baseline while
    the near one barely moves, and the difference over the separation is the
    angle. Measured on the simulated chamber, half a degree is already enough
    to lose the key -- about 3 px at the edge of a 768 px field -- so a mount
    that creeps in rotation rather than translation would look exactly like
    tampering without this.
    """
    if helper.fiducial_b is None:
        return 0.0
    ay, ax = helper.fid_a
    by, bx = helper.fid_b
    da = estimate_shift(img, helper.fiducial, origin=(ay, ax))
    db = estimate_shift(img, helper.fiducial_b, origin=(by, bx))
    baseline = float(bx - ax)
    if abs(baseline) < 1.0:
        return 0.0
    return float(db[0] - da[0]) / baseline


def _shift_to(img: np.ndarray, helper_or_fid) -> np.ndarray:
    """Undo rotation then whole-pixel translation, so grains land as enrolled.

    Two passes, because the translation estimate is only meaningful once the
    twist is out: with the field still rotated, the fiducial correlates worst
    exactly where it is being asked to be precise.
    """
    if isinstance(helper_or_fid, Helper):
        helper = helper_or_fid
        theta = estimate_rotation(img, helper)
        if abs(theta) > 1e-4:
            img = _rotate(img, -theta)
        fid, origin = helper.fiducial, helper.fid_a
    else:
        fid, origin = helper_or_fid, (FIDUCIAL_ORIGIN, FIDUCIAL_ORIGIN)
    dy, dx = estimate_shift(img, fid, origin=origin)
    if dy or dx:
        img = np.roll(np.roll(img, -dy, axis=0), -dx, axis=1)
    return img


def reproduce(image: np.ndarray, helper: Helper) -> bytes:
    """A fresh prepared image plus the public helper -> the key, or PufError.

    PufError is the tamper signal. It is not a comparison the firmware may
    skip: without the key there is nothing to unwrap the seed with.
    """
    img = np.asarray(image, dtype=np.float64)
    if helper.fiducial is not None:
        img = _shift_to(img, helper)
    bits, _ = bits_from_image(img, helper.grain_px, fid_b=helper.fid_b)
    if helper.mask.size and helper.mask.max() >= bits.size:
        raise PufError("read is smaller than the enrolled ROI")
    code = BCH(helper.m, helper.t)
    fixed = code.decode(helper.offset ^ bits[helper.mask])
    if fixed is None:
        raise PufError("chamber response is outside the enrolled radius")
    return _key(helper.offset ^ fixed, helper.salt)


def min_entropy(bits: np.ndarray) -> float:
    """Conservative per-bit MIN-entropy of a bit string.

    MIN-entropy, not Shannon, and the difference is the whole point. A fuzzy
    extractor's leakage argument is about the best single guess an attacker
    can make -- H_inf = -log2(p_max) -- not about the average surprise. They
    are not close where it matters: a bias of 0.44 is 0.989 bits of Shannon
    and 0.836 of min-entropy, and it is the second number the helper's n-k
    disclosure has to be paid out of.

    Two estimators, both from NIST SP 800-90B, and the smaller is returned:

      most common value (6.3.1)  the frequency of the commoner symbol, taken
                                 at its 99% upper confidence bound so a lucky
                                 sample cannot flatter the source
      Markov, order 1 (6.3.3)    the largest transition probability, which is
                                 what catches a source that is unbiased
                                 overall while still being predictable from
                                 its own previous bit

    The second one is here because this source has a specific way of failing
    that the first cannot see. Neighbouring grains share the tail of one
    speckle lobe, so a selection that happened to take adjacent cells would
    look perfectly balanced and still be guessable. Enrolment refuses touching
    grains for that reason; this measures whether that worked.

    Per-bit min-entropy does not compose to joint min-entropy under arbitrary
    correlation, so treat n * this as an estimate rather than a proof, and
    keep the margin over the key size wide.
    """
    b = np.asarray(bits, dtype=np.uint8).ravel()
    n = b.size
    if n < 2:
        return 0.0

    ones = float(b.mean())
    p_max = max(ones, 1.0 - ones)
    # 99% upper bound, so a short panel cannot report more entropy than it saw.
    p_u = min(1.0, p_max + 2.576 * np.sqrt(p_max * (1.0 - p_max) / (n - 1)))
    h_mcv = -np.log2(p_u)

    prev, nxt = b[:-1], b[1:]
    worst = 0.0
    for v in (0, 1):
        m = prev == v
        if m.sum() < 2:
            continue
        q = float(nxt[m].mean())
        worst = max(worst, max(q, 1.0 - q))
    h_markov = -np.log2(worst) if worst > 0 else h_mcv

    return float(min(h_mcv, h_markov))


def budget(m: int = 12, t: int = 180, per_bit_entropy: float = 0.78) -> dict:
    """What the parameters buy, so the choice is arguable rather than asserted.

    `per_bit_entropy` is MIN-entropy per selected bit. The default is what
    min_entropy() measures on the simulated chamber; test_optical_puf
    re-measures it on every run and fails if it drops, so this is a recorded
    measurement rather than a figure carried from one version to the next. It
    was 0.42 before the quantile transform and the adjacency rule went in.
    """
    code = BCH(m, t)
    leak = code.n - code.k
    return {"n": code.n, "k": code.k, "corrects": t,
            "max_ber": t / code.n,
            "leaked_bits": leak,
            "residual_entropy": code.n * per_bit_entropy - leak}


if __name__ == "__main__":
    b = budget()
    print(f"BCH(n={b['n']}, k={b['k']}, t={b['corrects']})")
    print(f"  corrects up to {b['max_ber']:.1%} of bits")
    print(f"  helper leaks <= {b['leaked_bits']} bits")
    print(f"  residual min-entropy ~{b['residual_entropy']:.0f} bits")


# --------------------------------------------------------------------------
# Device wiring
# --------------------------------------------------------------------------

def save_helper(helper: Helper, path: str) -> None:
    """The helper is public. It sits beside the encrypted seed in the clear.

    It is not a secret and it is not optional: without it the chamber cannot
    be decoded back to the enrolled reading, so back it up with the seed
    words. Losing it is losing the device, not the coins.
    """
    np.savez(path, mask=helper.mask, offset=helper.offset,
             m=helper.m, t=helper.t, salt=np.frombuffer(helper.salt, np.uint8),
             fiducial=np.asarray(helper.fiducial, dtype=np.float32),
             grain_px=helper.grain_px,
             fiducial_b=np.asarray(helper.fiducial_b, dtype=np.float32),
             fid_a=np.asarray(helper.fid_a), fid_b=np.asarray(helper.fid_b))


def load_helper(path: str) -> Helper:
    z = np.load(path)
    return Helper(mask=z["mask"], offset=z["offset"].astype(np.uint8),
                  m=int(z["m"]), t=int(z["t"]),
                  salt=z["salt"].tobytes(),
                  fiducial=z["fiducial"].astype(np.float64),
                  grain_px=int(z["grain_px"]),
                  fiducial_b=z["fiducial_b"].astype(np.float64),
                  fid_a=tuple(int(v) for v in z["fid_a"]),
                  fid_b=tuple(int(v) for v in z["fid_b"]))


def chamber_reader(capture, helper: Helper, grain_px: int = 4):
    """-> a callable the signer can hold, returning the chamber's key.

    `capture` takes a burst from the speckle camera with the laser on and the
    cartridge bay empty. Raises PufError if the chamber does not answer as
    enrolled, which is the whole point: the caller cannot get a key that is
    merely close.
    """
    def read() -> bytes:
        return reproduce(prepare(capture()), helper)
    return read
