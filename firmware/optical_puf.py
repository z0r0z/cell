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


def speckle_features(frames: np.ndarray, envelope_px: float = 12.0,
                     grain_px: int = 4) -> tuple[np.ndarray, np.ndarray]:
    """One speckle burst -> (bit per grain, how far that bit is from flipping).

    The diffuser is static, so unlike the blood path we AVERAGE the burst: the
    pattern does not move and averaging buys shot-noise SNR. Then remove the
    illumination envelope and take the sign. Sign is what makes this survive
    exposure and gain drift -- an intensity threshold would not.

    One bit per grain, not per pixel: neighbouring pixels inside a grain are
    the same measurement, and counting them again would inflate the entropy
    estimate without adding any.

    The margin is the second return and it is what makes the scheme work. A
    grain whose filtered value sits near the median is one shot noise event
    from reading the other way; a grain far from it is not. Drift flips the
    marginal bits first, so selecting on this at enrolment is worth far more
    than any amount of extra error correction -- BCH cannot reach 10% at a
    useful rate, and with the margin it does not have to.
    """
    f = np.asarray(frames, dtype=np.float64)
    if f.ndim == 2:
        f = f[None, ...]
    hp = _highpass(f.mean(axis=0), envelope_px)
    h, w = hp.shape
    gh, gw = h // grain_px, w // grain_px
    if gh == 0 or gw == 0:
        raise ValueError("ROI smaller than one speckle grain")
    cells = hp[:gh * grain_px, :gw * grain_px]
    cells = cells.reshape(gh, grain_px, gw, grain_px).mean(axis=(1, 3))
    centred = (cells - np.median(cells)).ravel()
    scale = np.median(np.abs(centred)) or 1.0
    return (centred > 0).astype(np.uint8), np.abs(centred) / scale


def speckle_bits(frames: np.ndarray, envelope_px: float = 12.0,
                 grain_px: int = 4) -> np.ndarray:
    """Just the bits, for callers that do not select on reliability."""
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

    def leakage_bits(self) -> int:
        """Upper bound on what the offset discloses: the code's redundancy."""
        return BCH(self.m, self.t).n - BCH(self.m, self.t).k


class PufError(Exception):
    """The chamber did not answer as enrolled."""


def _key(bits: np.ndarray, salt: bytes) -> bytes:
    packed = np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()
    return hashlib.sha256(b"CELL-puf-v1" + salt + packed).digest()


def enroll(reads: list[tuple[np.ndarray, np.ndarray]], m: int = 12,
           t: int = 180, salt: bytes = b"",
           rng: Optional[np.random.Generator] = None) -> tuple[Helper, bytes]:
    """Several (bits, margin) reads of an undisturbed chamber -> helper, key.

    Reads should span whatever conditions the device will see -- cold, warm,
    after a knock. Two filters run here and they do different jobs. A position
    that disagreed between reads is already known to be bad. A position that
    agreed but sits close to the sign boundary has not failed YET, and is the
    one that will fail in six months. Ranking the survivors by their weakest
    margin and taking the strongest n is what buys the error budget.

    The mask is public. It names positions, not values, and a position being
    reliable says nothing about which way it reads.
    """
    if len(reads) < 2:
        raise ValueError("enrolment needs at least two reads")
    bits = np.stack([np.asarray(b, dtype=np.uint8) for b, _ in reads])
    margins = np.stack([np.asarray(g, dtype=np.float64) for _, g in reads])

    agree = (bits == bits[0]).all(axis=0)
    worst = margins.min(axis=0)
    worst[~agree] = -1.0

    code = BCH(m, t)
    usable = int(np.count_nonzero(agree))
    if usable < code.n:
        raise PufError(
            f"only {usable} stable bits, code needs {code.n}. "
            f"Enlarge the ROI: at a {code.n}-bit code you want at least "
            f"{2 * code.n} grains so the margin filter has something to cut.")
    mask = np.sort(np.argsort(worst)[-code.n:])
    w = bits[0][mask]

    rng = rng or np.random.default_rng()
    msg = rng.integers(0, 2, code.k, dtype=np.uint8)
    offset = code.encode(msg) ^ w
    return Helper(mask, offset, m, t, salt), _key(w, salt)


def reproduce(read: np.ndarray, helper: Helper) -> bytes:
    """A fresh read plus the public helper -> the same key, or PufError.

    PufError is the tamper signal. It is not a comparison the firmware may
    skip: without the key there is nothing to unwrap the seed with.
    """
    r = np.asarray(read, dtype=np.uint8)
    if helper.mask.size and helper.mask.max() >= r.size:
        raise PufError("read is smaller than the enrolled ROI")
    w2 = r[helper.mask]
    code = BCH(helper.m, helper.t)
    fixed = code.decode(helper.offset ^ w2)
    if fixed is None:
        raise PufError("chamber response is outside the enrolled radius")
    return _key(helper.offset ^ fixed, helper.salt)


def budget(m: int = 12, t: int = 180, per_bit_entropy: float = 0.85) -> dict:
    """What the parameters buy, so the choice is arguable rather than asserted."""
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
             m=helper.m, t=helper.t, salt=np.frombuffer(helper.salt, np.uint8))


def load_helper(path: str) -> Helper:
    z = np.load(path)
    return Helper(mask=z["mask"], offset=z["offset"].astype(np.uint8),
                  m=int(z["m"]), t=int(z["t"]),
                  salt=z["salt"].tobytes())


def chamber_reader(capture, helper: Helper, grain_px: int = 4):
    """-> a callable the signer can hold, returning the chamber's key.

    `capture` takes a burst from the speckle camera with the laser on and the
    cartridge bay empty. Raises PufError if the chamber does not answer as
    enrolled, which is the whole point: the caller cannot get a key that is
    merely close.
    """
    def read() -> bytes:
        bits, _margin = speckle_features(capture(), grain_px=grain_px)
        return reproduce(bits, helper)
    return read
