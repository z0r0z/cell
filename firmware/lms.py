"""LMS hash-based signatures (RFC 8554), for post-quantum attestation.

WHY THIS, AND WHY IT FITS HERE

The attestation record is CELL's own format, not Bitcoin's, so it can move to
a post-quantum signature without waiting for a chain to. That matters more for
the attestation than for the spend key: the attestation key is published from
the day it is registered, where a spend key is only exposed once you spend.

The conservative post-quantum choice is hash-based. Security rests on the hash
function and nothing else -- no lattices, no new assumptions. Two things stop
most people using it, and CELL happens to answer both:

  IT IS STATEFUL. Signing twice with one leaf leaks the one-time key. Tracking
  that index correctly is the classic footgun, and the reason RFC 8554 spends
  a whole section on it. The device already has the answer in hardware: the
  ATECC608B's monotonic counter increments before every attestation and
  survives power loss. It is already in the record for anti-replay. That is
  exactly the leaf index, so the state everyone else has to invent is state
  this device was already keeping for another reason.

  IT RUNS OUT. A tree is a fixed number of signatures. At the design point of
  roughly two blood attestations a day, h=15 is 32,768 signatures or 44 years,
  and h=20 is fourteen centuries. The objection that kills this scheme for a
  server signing thousands of times a day does not survive a rate limit set by
  a human body.

It is also cheaper to verify on chain than it sounds, because verification is
only hashing -- no elliptic curve, no ecrecover, no modexp.

WHAT THIS IS NOT. A drop-in replacement for attest.py today. Signatures are
kilobytes rather than 64 bytes, and the tree has to be generated and its root
published at provisioning. See contracts/ for the on-chain side and the
measured gas.

Checked against the RFC 8554 Appendix F test vectors in test_lms.py, not only
against itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

H = hashlib.sha256
N = 32                      # hash output, bytes

# Typecodes, RFC 8554 sections 4.1 and 5.1.
LMOTS_SHA256_N32_W4 = 0x00000003
LMS_SHA256_M32_H5   = 0x00000005
LMS_SHA256_M32_H10  = 0x00000006
LMS_SHA256_M32_H15  = 0x00000007
LMS_SHA256_M32_H20  = 0x00000008

_LMS_H = {LMS_SHA256_M32_H5: 5, LMS_SHA256_M32_H10: 10,
          LMS_SHA256_M32_H15: 15, LMS_SHA256_M32_H20: 20}
_H_LMS = {v: k for k, v in _LMS_H.items()}

LMOTS_SHA256_N32_W1 = 0x00000001
LMOTS_SHA256_N32_W2 = 0x00000002
LMOTS_SHA256_N32_W8 = 0x00000004

# RFC 8554 Table 1: typecode -> (w, p, ls).
#
# The choice between them is the whole size-versus-gas question. w=8 gives the
# smallest signature, 1124 bytes of OTS against 2180, but the verifier then
# walks Winternitz chains up to 255 long instead of 15 -- and on chain the cost
# is dominated by the number of hashes, not the calldata. w=4 is the default
# here for that reason; contracts/ measures both.
_OTS = {
    LMOTS_SHA256_N32_W1: (1, 265, 7),
    LMOTS_SHA256_N32_W2: (2, 133, 6),
    LMOTS_SHA256_N32_W4: (4, 67, 4),
    LMOTS_SHA256_N32_W8: (8, 34, 0),
}
W, P, LS = _OTS[LMOTS_SHA256_N32_W4]        # module defaults

D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383


class LMSError(Exception):
    pass


class OutOfLeaves(LMSError):
    """The tree is exhausted. Not recoverable: a new tree means a new root."""


class LeafReused(LMSError):
    """A leaf index was used twice.

    Fatal on purpose. Two signatures under one LM-OTS key let an attacker
    combine the revealed chain values into a forgery, so this is the failure
    the whole design exists to make impossible. It is raised rather than
    returned so it cannot be ignored by a caller that checks a boolean.
    """


def _u32(x: int) -> bytes:
    return x.to_bytes(4, "big")


def _u16(x: int) -> bytes:
    return x.to_bytes(2, "big")


def _coef(s: bytes, i: int, w: int) -> int:
    """The i-th w-bit digit of s. RFC 8554 section 3.1.3."""
    return (2 ** w - 1) & (s[i * w // 8] >> (8 - (w * (i % (8 // w)) + w)))


def _checksum(s: bytes, w: int, ls: int) -> bytes:
    """RFC 8554 Algorithm 2.

    Without this an attacker can advance any Winternitz chain: every digit of
    a forged hash that is larger than the real one is reachable by hashing
    forward. The checksum decreases when the digits increase, so a forgery
    would have to advance a chain and walk one backwards at the same time.
    """
    total = 0
    for i in range(N * 8 // w):
        total += (2 ** w - 1) - _coef(s, i, w)
    return _u16((total << ls) & 0xFFFF)


# --------------------------------------------------------------------------
# LM-OTS
# --------------------------------------------------------------------------


def _ots_private(seed: bytes, I: bytes, q: int, p: int) -> list[bytes]:
    """Derive one leaf's p chain seeds.

    Pseudorandom generation, RFC 8554 Appendix A: the whole tree comes from one
    secret, so the device stores a seed rather than 2^h private keys. On device
    that seed comes from the secure element, and never leaves it.

    The order is the RFC's, `H(I || u32(q) || u16(i) || u8(0xff) || SEED)`,
    which this used to cite while computing `H(SEED || I || ...)`. Nothing
    interoperates on it -- only the Merkle root is ever published -- but the
    RFC's order also puts the 32-byte secret in the SHA-256 SUFFIX rather than
    the prefix, which is the stronger of the two positions. Changing it
    changes every tree, so it is done before any root is provisioned.
    """
    return [H(I + _u32(q) + _u16(i) + b"\xff" + seed).digest() for i in range(p)]


def _ots_public(x: list[bytes], I: bytes, q: int, w: int) -> bytes:
    y = []
    for i, xi in enumerate(x):
        tmp = xi
        for j in range(2 ** w - 1):
            tmp = H(I + _u32(q) + _u16(i) + bytes([j]) + tmp).digest()
        y.append(tmp)
    return H(I + _u32(q) + _u16(D_PBLC) + b"".join(y)).digest()


def _ots_sign(x: list[bytes], I: bytes, q: int, message: bytes,
              C: bytes, ots_type: int) -> bytes:
    w, _, ls = _OTS[ots_type]
    Q = H(I + _u32(q) + _u16(D_MESG) + C + message).digest()
    QC = Q + _checksum(Q, w, ls)
    out = [_u32(ots_type), C]
    for i, xi in enumerate(x):
        a = _coef(QC, i, w)
        tmp = xi
        for j in range(a):
            tmp = H(I + _u32(q) + _u16(i) + bytes([j]) + tmp).digest()
        out.append(tmp)
    return b"".join(out)


def _ots_public_from_sig(sig: bytes, I: bytes, q: int, message: bytes,
                         ots_type: int) -> bytes:
    """RFC 8554 Algorithm 4b: the public key a signature implies."""
    if ots_type not in _OTS:
        raise LMSError("unsupported LM-OTS typecode")
    w, p, ls = _OTS[ots_type]
    if len(sig) != 4 + N * (p + 1):
        raise LMSError(f"ots signature must be {4 + N * (p + 1)} bytes")
    if int.from_bytes(sig[:4], "big") != ots_type:
        raise LMSError("LM-OTS typecode does not match the public key")
    C = sig[4:4 + N]
    y = [sig[4 + N * (i + 1):4 + N * (i + 2)] for i in range(p)]

    Q = H(I + _u32(q) + _u16(D_MESG) + C + message).digest()
    QC = Q + _checksum(Q, w, ls)
    z = []
    for i in range(p):
        a = _coef(QC, i, w)
        tmp = y[i]
        for j in range(a, 2 ** w - 1):
            tmp = H(I + _u32(q) + _u16(i) + bytes([j]) + tmp).digest()
        z.append(tmp)
    return H(I + _u32(q) + _u16(D_PBLC) + b"".join(z)).digest()


# --------------------------------------------------------------------------
# LMS
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKey:
    lms_type: int
    ots_type: int
    I: bytes                # 16-byte tree identifier
    T1: bytes               # Merkle root

    def pack(self) -> bytes:
        return _u32(self.lms_type) + _u32(self.ots_type) + self.I + self.T1

    @staticmethod
    def unpack(b: bytes) -> "PublicKey":
        if len(b) != 4 + 4 + 16 + N:
            raise LMSError(f"public key must be {4 + 4 + 16 + N} bytes")
        lms_type = int.from_bytes(b[:4], "big")
        if lms_type not in _LMS_H:
            raise LMSError("unsupported LMS typecode")
        return PublicKey(lms_type, int.from_bytes(b[4:8], "big"), b[8:24], b[24:])

    @property
    def h(self) -> int:
        return _LMS_H[self.lms_type]


class PrivateKey:
    """A tree, generated from one seed.

    The leaf index is supplied by the caller, not tracked here. On device it is
    the secure element's monotonic counter, which is the only place it can live
    and survive a power cut mid-signature. `used` exists so the software path
    still refuses a reuse rather than silently forging a hole in itself.
    """

    def __init__(self, seed: bytes, I: bytes, h: int = 10,
                 ots_type: int = LMOTS_SHA256_N32_W4):
        if len(seed) != 32 or len(I) != 16:
            raise LMSError("seed must be 32 bytes and I 16 bytes")
        if h not in _H_LMS:
            raise LMSError(f"h must be one of {sorted(_H_LMS)}")
        if ots_type not in _OTS:
            raise LMSError("unsupported LM-OTS typecode")
        self.seed, self.I, self.h, self.ots_type = seed, I, h, ots_type
        self._used: set[int] = set()
        self._nodes = self._build()

    def _build(self) -> list[bytes]:
        """Full tree, 1-indexed: nodes[1] is the root, nodes[2^h + q] a leaf."""
        n_leaves = 1 << self.h
        nodes = [b""] * (2 * n_leaves)
        w, p_, _ = _OTS[self.ots_type]
        for q in range(n_leaves):
            k = _ots_public(_ots_private(self.seed, self.I, q, p_), self.I, q, w)
            r = n_leaves + q
            nodes[r] = H(self.I + _u32(r) + _u16(D_LEAF) + k).digest()
        for r in range(n_leaves - 1, 0, -1):
            nodes[r] = H(self.I + _u32(r) + _u16(D_INTR)
                         + nodes[2 * r] + nodes[2 * r + 1]).digest()
        return nodes

    def public_key(self) -> PublicKey:
        return PublicKey(_H_LMS[self.h], self.ots_type, self.I, self._nodes[1])

    def sign(self, message: bytes, q: int, C: bytes | None = None) -> bytes:
        # Lower bound as well as upper. `q` comes from the ATECC's monotonic
        # counter, and a negative one used to leave through _u32 as an
        # OverflowError -- outside this module's declared LMSError contract,
        # so a caller catching LMSError would not have caught it.
        if q < 0:
            raise OutOfLeaves(f"leaf index {q} is negative")
        if q >= (1 << self.h):
            raise OutOfLeaves(f"leaf {q} is beyond a height-{self.h} tree "
                              f"({1 << self.h} signatures)")
        if q in self._used:
            raise LeafReused(f"leaf {q} already signed; signing twice under one "
                             f"LM-OTS key leaks it")
        self._used.add(q)
        # C randomises the message hash. Derived from the seed and q rather
        # than drawn fresh, so signing is deterministic and a bad RNG cannot
        # weaken it -- the same reasoning as RFC 6979 for ECDSA.
        C = C if C is not None else H(self.seed + self.I + _u32(q) + b"\x01").digest()
        _, p_, _ = _OTS[self.ots_type]
        ots = _ots_sign(_ots_private(self.seed, self.I, q, p_), self.I, q,
                        message, C, self.ots_type)

        path, r = [], (1 << self.h) + q
        while r > 1:
            path.append(self._nodes[r ^ 1])
            r //= 2
        return _u32(q) + ots + _u32(_H_LMS[self.h]) + b"".join(path)


def verify(pub: PublicKey, message: bytes, sig: bytes) -> bool:
    """RFC 8554 Algorithm 6. Returns False rather than raising on any
    malformation, so a hostile signature cannot take the verifier down."""
    try:
        h = pub.h
        if pub.ots_type not in _OTS:
            return False
        _, p_, _ = _OTS[pub.ots_type]
        want = 4 + (4 + N * (p_ + 1)) + 4 + N * h
        if len(sig) != want:
            return False
        q = int.from_bytes(sig[:4], "big")
        if q >= (1 << h):
            return False
        ots = sig[4:4 + 4 + N * (p_ + 1)]
        rest = sig[4 + 4 + N * (p_ + 1):]
        if int.from_bytes(rest[:4], "big") != pub.lms_type:
            return False
        path = [rest[4 + N * i:4 + N * (i + 1)] for i in range(h)]

        kc = _ots_public_from_sig(ots, pub.I, q, message, pub.ots_type)
        node = (1 << h) + q
        tmp = H(pub.I + _u32(node) + _u16(D_LEAF) + kc).digest()
        for i in range(h):
            if node % 2:
                tmp = H(pub.I + _u32(node // 2) + _u16(D_INTR) + path[i] + tmp).digest()
            else:
                tmp = H(pub.I + _u32(node // 2) + _u16(D_INTR) + tmp + path[i]).digest()
            node //= 2
        return tmp == pub.T1
    except (LMSError, IndexError, ValueError):
        return False


def signature_size(h: int, ots_type: int = LMOTS_SHA256_N32_W4) -> int:
    _, p_, _ = _OTS[ots_type]
    return 4 + (4 + N * (p_ + 1)) + 4 + N * h


def years_at(per_day: float, h: int) -> float:
    return (1 << h) / per_day / 365.25
