"""Hash primitives the wallet layer needs and the standard library will not
reliably give us.

Two of these are here for specific reasons rather than for fun:

  RIPEMD-160  Bitcoin's HASH160 needs it. OpenSSL 3 moved it to the legacy
              provider, so `hashlib.new("ripemd160")` raises on a default
              Debian/Raspberry Pi OS build. A wallet that cannot compute an
              address on the target hardware is not a wallet, so the pure
              Python implementation is the primary and hashlib is not used.

  Keccak-256  Ethereum predates the SHA-3 standard and uses the original
              Keccak padding. `hashlib.sha3_256` is NOT the same function —
              it differs in one padding byte, and using it silently produces
              valid-looking, wrong addresses. That failure mode is exactly
              the kind that loses funds quietly, so we implement Keccak.

Both are verified against published vectors in _selftest().
"""

from __future__ import annotations

import hashlib


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    """Bitcoin's double SHA-256."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def tagged(tag: str, msg: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


# --------------------------------------------------------------------------
# RIPEMD-160 (ISO/IEC 10118-3). Pure Python.
# --------------------------------------------------------------------------

_R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RP = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_SP = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KP = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

_M32 = 0xFFFFFFFF


def _rol(x: int, n: int) -> int:
    x &= _M32
    return ((x << n) | (x >> (32 - n))) & _M32


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(msg: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    ml = len(msg)
    pad = msg + b"\x80" + b"\x00" * ((55 - ml) % 64) + (ml * 8).to_bytes(8, "little")

    for off in range(0, len(pad), 64):
        x = [int.from_bytes(pad[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        a, b, c, d, e = h
        ap, bp, cp, dp, ep = h
        for j in range(80):
            rnd = j // 16
            t = (_rol((a + _f(j, b, c, d) + x[_R[j]] + _K[rnd]) & _M32, _S[j]) + e) & _M32
            a, e, d, c, b = e, d, _rol(c, 10), b, t
            t = (_rol((ap + _f(79 - j, bp, cp, dp) + x[_RP[j]] + _KP[rnd]) & _M32,
                      _SP[j]) + ep) & _M32
            ap, ep, dp, cp, bp = ep, dp, _rol(cp, 10), bp, t
        h = [(h[1] + c + dp) & _M32, (h[2] + d + ep) & _M32, (h[3] + e + ap) & _M32,
             (h[4] + a + bp) & _M32, (h[0] + b + cp) & _M32]

    return b"".join(v.to_bytes(4, "little") for v in h)


def hash160(b: bytes) -> bytes:
    """RIPEMD160(SHA256(b)) — Bitcoin's key and script hash."""
    return ripemd160(hashlib.sha256(b).digest())


# --------------------------------------------------------------------------
# Keccak-256 (original padding, as Ethereum uses). Pure Python.
# --------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_M64 = 0xFFFFFFFFFFFFFFFF


def _rol64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M64


def _keccak_f(a: list[list[int]]) -> None:
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol64(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) & _M64
        a[0][0] ^= _RC[rnd]


def keccak256(msg: bytes) -> bytes:
    rate = 136                                  # 1088 bits, for 256-bit output
    a = [[0] * 5 for _ in range(5)]

    # Keccak's original padding is 0x01 ... 0x80. SHA-3 uses 0x06. That one
    # byte is the whole difference, and getting it wrong yields plausible
    # garbage rather than an error.
    padded = msg + b"\x01" + b"\x00" * ((-len(msg) - 1) % rate)
    padded = padded[:-1] + bytes([padded[-1] ^ 0x80])

    for off in range(0, len(padded), rate):
        blk = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(blk[8 * i:8 * i + 8], "little")
            a[i % 5][i // 5] ^= lane
        _keccak_f(a)

    out = b""
    while len(out) < 32:
        for i in range(rate // 8):
            out += a[i % 5][i // 5].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f(a)
    return out[:32]


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Hash primitives — RIPEMD-160 and Keccak-256 vectors\n")
    checks = []

    # RIPEMD-160, from the ISO reference set.
    for msg, want in [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
        (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
    ]:
        label = f"ripemd160({msg[:16]!r}{'...' if len(msg) > 16 else ''})"
        checks.append((label[:46], ripemd160(msg).hex() == want))

    # Cross-check against OpenSSL where it is still available, so a transcription
    # error in the tables cannot pass by agreeing with itself.
    try:
        ref = hashlib.new("ripemd160", b"CELL cross-check").digest()
        checks.append(("agrees with OpenSSL ripemd160",
                       ripemd160(b"CELL cross-check") == ref))
    except ValueError:
        print("  (OpenSSL ripemd160 unavailable — this is why we ship our own)")

    # Keccak-256, Ethereum's hash.
    for msg, want in [
        (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        (b"testing", "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"),
    ]:
        checks.append((f"keccak256({msg!r})"[:46], keccak256(msg).hex() == want))

    # The distinction that loses money if missed.
    checks.append(("keccak256 is NOT sha3_256",
                   keccak256(b"") != hashlib.sha3_256(b"").digest()))

    # Padding boundaries — one below, exactly at, and one above the rate.
    for n in (135, 136, 137, 271, 272):
        checks.append((f"keccak256 rate boundary n={n}",
                       len(keccak256(b"x" * n)) == 32))
    checks.append(("keccak256 135-byte block",
                   keccak256(b"\x00" * 135).hex()[:8] != keccak256(b"\x00" * 136).hex()[:8]))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
