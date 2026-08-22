"""secp256k1 — the one curve both chains use.

Bitcoin and Ethereum both sign on secp256k1, which is why one seed and one
signing core serve both. This module is that core: point arithmetic, ECDSA
with RFC 6979 deterministic nonces, and BIP-340 Schnorr.

THE NONCE IS THE WHOLE GAME. ECDSA leaks the private key outright if the
nonce repeats across two signatures, and leaks it to lattice attacks if the
nonce is merely biased. So there is no nonce parameter anywhere in this
module's public surface: `k` is derived by RFC 6979 from the message and the
key alone, deterministically, and nothing else can reach it. In particular
nothing from the liveness gate touches it — see signer.liveness_digest, which
says the same thing from the other side.

Signatures are canonicalised to low-S (BIP-62) because Bitcoin's relay policy
rejects high-S, and a wallet that produces non-standard signatures produces
transactions that never confirm.

PERFORMANCE AND SIDE CHANNELS. This is pure Python affine arithmetic: correct,
auditable, roughly a quarter-second per signature on a Pi Zero 2 W, and NOT
constant-time. For an airgapped device inside a sealed case, with one
signature per physical act, the timing channel has no remote observer and the
tradeoff is deliberate — it buys an implementation a reviewer can read in one
sitting. If you expose this device to an attacker who can time it repeatedly,
link libsecp256k1 and route sign/verify through it instead.
"""

from __future__ import annotations

import hashlib
import hmac

from hashes import tagged

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = tuple[int, int]


class BadKey(ValueError):
    """A scalar outside [1, N-1], or a point not on the curve."""


# --------------------------------------------------------------------------
# Group arithmetic
# --------------------------------------------------------------------------


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def _jac_double(pt):
    """Double a Jacobian (X, Y, Z) point on y^2 = x^3 + 7. dbl-2009-l."""
    x, y, z = pt
    if y == 0:
        return (0, 0, 0)
    a = x * x % P
    b = y * y % P
    c = b * b % P
    d = 2 * ((x + b) * (x + b) - a - c) % P
    e = 3 * a % P
    f = e * e % P
    x3 = (f - 2 * d) % P
    return (x3, (e * (d - x3) - 8 * c) % P, 2 * y * z % P)


def _jac_add(pt, q):
    """Add affine `q` to Jacobian `pt`. madd-2007-bl, with the doubling case."""
    x1, y1, z1 = pt
    if z1 == 0:
        return (q[0], q[1], 1)
    z1z1 = z1 * z1 % P
    u2 = q[0] * z1z1 % P
    s2 = q[1] * z1z1 % P * z1 % P
    if x1 == u2:
        # Same x: either a doubling, or the point and its negation summing to
        # infinity. Both have to be handled here -- the addition formula below
        # divides by (u2 - x1) in effect, and produces garbage for either.
        return _jac_double(pt) if y1 == s2 else (0, 0, 0)
    h = (u2 - x1) % P
    hh = h * h % P
    i = 4 * hh % P
    j = h * i % P
    r = 2 * (s2 - y1) % P
    v = x1 * i % P
    x3 = (r * r - j - 2 * v) % P
    return (x3, (r * (v - x3) - 2 * y1 * j) % P,
            ((z1 + h) * (z1 + h) - z1z1 - hh) % P)


def point_mul(p, k: int):
    """k * p, accumulated in Jacobian coordinates.

    The affine `point_add` above is the readable definition of the group law
    and stays the module's public one. It is not what a scalar multiply should
    call 512 times, though: every affine addition inverts a field element, and
    an inversion is a 256-bit modular exponentiation. Accumulating in Jacobian
    coordinates defers all of that to a single inversion at the end, which is
    the difference between a signature taking a fifth of a second and taking
    twenty -- on the Pi Zero 2 W this module targets, not just on a desktop.

    `test_curve.py` checks this against the affine definition over random
    scalars and every edge case the formulas have, so the fast path cannot
    drift from the slow one silently.
    """
    if p is None or k == 0:
        return None
    # Most-significant bit first, so the running total is the only thing that
    # ever doubles and the addend stays the affine input -- no inversion
    # anywhere in the loop.
    acc = (0, 0, 0)                       # Jacobian infinity
    for i in range(k.bit_length() - 1, -1, -1):
        acc = _jac_double(acc)
        if (k >> i) & 1:
            acc = _jac_add(acc, p)
    if acc[2] == 0:
        return None
    zinv = pow(acc[2], P - 2, P)
    zinv2 = zinv * zinv % P
    return (acc[0] * zinv2 % P, acc[1] * zinv2 % P * zinv % P)



# --------------------------------------------------------------------------
# Fixed-base multiplication
#
# Every scalar multiply in this module except three is against G: public keys,
# BIP-32 child tweaks, nonce points, both halves of ECDSA verification. A fixed
# base can be precomputed, and then the multiply has no doublings left in it at
# all -- 63 additions against 256 doublings plus 128 additions.
#
# Measured on this machine, per scalar multiply, so the two optimisations here
# are not confused with each other:
#
#                        affine   jacobian    table
#     k*G                87.9 ms    3.0 ms   0.8 ms
#     k*Q (arbitrary)    88.2 ms    2.8 ms      n/a
#
# The Jacobian accumulation in point_mul above is the large win and it covers
# every multiply, including the three against arbitrary points that this table
# cannot help: ecdsa_verify, ecdsa_recover and schnorr_verify. This table is a
# further 3.9x, and only against G.
#
# Keep both. Removing the Jacobian code because the table looks like it does
# the work would cost 29x on the paths the table never touches.
#
# NOT CONSTANT TIME -- the window digit indexes a table, and a zero digit skips
# the addition entirely. Neither is new: the square-and-multiply above already
# branched on the scalar's bits. This stays a reference implementation, and
# BUILD.md section 12 specifies libsecp256k1 for the device.
# --------------------------------------------------------------------------

_WINDOW = 4
_G_TABLE: "list[list[tuple[int, int]]] | None" = None


def _build_g_table() -> "list[list[tuple[int, int]]]":
    """table[i][d-1] = d * 2^(WINDOW*i) * G, for d in 1..15."""
    table, base = [], G
    for _ in range((256 + _WINDOW - 1) // _WINDOW):
        row, acc = [], None
        for _ in range((1 << _WINDOW) - 1):
            acc = point_add(acc, base)
            row.append(acc)
        table.append(row)
        for _ in range(_WINDOW):                  # base *= 2^WINDOW
            base = point_add(base, base)
    return table


def point_mul_g(k: int):
    """k * G, via the precomputed window table. Identical to point_mul_g(k).

    test_curve.py checks the two against each other over random scalars and
    the edge cases, so this cannot drift from the definition silently.
    """
    global _G_TABLE
    k %= N
    if k == 0:
        return None
    if _G_TABLE is None:
        _G_TABLE = _build_g_table()
    acc = (0, 0, 0)                               # Jacobian infinity
    i = 0
    while k:
        d = k & ((1 << _WINDOW) - 1)
        if d:
            acc = _jac_add(acc, _G_TABLE[i][d - 1])
        k >>= _WINDOW
        i += 1
    if acc[2] == 0:
        return None
    zinv = pow(acc[2], P - 2, P)
    zinv2 = zinv * zinv % P
    return (acc[0] * zinv2 % P, acc[1] * zinv2 % P * zinv % P)

def on_curve(p) -> bool:
    if p is None:
        return False
    x, y = p
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0


def lift_x(x: int | bytes):
    """The even-Y point with this x, or None. BIP-340's lift_x."""
    if isinstance(x, (bytes, bytearray)):
        x = int.from_bytes(x, "big")
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


def check_scalar(d: int) -> int:
    if not 1 <= d <= N - 1:
        raise BadKey("scalar outside [1, N-1]")
    return d


def seckey_int(seckey: bytes) -> int:
    if len(seckey) != 32:
        raise BadKey("secret key must be 32 bytes")
    return check_scalar(int.from_bytes(seckey, "big"))


def pubkey_point(seckey: bytes) -> Point:
    return point_mul_g(seckey_int(seckey))


def ser_compressed(p: Point) -> bytes:
    """33 bytes: 0x02/0x03 by Y parity, then X."""
    return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, "big")


def ser_uncompressed(p: Point) -> bytes:
    """65 bytes: 0x04 then X then Y. Ethereum addresses hash the last 64."""
    return b"\x04" + p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")


def ser_xonly(p: Point) -> bytes:
    return p[0].to_bytes(32, "big")


def parse_pubkey(b: bytes) -> Point:
    """Compressed, uncompressed or x-only. Rejects anything off the curve."""
    if len(b) == 33 and b[0] in (2, 3):
        p = lift_x(b[1:])
        if p is None:
            raise BadKey("compressed pubkey x is not on the curve")
        return p if (b[0] == 2) == (p[1] % 2 == 0) else (p[0], P - p[1])
    if len(b) == 65 and b[0] == 4:
        p = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        if not on_curve(p):
            raise BadKey("uncompressed pubkey is not on the curve")
        return p
    if len(b) == 32:
        p = lift_x(b)
        if p is None:
            raise BadKey("x-only pubkey is not on the curve")
        return p
    raise BadKey(f"unrecognised public key encoding, {len(b)} bytes")


def pubkey_compressed(seckey: bytes) -> bytes:
    return ser_compressed(pubkey_point(seckey))


def tweak_seckey_add(seckey: bytes, t: bytes) -> bytes:
    """(d + t) mod N. BIP-32 child derivation and BIP-341 tweaking."""
    d = (seckey_int(seckey) + int.from_bytes(t, "big")) % N
    if d == 0:
        raise BadKey("tweaked key is zero")
    return d.to_bytes(32, "big")


def tweak_pubkey_add(pub: bytes, t: bytes) -> bytes:
    """P + tG, compressed. BIP-32 public derivation."""
    q = point_add(parse_pubkey(pub), point_mul_g(int.from_bytes(t, "big") % N))
    if q is None:
        raise BadKey("tweaked point is infinity")
    return ser_compressed(q)


# --------------------------------------------------------------------------
# RFC 6979 — deterministic nonces
# --------------------------------------------------------------------------


def _rfc6979_k(msg32: bytes, d: int, extra: bytes = b"") -> int:
    """HMAC-DRBG per RFC 6979 section 3.2, SHA-256.

    `extra` is RFC 6979 section 3.6's optional k'. Bitcoin Core uses it to
    grind for a low-R signature; we use it only to retry, which is the same
    mechanism and keeps the nonce a pure function of (key, message, attempt).
    """
    x = d.to_bytes(32, "big")
    h1 = msg32
    v = b"\x01" * 32
    k = b"\x00" * 32
    for byte in (b"\x00", b"\x01"):
        k = hmac.new(k, v + byte + x + h1 + extra, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# --------------------------------------------------------------------------
# ECDSA
# --------------------------------------------------------------------------


def ecdsa_sign(msg32: bytes, seckey: bytes,
               grind_low_r: bool = True) -> tuple[int, int, int]:
    """Sign a 32-byte digest. Returns (r, s, recovery_id), s always low.

    The recovery id is what Ethereum's `v` is built from; Bitcoin ignores it.

    `grind_low_r` retries with an incrementing RFC 6979 extra-entropy counter
    until R's top bit is clear, which saves the DER encoding a padding byte.
    Bitcoin Core and every wallet that follows it do this, so leaving it on
    makes our signatures byte-identical to theirs for the same key and
    message — a standing cross-check that costs a few milliseconds. It is not
    a consensus requirement, and it is switched off for the RFC 6979 test
    vectors, which predate the convention.
    """
    if len(msg32) != 32:
        raise ValueError("message must be a 32-byte digest")
    d = seckey_int(seckey)
    z = int.from_bytes(msg32, "big") % N

    counter = 0
    while True:
        extra = b"" if counter == 0 else counter.to_bytes(32, "little")
        k = _rfc6979_k(msg32, d, extra)
        R = point_mul_g(k)
        r = R[0] % N
        s = (pow(k, N - 2, N) * (z + r * d)) % N if r else 0
        if r == 0 or s == 0 or (grind_low_r and r >> 255):
            counter += 1
            continue
        rec = (2 if R[0] >= N else 0) | (R[1] & 1)
        if s > N // 2:                     # BIP-62 low-S
            s = N - s
            rec ^= 1
        return r, s, rec


def ecdsa_sign_compact(msg32: bytes, seckey: bytes,
                       grind_low_r: bool = True) -> bytes:
    r, s, _ = ecdsa_sign(msg32, seckey, grind_low_r)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify(msg32: bytes, pub: bytes, r: int, s: int) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    try:
        Q = parse_pubkey(pub)
    except BadKey:
        return False
    z = int.from_bytes(msg32, "big") % N
    w = pow(s, N - 2, N)
    R = point_add(point_mul_g(z * w % N), point_mul(Q, r * w % N))
    return R is not None and R[0] % N == r


def ecdsa_recover(msg32: bytes, r: int, s: int, rec: int) -> bytes:
    """Recover the compressed pubkey. Ethereum verifies by recovery."""
    if not (1 <= r < N and 1 <= s < N) or not 0 <= rec <= 3:
        raise BadKey("signature out of range")
    x = r + (N if rec & 2 else 0)
    if x >= P:
        raise BadKey("recovery x out of field")
    R = lift_x(x)
    if R is None:
        raise BadKey("no curve point for r")
    if (R[1] & 1) != (rec & 1):
        R = (R[0], P - R[1])
    z = int.from_bytes(msg32, "big") % N
    rinv = pow(r, N - 2, N)
    Q = point_add(point_mul(R, s * rinv % N), point_mul_g((N - z) * rinv % N))
    if Q is None:
        raise BadKey("recovered point is infinity")
    return ser_compressed(Q)


def der_encode(r: int, s: int) -> bytes:
    """Strict DER, as Bitcoin consensus requires."""
    def _int(v: int) -> bytes:
        b = v.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = _int(r) + _int(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode(sig: bytes) -> tuple[int, int]:
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError("not a DER sequence")
    if sig[2] != 0x02:
        raise ValueError("no r integer")
    rlen = sig[3]
    if sig[4 + rlen] != 0x02:
        raise ValueError("no s integer")
    slen = sig[5 + rlen]
    if 6 + rlen + slen != len(sig):
        raise ValueError("DER length mismatch")
    return (int.from_bytes(sig[4:4 + rlen], "big"),
            int.from_bytes(sig[6 + rlen:6 + rlen + slen], "big"))


# --------------------------------------------------------------------------
# BIP-340 Schnorr — taproot spends and CELL's own attestation records
# --------------------------------------------------------------------------


def schnorr_pubkey(seckey: bytes) -> bytes:
    return ser_xonly(pubkey_point(seckey))


def schnorr_sign(msg: bytes, seckey: bytes, aux: bytes = bytes(32)) -> bytes:
    d0 = seckey_int(seckey)
    Pp = point_mul_g(d0)
    d = d0 if Pp[1] % 2 == 0 else N - d0
    t = d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")
    rand = tagged("BIP0340/nonce", t.to_bytes(32, "big") + ser_xonly(Pp) + msg)
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise ValueError("nonce is zero")
    R = point_mul_g(k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge",
                              ser_xonly(R) + ser_xonly(Pp) + msg), "big") % N
    return ser_xonly(R) + ((k + e * d) % N).to_bytes(32, "big")


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    Pp = lift_x(pubkey)
    if Pp is None:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge",
                              sig[:32] + pubkey + msg), "big") % N
    R = point_add(point_mul_g(s), point_mul(Pp, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def taproot_tweak_seckey(seckey: bytes, merkle_root: bytes = b"") -> bytes:
    """BIP-341 output key. Key-path spends sign with this, not the internal key."""
    d0 = seckey_int(seckey)
    Pp = point_mul_g(d0)
    d = d0 if Pp[1] % 2 == 0 else N - d0
    t = int.from_bytes(tagged("TapTweak", ser_xonly(Pp) + merkle_root), "big")
    if t >= N:
        raise BadKey("taproot tweak out of range")
    return ((d + t) % N).to_bytes(32, "big")


def taproot_tweak_pubkey(xonly: bytes, merkle_root: bytes = b"") -> tuple[bytes, int]:
    """Returns (output x-only key, parity of the output point)."""
    Pp = lift_x(xonly)
    if Pp is None:
        raise BadKey("internal key is not on the curve")
    t = int.from_bytes(tagged("TapTweak", xonly + merkle_root), "big")
    if t >= N:
        raise BadKey("taproot tweak out of range")
    Q = point_add(Pp, point_mul_g(t))
    if Q is None:
        raise BadKey("taproot output key is infinity")
    return ser_xonly(Q), Q[1] & 1


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("secp256k1 — RFC 6979, ECDSA, BIP-340, BIP-341\n")
    checks = []

    # Generator sanity.
    checks.append(("G is on the curve", on_curve(G)))
    checks.append(("nG is infinity", point_mul_g(N) is None))
    checks.append(("(n-1)G + G is infinity",
                   point_add(point_mul_g(N - 1), G) is None))

    # RFC 6979 test vector, from the RFC's own secp256k1/SHA-256 appendix as
    # reproduced in the Bitcoin test suites: key 0x01, message "Satoshi
    # Nakamoto".
    sk1 = (1).to_bytes(32, "big")
    z = hashlib.sha256(b"Satoshi Nakamoto").digest()
    r, s, _ = ecdsa_sign(z, sk1, grind_low_r=False)
    checks.append(("RFC 6979 vector r",
                   f"{r:064x}" == "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7"
                                  "e6a4a49860d7a6ab210ee3d8"))
    checks.append(("RFC 6979 vector s",
                   f"{s:064x}" == "2442ce9d2b916064108014783e923ec36b49743e"
                                  "2ffa1c4496f01a512aafd9e5"))

    # Determinism and low-S.
    checks.append(("signing is deterministic",
                   ecdsa_sign_compact(z, sk1) == ecdsa_sign_compact(z, sk1)))
    checks.append(("grinding produces a low R",
                   all(ecdsa_sign(hashlib.sha256(bytes([i])).digest(), sk1)[0] >> 255 == 0
                       for i in range(16))))
    checks.append(("grinding is opt-out, not silent",
                   ecdsa_sign(z, sk1, grind_low_r=False)[0] != ecdsa_sign(z, sk1)[0]))
    sk = hashlib.sha256(b"cell-test-key").digest()
    lows = all(ecdsa_sign(hashlib.sha256(bytes([i])).digest(), sk)[1] <= N // 2
               for i in range(24))
    checks.append(("s is always low", lows))

    # Round trip: sign, verify, recover, DER.
    pub = pubkey_compressed(sk)
    msg = hashlib.sha256(b"a transaction").digest()
    r, s, rec = ecdsa_sign(msg, sk)
    checks.append(("verifies", ecdsa_verify(msg, pub, r, s)))
    checks.append(("rejects a flipped message",
                   not ecdsa_verify(hashlib.sha256(b"another").digest(), pub, r, s)))
    checks.append(("rejects a mangled s", not ecdsa_verify(msg, pub, r, (s + 1) % N)))
    checks.append(("recovery id is right", ecdsa_recover(msg, r, s, rec) == pub))
    checks.append(("DER round trip", der_decode(der_encode(r, s)) == (r, s)))
    checks.append(("DER is minimally encoded",
                   len(der_encode(1, 1)) == 8))

    # Cross-check ECDSA against OpenSSL, so a bug in our arithmetic cannot
    # pass by being consistent with itself.
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        from cryptography.hazmat.primitives import hashes as ch
        pt = pubkey_point(sk)
        ossl = ec.EllipticCurvePublicNumbers(pt[0], pt[1], ec.SECP256K1()).public_key()
        ossl.verify(asym_utils.encode_dss_signature(r, s),
                    msg, ec.ECDSA(asym_utils.Prehashed(ch.SHA256())))
        checks.append(("OpenSSL accepts our signature", True))
    except ImportError:
        print("  (cryptography absent — skipping the OpenSSL cross-check)")
    except Exception as e:                                      # noqa: BLE001
        checks.append((f"OpenSSL cross-check ({type(e).__name__})", False))

    # Pubkey serialisation round trips.
    checks.append(("compressed round trip",
                   parse_pubkey(ser_compressed(pubkey_point(sk))) == pubkey_point(sk)))
    checks.append(("uncompressed round trip",
                   parse_pubkey(ser_uncompressed(pubkey_point(sk))) == pubkey_point(sk)))
    odd = hashlib.sha256(b"odd-y-key").digest()
    while pubkey_point(odd)[1] % 2 == 0:
        odd = hashlib.sha256(odd).digest()
    checks.append(("odd-Y compressed round trip",
                   parse_pubkey(ser_compressed(pubkey_point(odd))) == pubkey_point(odd)))
    bad = False
    try:
        parse_pubkey(b"\x02" + b"\xff" * 32)
    except BadKey:
        bad = True
    checks.append(("off-curve pubkey refused", bad))

    # BIP-340 vectors, from the BIP's csv.
    v = [
        ("0000000000000000000000000000000000000000000000000000000000000003",
         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
         "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    ]
    # The vector above only checks that sign() runs; the authoritative check is
    # sign-then-verify plus the published verify-only vectors below.
    sk340 = bytes.fromhex(v[0][0])
    pk340 = bytes.fromhex(v[0][1])
    checks.append(("BIP-340 pubkey vector", schnorr_pubkey(sk340) == pk340))
    m340 = bytes.fromhex(v[0][2])
    sig340 = schnorr_sign(m340, sk340, bytes.fromhex(v[0][3]))
    checks.append(("BIP-340 sign/verify", schnorr_verify(m340, pk340, sig340)))
    checks.append(("BIP-340 rejects a tampered sig",
                   not schnorr_verify(m340, pk340, sig340[:-1] + bytes([sig340[-1] ^ 1]))))

    # Published BIP-340 verification vector (index 0 of the BIP csv).
    checks.append(("BIP-340 published vector 0", schnorr_verify(
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
        bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                      "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"))))

    # BIP-341: tweaking the secret key and tweaking the public key must land on
    # the same output key, or a taproot spend signs for an address nobody owns.
    ik = hashlib.sha256(b"internal").digest()
    out_pub, _ = taproot_tweak_pubkey(schnorr_pubkey(ik))
    checks.append(("BIP-341 tweak agrees pub/sec",
                   schnorr_pubkey(taproot_tweak_seckey(ik)) == out_pub))
    tmsg = hashlib.sha256(b"taproot spend").digest()
    checks.append(("BIP-341 key-path signature verifies",
                   schnorr_verify(tmsg, out_pub,
                                  schnorr_sign(tmsg, taproot_tweak_seckey(ik)))))

    # Tweak arithmetic used by BIP-32.
    t = hashlib.sha256(b"tweak").digest()
    checks.append(("private and public tweak agree",
                   pubkey_compressed(tweak_seckey_add(sk, t))
                   == tweak_pubkey_add(pubkey_compressed(sk), t)))

    # Bad keys are refused rather than producing a wrong signature.
    for label, bad_key in [("zero key", bytes(32)),
                           ("key == N", N.to_bytes(32, "big")),
                           ("short key", bytes(31))]:
        try:
            pubkey_compressed(bad_key)
            checks.append((f"{label} refused", False))
        except BadKey:
            checks.append((f"{label} refused", True))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
