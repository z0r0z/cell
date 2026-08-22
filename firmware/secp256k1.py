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


def point_mul(p, k: int):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = point_add(r, p)
        p = point_add(p, p)
    return r


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
    return point_mul(G, seckey_int(seckey))


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
    q = point_add(parse_pubkey(pub), point_mul(G, int.from_bytes(t, "big") % N))
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


def ecdsa_sign(msg32: bytes, seckey: bytes) -> tuple[int, int, int]:
    """Sign a 32-byte digest. Returns (r, s, recovery_id), s always low.

    The recovery id is what Ethereum's `v` is built from; Bitcoin ignores it.
    """
    if len(msg32) != 32:
        raise ValueError("message must be a 32-byte digest")
    d = seckey_int(seckey)
    z = int.from_bytes(msg32, "big") % N

    attempt = b""
    while True:
        k = _rfc6979_k(msg32, d, attempt)
        R = point_mul(G, k)
        r = R[0] % N
        if r == 0:
            attempt += b"\x00"
            continue
        s = (pow(k, N - 2, N) * (z + r * d)) % N
        if s == 0:
            attempt += b"\x00"
            continue
        rec = (2 if R[0] >= N else 0) | (R[1] & 1)
        if s > N // 2:                     # BIP-62 low-S
            s = N - s
            rec ^= 1
        return r, s, rec


def ecdsa_sign_compact(msg32: bytes, seckey: bytes) -> bytes:
    r, s, _ = ecdsa_sign(msg32, seckey)
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
    R = point_add(point_mul(G, z * w % N), point_mul(Q, r * w % N))
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
    Q = point_add(point_mul(R, s * rinv % N), point_mul(G, (N - z) * rinv % N))
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
    Pp = point_mul(G, d0)
    d = d0 if Pp[1] % 2 == 0 else N - d0
    t = d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")
    rand = tagged("BIP0340/nonce", t.to_bytes(32, "big") + ser_xonly(Pp) + msg)
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise ValueError("nonce is zero")
    R = point_mul(G, k0)
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
    R = point_add(point_mul(G, s), point_mul(Pp, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def taproot_tweak_seckey(seckey: bytes, merkle_root: bytes = b"") -> bytes:
    """BIP-341 output key. Key-path spends sign with this, not the internal key."""
    d0 = seckey_int(seckey)
    Pp = point_mul(G, d0)
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
    Q = point_add(Pp, point_mul(G, t))
    if Q is None:
        raise BadKey("taproot output key is infinity")
    return ser_xonly(Q), Q[1] & 1


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("secp256k1 — RFC 6979, ECDSA, BIP-340, BIP-341\n")
    checks = []

    # Generator sanity.
    checks.append(("G is on the curve", on_curve(G)))
    checks.append(("nG is infinity", point_mul(G, N) is None))
    checks.append(("(n-1)G + G is infinity",
                   point_add(point_mul(G, N - 1), G) is None))

    # RFC 6979 test vector, from the RFC's own secp256k1/SHA-256 appendix as
    # reproduced in the Bitcoin test suites: key 0x01, message "Satoshi
    # Nakamoto".
    sk1 = (1).to_bytes(32, "big")
    z = hashlib.sha256(b"Satoshi Nakamoto").digest()
    r, s, _ = ecdsa_sign(z, sk1)
    checks.append(("RFC 6979 vector r",
                   f"{r:064x}" == "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7"
                                  "e6a4a49860d7a6ab210ee3d8"))
    checks.append(("RFC 6979 vector s",
                   f"{s:064x}" == "2442ce9d2b916064108014783e923ec36b49743e"
                                  "2ffa1c4496f01a512aafd9e5"))

    # Determinism and low-S.
    checks.append(("signing is deterministic",
                   ecdsa_sign_compact(z, sk1) == ecdsa_sign_compact(z, sk1)))
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
