"""CELL tier attestation — a signed claim about which gate ran.

A signature carries no information about what gated the key. So "this was
signed with blood" has to be a SEPARATE claim, signed by a different key that
the verifier already trusts.

    The device signs the transaction with its SIGNING key.
    The device signs a claim about the transaction with its ATTESTATION key.

The attestation key is generated in the ATECC608B at provisioning and never
changes. You record its public half the way you record an xpub. Co-signers
register each other's attestation keys once; after that, "everyone in this
quorum signed with blood" is a mechanical check.

WHAT THIS PROVES: a device holding this attestation key states that it ran the
blood gate for this exact sighash.

SCOPE: the claim rests on the firmware and the tamper seal, exactly as a TPM
quote or an Apple Secure Enclave receipt does. That is why fw_hash is in the
record and why verify() refuses builds that are not on the accepted list —
co-signers pin firmware alongside keys. The chain does not check any of this;
the quorum does.

THREE THINGS THE RECORD MUST CARRY, and why:

  sighash     Binds the claim to one transaction. Without it, a blood
              attestation can be lifted onto any other signature.
  counter     The device's monotonic counter. Without it, an old blood
              attestation can be replayed for a new transaction.
  fw_hash     Which firmware made the claim. Lets a verifier refuse
              attestations from a build they do not recognise.

NO TIMESTAMP. The device is airgapped and has no battery-backed clock, so it
cannot honestly attest to time. The counter orders events; the coordinator's
own clock does the rest.

PRIVACY: the attestation travels beside the PSBT, in a BIP-174 proprietary
field (prefix "CELL"), and is stripped before broadcast. It must not go on
chain by default — publishing it fingerprints the address as a CELL device and
discloses how it was authorised. Putting it on chain is possible and is a
deliberate choice, not a default.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from policy import Tier

MAGIC = b"CELL"
VERSION = 1
RECORD_LEN = 4 + 1 + 1 + 8 + 32 + 32 + 32 + 32      # 142
SIG_LEN = 64


# --------------------------------------------------------------------------
# BIP-340 Schnorr, reference implementation.
#
# Pure Python, verified against the BIP-340 test vectors in _selftest(). It is
# here so this file can be audited and run standalone. ON DEVICE, USE
# libsecp256k1 — this implementation is not constant-time and must not touch a
# real key outside of tests.
# --------------------------------------------------------------------------

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], _P - 2, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], _P - 2, _P) % _P
    x3 = (lam * lam - p1[0] - p2[0]) % _P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % _P)


def _mul(p, k: int):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = _add(r, p)
        p = _add(p, p)
    return r


def _lift_x(b: bytes):
    x = int.from_bytes(b, "big")
    if x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def _xbytes(p) -> bytes:
    return p[0].to_bytes(32, "big")


def schnorr_pubkey(seckey: bytes) -> bytes:
    d = int.from_bytes(seckey, "big")
    if not 1 <= d <= _N - 1:
        raise ValueError("bad secret key")
    return _xbytes(_mul(_G, d))


def schnorr_sign(msg: bytes, seckey: bytes, aux: bytes = bytes(32)) -> bytes:
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 <= _N - 1:
        raise ValueError("bad secret key")
    P = _mul(_G, d0)
    d = d0 if P[1] % 2 == 0 else _N - d0
    t = d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")
    rand = _tagged("BIP0340/nonce",
                   t.to_bytes(32, "big") + _xbytes(P) + msg)
    k0 = int.from_bytes(rand, "big") % _N
    if k0 == 0:
        raise ValueError("nonce is zero")
    R = _mul(_G, k0)
    k = k0 if R[1] % 2 == 0 else _N - k0
    e = int.from_bytes(_tagged("BIP0340/challenge",
                               _xbytes(R) + _xbytes(P) + msg), "big") % _N
    return _xbytes(R) + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    P = _lift_x(pubkey)
    if P is None:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge",
                              sig[:32] + pubkey + msg), "big") % _N
    R = _add(_mul(_G, s), _mul(P, _N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


# --------------------------------------------------------------------------
# Record
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    tier: Tier
    counter: int
    sighash: bytes          # 32
    fw_hash: bytes          # 32
    cal_hash: bytes         # 32 — SHA-256 of the active threshold set
    attest_pub: bytes       # 32, x-only
    signature: bytes = b""  # 64

    def body(self) -> bytes:
        if any(len(f) != 32 for f in
               (self.sighash, self.fw_hash, self.cal_hash, self.attest_pub)):
            raise ValueError("hash and key fields must be 32 bytes")
        return (MAGIC + bytes([VERSION, int(self.tier)])
                + self.counter.to_bytes(8, "big")
                + self.sighash + self.fw_hash + self.cal_hash + self.attest_pub)

    def digest(self) -> bytes:
        return _tagged("CELL/attest-v1", self.body())

    def pack(self) -> bytes:
        return self.body() + self.signature

    @staticmethod
    def unpack(blob: bytes) -> "Attestation":
        if len(blob) != RECORD_LEN + SIG_LEN:
            raise ValueError(f"expected {RECORD_LEN + SIG_LEN} bytes, got {len(blob)}")
        if blob[:4] != MAGIC or blob[4] != VERSION:
            raise ValueError("not a CELL v1 attestation")
        # A tier byte outside the enum is a malformed record, not a crash. The
        # verifier must be able to reject anything a co-signer hands it without
        # taking the process down — an unparseable attestation is exactly what
        # a hostile counterparty would send.
        try:
            tier = Tier(blob[5])
        except ValueError:
            raise ValueError(f"unknown tier byte {blob[5]}") from None
        return Attestation(
            tier=tier,
            counter=int.from_bytes(blob[6:14], "big"),
            sighash=blob[14:46], fw_hash=blob[46:78], cal_hash=blob[78:110],
            attest_pub=blob[110:142], signature=blob[142:],
        )


def attest(tier: Tier, counter: int, sighash: bytes, fw_hash: bytes,
           cal_hash: bytes, sign: Callable[[bytes], bytes],
           attest_pub: bytes) -> Attestation:
    """Device side. `sign` is the ATECC608B/SE signing callable — the raw key
    never appears here."""
    a = Attestation(tier, counter, sighash, fw_hash, cal_hash, attest_pub)
    return Attestation(tier, counter, sighash, fw_hash, cal_hash, attest_pub,
                       sign(a.digest()))


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


@dataclass
class Verdict:
    ok: bool
    reason: str

    def __str__(self) -> str:
        return f"[{'OK  ' if self.ok else 'FAIL'}] {self.reason}"


def verify_blob(blob: bytes, expect_pub: bytes, expect_sighash: bytes,
                **kw) -> "Verdict":
    """Parse and verify in one step, converting any malformed record into a
    Verdict rather than an exception.

    Use this at every trust boundary — anything arriving from a co-signer, a
    QR scan or a PSBT field. `verify()` assumes an already-parsed record.
    """
    try:
        a = Attestation.unpack(blob)
    except ValueError as e:
        return Verdict(False, f"malformed attestation: {e}")
    return verify(a, expect_pub, expect_sighash, **kw)


def verify(a: Attestation, expect_pub: bytes, expect_sighash: bytes,
           min_counter: int = -1,
           allowed_fw: Optional[Iterable[bytes]] = None,
           require: Tier = Tier.BLOOD,
           allowed_cal: Optional[Iterable[bytes]] = None) -> Verdict:
    """Verifier side. Every check is a separate named failure, deliberately —
    "attestation invalid" tells a co-signer nothing actionable."""
    if a.attest_pub != expect_pub:
        return Verdict(False, "attestation key is not the registered one for this signer")
    if a.sighash != expect_sighash:
        return Verdict(False, "attestation is bound to a different transaction")
    if not schnorr_verify(a.digest(), a.attest_pub, a.signature):
        return Verdict(False, "signature does not verify")
    if a.counter <= min_counter:
        return Verdict(False, f"counter {a.counter} not above last seen {min_counter} — replay")
    if allowed_fw is not None and a.fw_hash not in set(allowed_fw):
        return Verdict(False, "firmware hash is not on the accepted list")
    # Checked separately from firmware, and named separately, because the
    # remedy differs: an unknown firmware means do not trust this device, an
    # unknown calibration means ask which thresholds it is running.
    if allowed_cal is not None and a.cal_hash not in set(allowed_cal):
        return Verdict(False, "calibration hash is not on the accepted list")
    if a.tier < require:
        return Verdict(False, f"signed at {a.tier.name}, {require.name} was required")
    return Verdict(True, f"{a.tier.name}, counter {a.counter}")


def verify_quorum(attestations: dict[str, Attestation],
                  roster: dict[str, bytes],
                  sighash: bytes,
                  last_counters: Optional[dict[str, int]] = None,
                  allowed_fw: Optional[Iterable[bytes]] = None,
                  require: Tier = Tier.BLOOD,
                  allowed_cal: Optional[Iterable[bytes]] = None
                  ) -> tuple[bool, dict[str, Verdict]]:
    """"Everyone in this quorum signed with blood."

    `roster` is the registered attestation pubkey per signer, recorded once at
    setup. A missing attestation is a failure, not an abstention — otherwise
    the claim degrades silently to "everyone who bothered signed with blood".
    """
    last = last_counters or {}
    out: dict[str, Verdict] = {}
    for name, pub in roster.items():
        a = attestations.get(name)
        if a is None:
            out[name] = Verdict(False, "no attestation provided")
            continue
        out[name] = verify(a, pub, sighash, last.get(name, -1), allowed_fw,
                           require, allowed_cal)
    return all(v.ok for v in out.values()), out


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _selftest() -> int:
    ok = True

    # BIP-340 vector 0 — proves the Schnorr implementation, not just that it
    # round-trips with itself.
    sk = bytes.fromhex("00" * 31 + "03")
    want_pk = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    want_sig = bytes.fromhex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    pk = schnorr_pubkey(sk)
    sig = schnorr_sign(bytes(32), sk, bytes(32))
    for label, got, want in (("pubkey", pk, want_pk), ("signature", sig, want_sig)):
        good = got == want
        ok &= good
        print(f"  BIP-340 {label:<10}{'matches test vector' if good else 'MISMATCH'}")
    ok &= schnorr_verify(bytes(32), want_pk, want_sig)

    # Attestation round trip
    fw = hashlib.sha256(b"firmware-v1").digest()
    cal = hashlib.sha256(b"thresholds-A").digest()
    other_cal = hashlib.sha256(b"thresholds-B").digest()
    sh = hashlib.sha256(b"tx-A").digest()
    other = hashlib.sha256(b"tx-B").digest()
    signer = lambda m: schnorr_sign(m, sk)
    a = attest(Tier.BLOOD, 42, sh, fw, cal, signer, pk)
    good = Attestation.unpack(a.pack()) == a and len(a.pack()) == RECORD_LEN + SIG_LEN
    ok &= good
    print(f"\n  record        {len(a.pack())} bytes, round-trips{'' if good else '  MISMATCH'}")

    print("\n  Verification cases:")
    cases = [
        ("valid blood",        verify(a, pk, sh, 41, [fw]),                        True),
        ("wrong transaction",  verify(a, pk, other, 41, [fw]),                     False),
        ("replayed counter",   verify(a, pk, sh, 42, [fw]),                        False),
        ("unknown firmware",   verify(a, pk, sh, 41, [bytes(32)]),                 False),
        ("wrong signer key",   verify(a, bytes(32), sh, 41, [fw]),                 False),
        ("unknown calibration", verify(a, pk, sh, 41, [fw],
                                       allowed_cal=[other_cal]),                   False),
        ("registered calibration", verify(a, pk, sh, 41, [fw],
                                          allowed_cal=[cal]),                      True),
    ]
    tampered = Attestation(Tier.BLOOD, 42, sh, fw, cal, pk, bytes(64))
    cases.append(("forged signature", verify(tampered, pk, sh, 41, [fw]), False))
    touch = attest(Tier.TOUCH, 43, sh, fw, cal, signer, pk)
    cases.append(("touch when blood required", verify(touch, pk, sh, 42, [fw]), False))
    cases.append(("touch when touch allowed",
                  verify(touch, pk, sh, 42, [fw], require=Tier.TOUCH), True))
    for label, v, want in cases:
        good = v.ok == want
        ok &= good
        print(f"    {label:<28}{v}{'' if good else '   <-- UNEXPECTED'}")

    # Malformed records must come back as a Verdict, never as an exception.
    # A verifier that crashes on hostile input is a denial of service on the
    # co-signing flow.
    print("\n  Malformed input (must reject, never raise):")
    blob = a.pack()
    bad = [
        ("truncated",        blob[:-1]),
        ("empty",            b""),
        ("wrong magic",      b"XXXX" + blob[4:]),
        ("wrong version",    blob[:4] + bytes([99]) + blob[5:]),
        ("unknown tier",     blob[:5] + bytes([7]) + blob[6:]),
        ("all zeroes",       bytes(len(blob))),
    ]
    for label, b in bad:
        try:
            v = verify_blob(b, pk, sh, min_counter=41, allowed_fw=[fw])
            good = not v.ok
        except Exception as e:                      # noqa: BLE001
            v, good = f"RAISED {type(e).__name__}: {e}", False
        ok &= good
        print(f"    {label:<28}{v}{'' if good else '   <-- UNEXPECTED'}")
    good = verify_blob(blob, pk, sh, min_counter=41, allowed_fw=[fw]).ok
    ok &= good
    print(f"    well-formed still verifies  {'PASS' if good else 'FAIL'}")

    # Quorum: "everyone in this multisig signed with blood"
    print("\n  Quorum — all three must be BLOOD:")
    keys = {n: bytes.fromhex(f"{i+7:064x}") for i, n in enumerate(("alice", "bob", "carol"))}
    roster = {n: schnorr_pubkey(k) for n, k in keys.items()}
    atts = {n: attest(Tier.BLOOD, 1, sh, fw, cal,
                      lambda m, k=k: schnorr_sign(m, k), roster[n])
            for n, k in keys.items()}
    passed, det = verify_quorum(atts, roster, sh, allowed_fw=[fw])
    ok &= passed
    print(f"    all blood                   {'PASS' if passed else 'FAIL'}")

    atts["bob"] = attest(Tier.TOUCH, 1, sh, fw, cal,
                         lambda m: schnorr_sign(m, keys["bob"]), roster["bob"])
    passed, det = verify_quorum(atts, roster, sh, allowed_fw=[fw])
    ok &= not passed
    print(f"    bob used touch              {'correctly rejected' if not passed else 'FAIL'}"
          f"  ({det['bob'].reason})")

    del atts["carol"]
    passed, det = verify_quorum(atts, roster, sh, allowed_fw=[fw])
    ok &= not passed
    print(f"    carol did not attest        {'correctly rejected' if not passed else 'FAIL'}"
          f"  ({det['carol'].reason})")

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    print("CELL attestation self-test\n")
    raise SystemExit(_selftest())
