#!/usr/bin/env python3
"""Unlinkable attestation: one of these devices bled, and you cannot tell which.

WHAT PROBLEM THIS SOLVES. The ordinary attestation in attest.py carries
`attest_pub`, so publishing one says "this address is a CELL device and this
action was authorised with blood". README calls that a leak and strips the
record before broadcast, which is right for a treasury and throws away the
part of this design with the widest reach.

Because the interesting claim is not "device 7 bled". It is "a human bled",
and that is a rate limit denominated in something an attacker cannot buy more
of: a script can produce a million signatures, a body produces about two a
day, and each costs a lancet and ten minutes. Allowlists, mints, quorum votes
and one-human-one-action all want exactly that, and none of them want to know
which device.

So: a ring signature over the registered attestation keys. It proves that ONE
member of a named set produced this claim, and says nothing about which.

    LSAG, over the same secp256k1 the rest of the device signs on. Liu, Wei
    and Wong (2004), which is the construction Monero's ring signatures came
    from and about as well studied as this gets.

LINKABLE, AND ONLY WITHIN ONE EVENT. A ring signature alone would let one
device vote a thousand times. The key image fixes that:

    I = d * H_p(event || P)

Two claims from the same device in the same event carry the same image and
are refused as a double vote. Two claims in DIFFERENT events carry unrelated
images, because the event tag is inside the hash-to-point, so nothing links a
device's votes across rounds. That distinction is the whole design: a key
image that omitted the event would make every claim a device ever made
linkable to every other, which is a worse leak than the one this file exists
to remove.

WHAT THE CLAIM DELIBERATELY DOES NOT CARRY. The ordinary record commits to
`fw_hash` and `cal_hash` so a co-signer can refuse builds they do not
recognise. Those fields are exactly what would deanonymise this one: a
firmware hash shared by three of forty devices narrows the ring to three. They
are absent here, and what replaces them is the ring itself. A verifier admits
a set of keys, and the keys it admits are the ones whose firmware it already
checked at registration.

COST, AND WHY IT IS AFFORDABLE HERE. Signing and verifying are both about 2n
scalar multiplications for a ring of n. That is slow in pure Python on a Pi
Zero, and it does not matter: the blood gate takes ten minutes, and the ring
can be computed while the sample clots. See `bench()` for measured numbers.

NOT FOR ON-CHAIN VERIFICATION YET. 2n multiplications is not a precompile.
Use this off chain, or in an allowlist a coordinator maintains. A contract
that wants it needs a different construction than this file.

THE NONCE. A repeated `u` leaks the signing key outright, which is a sharper
edge than ECDSA's. So it is not drawn from the RNG alone: it is derived from
the key and the message, hedged with fresh randomness, in the manner BIP-340
hedges `aux_rand`. Pass `aux=b""` for the deterministic form the test vectors
use.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

import secp256k1 as ec

N = ec.N


class BadRing(ValueError):
    """A ring, a claim, or a signature this code will not produce or accept."""


def _tagged(tag: str, msg: bytes) -> bytes:
    """BIP-340's tagged hash. Domain separation, cheaply."""
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _hash_to_point(event: bytes, pub: bytes) -> "tuple[int, int]":
    """A curve point nobody knows the discrete log of, per (event, key).

    Try-and-increment. Not constant time, and it does not need to be: every
    input is public, and the branch it takes depends on nothing secret.
    """
    for ctr in range(256):
        h = _tagged("CELL/ring-h2c-v1", event + pub + bytes([ctr]))
        # lift_x returns None for an x that is not on the curve. About half
        # of all x values are not, so the loop is expected to run once or
        # twice and effectively never more.
        point = ec.lift_x(h)
        if point is not None:
            return point
    raise BadRing("no point found for this key")            # pragma: no cover


def _challenge(msg: bytes, left, right) -> int:
    return int.from_bytes(
        _tagged("CELL/ring-c-v1",
                msg + ec.ser_compressed(left) + ec.ser_compressed(right)),
        "big") % N


def canonical(ring: "list[bytes] | tuple[bytes, ...]") -> "tuple[bytes, ...]":
    """The ring as everyone must see it: x-only keys, sorted, no duplicates.

    Sorted because the challenge chain walks the ring in order, so two parties
    holding the same SET in different orders would compute different
    signatures over the same claim and neither could verify the other's.
    """
    out = []
    for k in ring:
        if not isinstance(k, (bytes, bytearray)) or len(k) != 32:
            raise BadRing("a ring member is a 32-byte x-only public key")
        if ec.lift_x(bytes(k)) is None:
            raise BadRing(
                f"ring member {bytes(k).hex()[:16]}... is not a point on the "
                f"curve, so nothing could ever sign as it")
        out.append(bytes(k))
    if len(set(out)) != len(out):
        raise BadRing("the ring holds the same key twice, which is not a ring")
    if len(out) < 2:
        raise BadRing(
            "a ring of one proves nothing and names the signer. Two is the "
            "smallest set that hides anybody.")
    return tuple(sorted(out))


@dataclass(frozen=True)
class Claim:
    """What is being asserted, without saying by whom.

    `tier` and `action_digest` are the whole of it. See the module docstring
    for why the firmware and calibration hashes are deliberately absent.
    """

    tier: int
    action_digest: bytes                # 32
    event: bytes                        # the round, ballot or allowlist id

    def check(self) -> None:
        if self.tier not in (1, 2):
            raise BadRing(f"tier {self.tier} is not a tier this device runs")
        if len(self.action_digest) != 32:
            raise BadRing("an action digest is 32 bytes")
        if not self.event or len(self.event) > 64:
            raise BadRing("an event tag is 1 to 64 bytes, and is required")

    def message(self, ring: "tuple[bytes, ...]") -> bytes:
        """What the ring signs. Commits to the claim AND to the ring itself.

        Without the ring in the message, a signature could be lifted onto a
        smaller ring, and a ring of two names the signer half the time.
        """
        self.check()
        return _tagged("CELL/ring-msg-v1",
                       bytes([self.tier]) + self.action_digest
                       + len(self.event).to_bytes(1, "big") + self.event
                       + len(ring).to_bytes(2, "big") + b"".join(ring))


@dataclass(frozen=True)
class RingSignature:
    ring: "tuple[bytes, ...]"
    key_image: bytes                    # 33, compressed
    c0: int
    s: "tuple[int, ...]"

    def check(self) -> None:
        if len(self.s) != len(self.ring):
            raise BadRing("one scalar per ring member, and no more")
        if not 0 < self.c0 < N:
            raise BadRing("c0 out of range")
        for v in self.s:
            if not 0 <= v < N:
                raise BadRing("a scalar is out of range")
        if len(self.key_image) != 33:
            raise BadRing("a key image is a compressed point")


def sign(claim: Claim, ring: "list[bytes]", seckey: bytes,
         aux: "bytes | None" = None) -> RingSignature:
    """Sign as whichever ring member `seckey` corresponds to.

    The secret is the BIP-340 form: the attestation key as `attest.py` holds
    it, normalised so its public point has even Y.
    """
    members = canonical(ring)
    d = ec.seckey_int(seckey)
    pub = ec.ser_xonly(ec.point_mul_g(d))
    # BIP-340 normalisation: the key that signs is the one whose point has
    # even Y, so a secret whose point does not is negated. Do the same here or
    # the point derived below is not the ring member anybody registered.
    if ec.point_mul_g(d)[1] % 2:                            # pragma: no cover
        d = N - d
        pub = ec.ser_xonly(ec.point_mul_g(d))
    if pub not in members:
        raise BadRing(
            "this key is not in the ring. Signing would produce something "
            "that verifies against nothing.")
    pi = members.index(pub)
    n = len(members)

    msg = claim.message(members)
    hp = _hash_to_point(claim.event, pub)
    image = ec.point_mul(hp, d)
    image_b = ec.ser_compressed(image)

    # Hedged, deterministic. A repeated u leaks d outright, so this does not
    # depend on the RNG being healthy -- but it still mixes it in, so a
    # predictable message cannot make two signatures identical either.
    if aux is None:
        aux = os.urandom(32)
    stream = _tagged("CELL/ring-nonce-v1", seckey + msg + image_b + aux)

    def scalar(i: int) -> int:
        return int.from_bytes(
            _tagged("CELL/ring-nonce-v1", stream + i.to_bytes(2, "big")),
            "big") % N

    u = scalar(0) or 1
    s = [0] * n
    c = [0] * n

    left = ec.point_mul_g(u)
    right = ec.point_mul(hp, u)
    c[(pi + 1) % n] = _challenge(msg, left, right)

    i = (pi + 1) % n
    while i != pi:
        s[i] = scalar(i + 1) or 1
        p_i = ec.lift_x(members[i])
        hp_i = _hash_to_point(claim.event, members[i])
        left = ec.point_add(ec.point_mul_g(s[i]), ec.point_mul(p_i, c[i]))
        right = ec.point_add(ec.point_mul(hp_i, s[i]),
                             ec.point_mul(image, c[i]))
        c[(i + 1) % n] = _challenge(msg, left, right)
        i = (i + 1) % n

    s[pi] = (u - c[pi] * d) % N
    return RingSignature(ring=members, key_image=image_b, c0=c[0],
                         s=tuple(s))


def verify(claim: Claim, sig: RingSignature) -> bool:
    """Does one member of this ring stand behind this claim."""
    try:
        sig.check()
        members = canonical(list(sig.ring))
        if members != tuple(sig.ring):
            return False                # a ring out of canonical order
        image = ec.parse_pubkey(sig.key_image)
        if image is None or not ec.on_curve(image):
            return False
        msg = claim.message(members)
    except (BadRing, ec.BadKey, ValueError):
        return False

    c = sig.c0
    for i, member in enumerate(members):
        p_i = ec.lift_x(member)
        if p_i is None:                                     # pragma: no cover
            return False
        try:
            hp_i = _hash_to_point(claim.event, member)
        except BadRing:                                     # pragma: no cover
            return False
        left = ec.point_add(ec.point_mul_g(sig.s[i]), ec.point_mul(p_i, c))
        right = ec.point_add(ec.point_mul(hp_i, sig.s[i]),
                             ec.point_mul(image, c))
        c = _challenge(msg, left, right)
    return c == sig.c0


def links(a: RingSignature, b: RingSignature) -> bool:
    """Same device, same event. The double-vote test a verifier runs.

    Across two DIFFERENT events this is always false, whoever signed, because
    the event tag is inside the hash-to-point. That is the property that keeps
    a device's votes from being joined up across rounds.
    """
    return a.key_image == b.key_image


def bench(sizes=(4, 8, 16, 32)) -> "list[tuple[int, float, float]]":
    """Measured cost, so the claim about affordability is a number."""
    import time
    out = []
    keys = [bytes([0] * 31 + [i + 1]) for i in range(max(sizes))]
    pubs = [ec.ser_xonly(ec.point_mul_g(ec.seckey_int(k))) for k in keys]
    claim = Claim(tier=2, action_digest=b"\x11" * 32, event=b"round-1")
    for n in sizes:
        ring = pubs[:n]
        t0 = time.perf_counter()
        sig = sign(claim, ring, keys[0], aux=b"")
        t1 = time.perf_counter()
        assert verify(claim, sig)
        t2 = time.perf_counter()
        out.append((n, t1 - t0, t2 - t1))
    return out


def _selftest() -> int:                                     # pragma: no cover
    import test_ring
    return test_ring.main()


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(_selftest())
