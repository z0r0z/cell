#!/usr/bin/env python3
"""The unlinkable attestation: what it proves, and what it must never leak.

Four families, and they are not equally strong claims.

CORRECTNESS is testable and tested exhaustively: every member of a ring can
sign, and every one of those signatures verifies.

BINDING is testable. A signature must not survive being moved to a different
ring, a different claim, a different event, or a different tier, and must not
survive any single byte being changed. Each is attempted here.

LINKABILITY is testable and is the property that makes this usable for
one-human-one-action. Two claims from one device in one event carry the same
key image; two claims from one device in DIFFERENT events do not. The second
half is the one people get wrong, and it is the difference between a system
that resists sybils and one that publishes a voting history.

ANONYMITY IS NOT TESTABLE HERE, and pretending otherwise would be the worst
thing in this file. That a ring signature hides its signer is a theorem about
the construction, not something a unit test establishes. What is asserted
below is the structural part a test can reach: the signature is the same shape
whoever signed it, and nothing in it varies with the signer's position in a
way this code can find. The rest rests on LSAG being what Liu, Wei and Wong
proved it is.
"""

from __future__ import annotations

import sys

import ring
import secp256k1 as ec
from ring import BadRing, Claim

KEYS = [bytes([0] * 31 + [i + 1]) for i in range(12)]
PUBS = [ec.ser_xonly(ec.point_mul_g(ec.seckey_int(k))) for k in KEYS]
OUTSIDER = bytes([0] * 31 + [99])

CLAIM = Claim(tier=2, action_digest=b"\x11" * 32, event=b"allowlist-round-1")


def _report(checks) -> bool:
    ok = True
    for label, good in checks:
        ok &= bool(good)
        print(f"  {label:<56}{'PASS' if good else 'FAIL'}")
    return ok


def _raises(fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
    except BadRing:
        return True
    except Exception:                                       # noqa: BLE001
        return False
    return False


def correctness() -> bool:
    checks = []
    for n in (2, 3, 5, 8):
        ring_n = PUBS[:n]
        all_ok = True
        for i in range(n):
            key = next(k for k in KEYS[:n]
                       if ec.ser_xonly(ec.point_mul_g(ec.seckey_int(k)))
                       == ring.canonical(ring_n)[i])
            all_ok &= ring.verify(CLAIM, ring.sign(CLAIM, ring_n, key))
        checks.append((f"every member of a ring of {n} can sign, and does "
                       f"verify", all_ok))
    sig = ring.sign(CLAIM, PUBS[:8], KEYS[3])
    checks += [
        ("the ring travels with the signature", len(sig.ring) == 8),
        ("one scalar per member", len(sig.s) == 8),
        ("the key image is a compressed point", len(sig.key_image) == 33),
        ("an outsider cannot sign",
         _raises(ring.sign, CLAIM, PUBS[:8], OUTSIDER)),
    ]
    return _report(checks)


def binding() -> bool:
    ring8 = PUBS[:8]
    sig = ring.sign(CLAIM, ring8, KEYS[3])
    members = list(sig.ring)

    import dataclasses as dc

    def altered(**kw):
        return not ring.verify(CLAIM, dc.replace(sig, **kw))

    swapped = list(members)
    swapped[0] = PUBS[9]
    grown = tuple(ring.canonical(members + [PUBS[10]]))
    shrunk = tuple(members[1:])
    reordered = tuple(reversed(members))

    bad_s = list(sig.s)
    bad_s[5] = (bad_s[5] + 1) % ring.N
    bad_image = bytes([sig.key_image[0]]) + bytes(
        [sig.key_image[1] ^ 1]) + sig.key_image[2:]

    return _report([
        ("a signature does not survive a swapped ring member",
         altered(ring=tuple(ring.canonical(swapped)))),
        ("...nor a member added", altered(ring=grown)),
        ("...nor a member removed", altered(ring=shrunk)),
        ("...nor the ring being reordered", altered(ring=reordered)),
        ("...nor c0 changed", altered(c0=(sig.c0 + 1) % ring.N)),
        ("...nor any single scalar changed", altered(s=tuple(bad_s))),
        ("...nor the key image changed", altered(key_image=bad_image)),
        ("a claim at another tier does not verify",
         not ring.verify(dc.replace(CLAIM, tier=1), sig)),
        ("a claim over another action does not verify",
         not ring.verify(dc.replace(CLAIM, action_digest=b"\x22" * 32), sig)),
        ("a claim in another event does not verify",
         not ring.verify(dc.replace(CLAIM, event=b"round-2"), sig)),
    ])


def linkability() -> bool:
    ring8 = PUBS[:8]
    import dataclasses as dc
    a = ring.sign(CLAIM, ring8, KEYS[3])
    b = ring.sign(CLAIM, ring8, KEYS[3])          # same device, same event
    c = ring.sign(CLAIM, ring8, KEYS[6])          # different device
    other_event = dc.replace(CLAIM, event=b"allowlist-round-2")
    d = ring.sign(other_event, ring8, KEYS[3])    # same device, next event
    # A different ACTION inside the same event is still the same device voting
    # in that event, so it must still link. This is what stops one device
    # splitting its vote across two proposals in one round.
    other_action = dc.replace(CLAIM, action_digest=b"\x33" * 32)
    e = ring.sign(other_action, ring8, KEYS[3])
    return _report([
        ("one device, one event: two claims link", ring.links(a, b)),
        ("two devices in one event do not link", not ring.links(a, c)),
        ("one device across two events does not link", not ring.links(a, d)),
        ("...and that claim still verifies", ring.verify(other_event, d)),
        ("one device, one event, two actions: still links", ring.links(a, e)),
        ("the image does not depend on the nonce",
         ring.sign(CLAIM, ring8, KEYS[3], aux=b"").key_image == a.key_image),
        # The attack a reviewer asks about: sign as yourself, but present
        # somebody else's image, to vote twice or to frame them. The
        # verification equation only closes for the image the signer's own
        # key produces, so this is refused rather than merely discouraged.
        ("a signer cannot present another device's image",
         not ring.verify(CLAIM, dc.replace(a, key_image=c.key_image))),
    ])


def the_nonce() -> bool:
    """A repeated u leaks the key. This checks the hedge, not the theorem."""
    ring8 = PUBS[:8]
    det1 = ring.sign(CLAIM, ring8, KEYS[2], aux=b"")
    det2 = ring.sign(CLAIM, ring8, KEYS[2], aux=b"")
    hedged1 = ring.sign(CLAIM, ring8, KEYS[2])
    hedged2 = ring.sign(CLAIM, ring8, KEYS[2])
    import dataclasses as dc
    other = ring.sign(dc.replace(CLAIM, action_digest=b"\x44" * 32),
                      ring8, KEYS[2], aux=b"")
    return _report([
        ("the deterministic form repeats exactly", det1.s == det2.s),
        ("the hedged form does not", hedged1.s != hedged2.s),
        ("both verify", ring.verify(CLAIM, det1) and ring.verify(CLAIM, hedged1)
         and ring.verify(CLAIM, hedged2)),
        ("a different message gives different scalars", other.s != det1.s),
    ])


def malformed() -> bool:
    ring8 = PUBS[:8]
    sig = ring.sign(CLAIM, ring8, KEYS[1])
    import dataclasses as dc
    off_curve = b"\xff" * 32
    return _report([
        ("a ring of one is refused", _raises(ring.canonical, [PUBS[0]])),
        ("a ring of zero is refused", _raises(ring.canonical, [])),
        ("a duplicated member is refused",
         _raises(ring.canonical, [PUBS[0], PUBS[1], PUBS[0]])),
        ("a member that is not on the curve is refused",
         _raises(ring.canonical, [PUBS[0], off_curve])),
        ("a short key is refused", _raises(ring.canonical, [PUBS[0], b"\x01"])),
        ("a claim with no event is refused",
         _raises(dc.replace(CLAIM, event=b"").check)),
        ("a claim at an unknown tier is refused",
         _raises(dc.replace(CLAIM, tier=7).check)),
        ("a short action digest is refused",
         _raises(dc.replace(CLAIM, action_digest=b"\x00").check)),
        ("too few scalars is refused",
         not ring.verify(CLAIM, dc.replace(sig, s=sig.s[:-1]))),
        ("an out-of-range scalar is refused",
         not ring.verify(CLAIM, dc.replace(sig, s=(ring.N,) + sig.s[1:]))),
        ("a key image of the wrong length is refused",
         not ring.verify(CLAIM, dc.replace(sig, key_image=b"\x02" * 32))),
        ("a key image that is not a point is refused",
         not ring.verify(CLAIM, dc.replace(sig, key_image=b"\x02" + b"\xff" * 32))),
    ])


def anonymity_shape() -> bool:
    """The structural half. The rest is the construction, not this file."""
    ring8 = list(ring.canonical(PUBS[:8]))
    sigs = []
    for member in ring8:
        key = next(k for k in KEYS[:8]
                   if ec.ser_xonly(ec.point_mul_g(ec.seckey_int(k))) == member)
        sigs.append(ring.sign(CLAIM, ring8, key, aux=b""))
    sizes = {(len(s.s), len(s.key_image)) for s in sigs}
    # If any component gave the position away, the signer's own scalar would
    # be findable. Check the obvious tells: it is not the smallest, not the
    # largest, and not at a fixed offset.
    positions = []
    for idx, s in enumerate(sigs):
        order = sorted(range(8), key=lambda i: s.s[i])
        positions.append(order.index(idx))
    return _report([
        ("every signature is the same shape", len(sizes) == 1),
        ("all eight verify", all(ring.verify(CLAIM, s) for s in sigs)),
        ("every signer produces a distinct key image",
         len({s.key_image for s in sigs}) == 8),
        ("the signer's scalar is not the smallest", set(positions) != {0}),
        ("nor at any fixed rank", len(set(positions)) > 1),
        ("the ring is identical in all of them",
         len({s.ring for s in sigs}) == 1),
    ])


def cost() -> bool:
    print(f"  {'ring':>6}{'sign s':>10}{'verify s':>11}")
    for n, t_sign, t_verify in ring.bench((4, 8, 16, 32)):
        print(f"  {n:>6}{t_sign:>10.3f}{t_verify:>11.3f}")
    print("  A Pi Zero 2 W is roughly 15-25x slower than this machine, and a")
    print("  blood capture takes 600 s, so the ring computes while it clots.")
    return True


def main() -> int:
    print("Unlinkable attestation: one of these devices bled\n")
    print("Correctness:")
    a = correctness()
    print("\nWhat the signature is bound to:")
    b = binding()
    print("\nLinkability, and the half people get wrong:")
    c = linkability()
    print("\nThe nonce:")
    d = the_nonce()
    print("\nMalformed input:")
    e = malformed()
    print("\nAnonymity, the structural half only:")
    f = anonymity_shape()
    print("\nCost:")
    g = cost()
    ok = all([a, b, c, d, e, f, g])
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
