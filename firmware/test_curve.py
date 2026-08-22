#!/usr/bin/env python3
"""The fast scalar multiply against the slow one, and against published keys.

`point_mul` accumulates in Jacobian coordinates so a signature does one field
inversion instead of five hundred. That is a real speedup and a real risk: the
formulas have edge cases the affine group law does not, and a wrong answer
here is a wrong signature or a leaked key rather than a failed assertion. So
the fast path is checked against the readable affine definition — the same
`point_add` the module documents as the group law — over random scalars and
over every case the Jacobian formulas special-case.

    python3 firmware/test_curve.py
"""

from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secp256k1 as ec


def affine_mul(p, k: int):
    """The definition: double-and-add in affine coordinates, no shortcuts.

    This is what `point_mul` was before it was made fast, kept here as the
    thing the fast one has to agree with.
    """
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = ec.point_add(r, p)
        p = ec.point_add(p, p)
    return r


def deterministic_scalars(n: int):
    """Scalars from a fixed seed: varied, but the same set on every run.

    A random test that fails once and passes on re-run tells you nothing.
    """
    out = []
    h = b"cell test_curve"
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        k = int.from_bytes(h, "big") % ec.N
        if k:
            out.append(k)
    return out


def agrees_with_affine() -> bool:
    ok = True
    cases = [
        ("k = 1", 1),
        ("k = 2", 2),
        ("k = 3", 3),
        ("k = 2^128", 1 << 128),
        ("k = 2^255", 1 << 255),
        ("k = N - 1", ec.N - 1),
        ("all bits set below N", (1 << 255) - 1),
    ]
    cases += [(f"random #{i}", k) for i, k in enumerate(deterministic_scalars(12))]

    for name, k in cases:
        fast = ec.point_mul(ec.G, k)
        slow = affine_mul(ec.G, k)
        if fast != slow:
            print(f"    {name}: {fast} != affine {slow}")
            ok = False
            continue
        if not ec.on_curve(fast):
            print(f"    {name}: result is not on the curve")
            ok = False
    print(f"    {len(cases)} scalars agree with the affine definition")
    return ok


def handles_the_special_cases() -> bool:
    """The two branches the Jacobian addition needs and affine does not.

    Accumulating most-significant-bit first means the running total is always
    an even multiple of the base point at the moment an odd one is added, so
    neither branch is reachable with a scalar in [1, N-1]. They are reachable
    just past it, which is exactly where a scalar that skipped `check_scalar`
    would land.
    """
    ok = True

    # acc + p where acc == -p: the sum is infinity. 2 * ((N-1)/2) == N-1 == -1.
    if ec.point_mul(ec.G, ec.N) is not None:
        print("    N * G should be the point at infinity")
        ok = False

    # acc + p where acc == p: the addition has to fall through to a doubling.
    # 2 * ((N+1)/2) == N+1 == 1, so the last add of (N+2) doubles instead.
    if ec.point_mul(ec.G, ec.N + 2) != ec.point_mul(ec.G, 2):
        print("    (N + 2) * G should equal 2 * G")
        ok = False

    if ec.point_mul(ec.G, 0) is not None:
        print("    0 * G should be the point at infinity")
        ok = False

    if ec.point_mul(None, 7) is not None:
        print("    7 * infinity should be the point at infinity")
        ok = False

    print("    infinity, negation and the doubling fallthrough all handled")
    return ok


def matches_known_keys() -> bool:
    """Published secp256k1 vectors, so this is not just self-consistency.

    Two implementations agreeing on a wrong curve is still wrong. These are
    the standard low-multiple points of G.
    """
    known = {
        1: ("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        2: ("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
        3: ("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
        5: ("2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
            "D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6"),
    }
    ok = True
    for k, (x, y) in known.items():
        want = (int(x, 16), int(y, 16))
        if ec.point_mul(ec.G, k) != want:
            print(f"    {k} * G does not match the published point")
            ok = False
    print(f"    {len(known)} published multiples of G match")
    return ok


def signatures_still_verify() -> bool:
    """End to end through the fast path, both signature schemes."""
    ok = True
    seckey = hashlib.sha256(b"cell test_curve key").digest()
    msg = hashlib.sha256(b"a message").digest()

    r, s, _rec = ec.ecdsa_sign(msg, seckey)
    pub = ec.pubkey_compressed(seckey)
    if not ec.ecdsa_verify(msg, pub, r, s):
        print("    ECDSA signature does not verify")
        ok = False
    if ec.ecdsa_verify(bytes(32), pub, r, s):
        print("    ECDSA verified a signature over the wrong message")
        ok = False

    sig = ec.schnorr_sign(msg, seckey)
    xonly = ec.schnorr_pubkey(seckey)
    if not ec.schnorr_verify(msg, xonly, sig):
        print("    Schnorr signature does not verify")
        ok = False
    if ec.schnorr_verify(bytes(32), xonly, sig):
        print("    Schnorr verified a signature over the wrong message")
        ok = False

    print("    ECDSA and Schnorr both sign and verify, and reject a swap")
    return ok


def fixed_base_agrees() -> bool:
    """The precomputed-G path against the general one, and against affine.

    `point_mul_g` is a third implementation of the same operation — a window
    table over a fixed base — and almost every multiply in the module now goes
    through it: public keys, BIP-32 tweaks, nonce points, both halves of ECDSA
    verification. Three implementations that agree are evidence; two that
    agree and one nobody checks is a latent wrong key.
    """
    ok = True
    cases = [("k = 1", 1), ("k = 15", 15), ("k = 16", 16), ("k = 17", 17),
             ("k = 2^128", 1 << 128), ("k = N - 1", ec.N - 1)]
    cases += [(f"random #{i}", k) for i, k in enumerate(deterministic_scalars(12))]

    for name, k in cases:
        table = ec.point_mul_g(k)
        general = ec.point_mul(ec.G, k)
        if table != general:
            print(f"    {name}: table {table} != point_mul {general}")
            ok = False
        elif table != affine_mul(ec.G, k):
            print(f"    {name}: both fast paths disagree with affine")
            ok = False

    # The table path reduces mod N first, so these are its own edge cases.
    if ec.point_mul_g(ec.N) is not None:
        print("    N * G via the table should be infinity")
        ok = False
    if ec.point_mul_g(ec.N + 2) != ec.point_mul_g(2):
        print("    the table should reduce (N + 2) to 2")
        ok = False
    if ec.point_mul_g(0) is not None:
        print("    0 * G via the table should be infinity")
        ok = False

    print(f"    {len(cases)} scalars agree across table, Jacobian and affine")
    return ok


TESTS = [
    ("the fast multiply agrees with the affine definition", agrees_with_affine),
    ("the fixed-base table agrees with both", fixed_base_agrees),
    ("the Jacobian special cases", handles_the_special_cases),
    ("published multiples of G", matches_known_keys),
    ("signatures still verify end to end", signatures_still_verify),
]


def main() -> int:
    failures = []
    for name, fn in TESTS:
        print(f"\n {name}")
        try:
            good = fn()
        except Exception as e:                               # noqa: BLE001
            print(f"    raised {type(e).__name__}: {e}")
            good = False
        if not good:
            failures.append(name)
    print("\n" + "-" * 66)
    if failures:
        print(f"FAIL — {len(failures)} of {len(TESTS)}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
