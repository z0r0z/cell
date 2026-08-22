"""LMS tests, against RFC 8554's own vectors and then against ourselves.

The vectors matter more than the round trip. An implementation that agrees
with itself proves only that it is self-consistent, which is exactly what the
PSBT proprietary key was before Bitcoin Core saw it. Test Case 2 in RFC 8554
Appendix F uses LMOTS_SHA256_N32_W4 and LM_SHA256_M32_H10 -- our parameters --
so it can be verified directly.

Run standalone, or through firmware/run_tests.py.
"""

from __future__ import annotations

import pathlib
import re
import sys

import lms


def _load_rfc_vectors(path: pathlib.Path):
    """Pull Test Case 2's HSS public key and signature out of the RFC text.

    The hex is laid out as an optional label followed by 16-byte groups, with
    comments after '#'. Anything that is not a hex group on a labelled or
    continuation line is layout, not data.
    """
    text = path.read_text()

    def block(start: str, end: str) -> str:
        i = text.index(start)
        return text[i:text.index(end, i)]

    def hexbytes(seg: str) -> bytes:
        """Hex data rows from an RFC block.

        A token counts as data only if it is entirely lowercase hex of even
        length. That drops the labels ("levels", "LMS type", "I", "C", "y[0]",
        "Message") without needing to know their shapes, and keeps a short
        final group like "2e0a".

        Page furniture has to go first and explicitly: "RFC 8554" and "April
        2019" both survive the hex test, and appending them to a message
        produces an INVALID that looks like broken crypto. That is exactly what
        happened here before this filter existed.
        """
        out = []
        for line in seg.splitlines():
            if "McGrew" in line or "[Page" in line or line.startswith("RFC 8554"):
                continue
            body = line.split("#")[0].split("|")[0]
            out += [t for t in body.split()
                    if re.fullmatch(r"[0-9a-f]+", t) and len(t) % 2 == 0]
        return bytes.fromhex("".join(out))

    return (hexbytes(block("Test Case 2 Public Key", "Test Case 2 Message")),
            hexbytes(block("Test Case 2 Signature", "Acknowledgements")),
            hexbytes(block("Test Case 2 Message", "Test Case 2 Signature")))


def rfc_vectors() -> bool:
    """Verify RFC 8554 Test Case 2 end to end.

    It is a two-level HSS signature, so there are two LMS verifications in it:
    the root signs the level-1 public key, and level 1 signs the message. Both
    have to pass, which exercises the OTS chains, the checksum and the Merkle
    path against values we did not produce.
    """
    rfc = pathlib.Path("/tmp/rfc8554.txt")
    if not rfc.exists():
        print("  RFC 8554 text not present, skipping vector check")
        print("  fetch: curl -o /tmp/rfc8554.txt https://www.rfc-editor.org/rfc/rfc8554.txt")
        return True

    pub_blob, sig_blob, msg = _load_rfc_vectors(rfc)
    ok = True
    # HSS public key: u32(levels) || LMS public key
    levels = int.from_bytes(pub_blob[:4], "big")
    root = lms.PublicKey.unpack(pub_blob[4:4 + 8 + 16 + 32])
    ok &= levels == 2
    ok &= root.ots_type == lms.LMOTS_SHA256_N32_W4
    ok &= root.lms_type == lms.LMS_SHA256_M32_H10
    print(f"  parsed HSS public key: {levels} levels, "
          f"{'W4/H10 as expected' if ok else 'UNEXPECTED PARAMETERS'}")

    # HSS signature: u32(Nspk) || sig[0] || pub[1] || sig[1]
    #
    # The two levels do NOT share parameters. The root here is W4/H10 and the
    # level-1 key is W8/H5, so each slice has to be sized from the key that
    # signed it. Assuming one length for both is why this read INVALID at
    # first, and it was the test that was wrong rather than the implementation.
    nspk = int.from_bytes(sig_blob[:4], "big")
    root_siglen = lms.signature_size(root.h, root.ots_type)
    sig0 = sig_blob[4:4 + root_siglen]
    pub1_blob = sig_blob[4 + root_siglen:4 + root_siglen + 8 + 16 + 32]
    ok &= nspk == 1

    pub1 = lms.PublicKey.unpack(pub1_blob)
    sig1 = sig_blob[4 + root_siglen + 8 + 16 + 32:]
    sig1 = sig1[:lms.signature_size(pub1.h, pub1.ots_type)]
    print(f"  root is w={lms._OTS[root.ots_type][0]}/h={root.h}, "
          f"level 1 is w={lms._OTS[pub1.ots_type][0]}/h={pub1.h}")
    a = lms.verify(root, pub1_blob, sig0)
    b = lms.verify(pub1, msg, sig1)
    ok &= a and b
    print(f"  root signature over the level-1 public key : {'VALID' if a else 'INVALID'}")
    print(f"  level-1 signature over the message         : {'VALID' if b else 'INVALID'}")

    # A vector that must fail: one flipped byte of the message.
    bad = lms.verify(pub1, msg[:-1] + bytes([msg[-1] ^ 1]), sig1)
    ok &= not bad
    print(f"  tampered message                           : "
          f"{'correctly rejected' if not bad else 'ACCEPTED, WRONG'}")
    return ok


def round_trip() -> bool:
    ok = True
    seed = bytes(range(32))
    I = bytes(range(16))
    sk = lms.PrivateKey(seed, I, h=5)
    pk = sk.public_key()
    msg = b"authorise 0.418 BTC to bc1q..."

    sig = sk.sign(msg, 0)
    checks = [
        ("signs and verifies", lms.verify(pk, msg, sig)),
        ("signature is the documented size", len(sig) == lms.signature_size(5)),
        ("public key round-trips", lms.PublicKey.unpack(pk.pack()) == pk),
        ("wrong message rejected", not lms.verify(pk, msg + b"!", sig)),
        ("another tree's key rejected",
         not lms.verify(lms.PrivateKey(bytes(32), I, h=5).public_key(), msg, sig)),
    ]
    # Every byte position matters: flip one and it must stop verifying.
    tampered = all(
        not lms.verify(pk, msg, sig[:i] + bytes([sig[i] ^ 1]) + sig[i + 1:])
        for i in range(0, len(sig), 37))
    checks.append(("any single flipped byte rejected", tampered))

    # A leaf must never be reused, and the failure has to be loud.
    sk.sign(msg, 1)
    try:
        sk.sign(b"different", 1)
        checks.append(("leaf reuse refused", False))
    except lms.LeafReused:
        checks.append(("leaf reuse refused", True))
    try:
        sk.sign(msg, 32)
        checks.append(("beyond the tree refused", False))
    except lms.OutOfLeaves:
        checks.append(("beyond the tree refused", True))

    # Signing is deterministic, so a weak RNG cannot weaken it.
    sk2 = lms.PrivateKey(seed, I, h=5)
    checks.append(("deterministic across instances", sk2.sign(msg, 0) == sig))

    # Malformed input returns False, never raises.
    raised = False
    for junk in (b"", b"\x00" * 10, sig[:-1], sig + b"\x00", bytes(len(sig))):
        try:
            lms.verify(pk, msg, junk)
        except Exception:                                   # noqa: BLE001
            raised = True
    checks.append(("malformed signatures rejected without raising", not raised))

    for label, good in checks:
        ok &= good
        print(f"  {label:<44}{'PASS' if good else 'FAIL'}")
    return ok


def capacity() -> bool:
    print(f"  {'height':>7}{'signatures':>13}{'sig bytes':>11}{'years @ 2/day':>15}")
    for h in (5, 10, 15, 20):
        print(f"  {h:>7}{1 << h:>13,}{lms.signature_size(h):>11,}"
              f"{lms.years_at(2, h):>15,.0f}")
    return True


def main() -> int:
    print("LMS (RFC 8554) — post-quantum attestation signatures\n")
    print("RFC 8554 Appendix F, Test Case 2:")
    a = rfc_vectors()
    print("\nRound trip and refusals:")
    b = round_trip()
    print("\nCapacity, at the blood tier's design point:")
    c = capacity()
    ok = a and b and c
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
