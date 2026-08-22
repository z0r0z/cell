#!/usr/bin/env python3
"""Do our signatures actually satisfy the scripts they are meant to?

Everything else in this repo checks that we compute what the specifications
say. That is necessary and it is not the same question. A signature can match
a published sighash vector exactly and still fail on the network, because what
a node does is not compare digests — it runs the script, and the script has
opinions about DER encoding, about the S value, about a dummy element on the
stack that nobody reads.

So this file hands our output to a script interpreter written by somebody
else, under the consensus flags a node applies, and asks whether the script
succeeds. The interpreter comes from `python-bitcoinlib`, which is not a
dependency of this firmware — it is a second opinion, and a second opinion
that shared our code would not be one.

WHAT IT COVERS. Legacy script evaluation: p2pkh, and bare m-of-n multisig,
which is the same code path a p2wsh witness script is evaluated through. That
covers OP_CHECKSIG and OP_CHECKMULTISIG against our DER encodings, our
sighash byte, and the NULLDUMMY rule. It does NOT cover low-S: the library
declares that flag without implementing it, so low-S stays asserted where it
is actually enforceable, in `secp256k1.py`.

WHAT IT DOES NOT COVER. Witness execution. This interpreter predates segwit
and has no witness support, so v0 and taproot spends cannot be run through it.
Those rest on the published BIP-143 and BIP-341 vectors in `tx.py`, and on the
byte-for-byte agreement with `embit` recorded in VALIDATION.md. A node is
still the only thing that settles it, and only a real transaction does that.
"""

from __future__ import annotations

import sys

import addresses
import bip32
import bip39
import secp256k1 as ec
import tx as ourtx

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon " \
           "abandon abandon abandon abandon about"
DEST = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

FAILURES: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


def _interpreter():
    """The second opinion, or None if it is not installed."""
    try:
        from bitcoin.core import CTransaction, CScript
        from bitcoin.core.scripteval import (VerifyScript,
                                             SCRIPT_VERIFY_FLAGS_BY_NAME)
    except ImportError:
        return None
    # The flags a node applies to a standard transaction today. LOW_S and
    # DERSIG are the two most likely to catch a home-made signer, and
    # CLEANSTACK catches a script_sig that leaves rubbish behind.
    flags = tuple(SCRIPT_VERIFY_FLAGS_BY_NAME[n] for n in
                  ("P2SH", "DERSIG", "LOW_S", "STRICTENC", "NULLDUMMY",
                   "CLEANSTACK", "MINIMALDATA"))
    return CTransaction, CScript, VerifyScript, flags


def _spend_of(script_pubkey: bytes, amount: int = 100_000):
    """A funding transaction and the spend of it, unsigned."""
    parent = ourtx.Transaction(
        2, [ourtx.TxIn(b"\x11" * 32, 0)], [ourtx.TxOut(amount, script_pubkey)], 0)
    spend = ourtx.Transaction(
        2, [ourtx.TxIn(parent.txid(), 0)],
        [ourtx.TxOut(amount - 10_000, addresses.address_to_script(DEST))], 0)
    return parent, spend


def main() -> int:
    print("Consensus — does an independent interpreter accept our signatures?\n")
    parts = _interpreter()
    if parts is None:
        print("  python-bitcoinlib is not installed — nothing to compare against.")
        print("  This suite is a second opinion, not a requirement:")
        print("      pip install python-bitcoinlib")
        print("\nSKIP")
        return 0
    CTransaction, CScript, VerifyScript, flags = parts

    def runs(script_sig: bytes, script_pubkey: bytes, spend) -> bool:
        spend.vin[0].script_sig = script_sig
        txTo = CTransaction.deserialize(spend.serialize())
        try:
            VerifyScript(CScript(script_sig), CScript(script_pubkey), txTo, 0, flags)
            return True
        except Exception:                                       # noqa: BLE001
            return False

    def push(b: bytes) -> bytes:
        if len(b) >= 0x4C:
            raise AssertionError("test pushes are all short")
        return bytes([len(b)]) + b

    root = bip32.from_mnemonic(MNEMONIC)

    # ---- p2pkh, the whole path: sighash, sign, encode, execute ----------
    print(" pay-to-pubkey-hash")
    key = root.derive("m/44h/0h/0h/0/0")
    spk = addresses.p2pkh_script(key.pubkey)
    _, spend = _spend_of(spk)
    digest = spend.sighash_legacy(0, spk)
    r, s, _ = ec.ecdsa_sign(digest, key.seckey)
    sig = ec.der_encode(r, s) + bytes([ourtx.SIGHASH_ALL])

    check("the script runs and the signature satisfies it",
          runs(push(sig) + push(key.pubkey), spk, spend))

    # Each of these is a rule a home-made signer gets wrong quietly.
    #
    # LOW_S is the exception, and worth stating rather than glossing: this
    # interpreter declares the flag and does not implement it, so it accepts a
    # high-S signature that a node's relay policy would drop. Asserting a
    # rejection here would be testing the library, not us. What we can assert
    # is that our signer never produces one — secp256k1.py checks that across
    # a run of signatures, and this checks it on the signature actually being
    # executed.
    check("our signature is low-S, whatever this interpreter enforces",
          s <= ec.N // 2)
    high_s = ec.der_encode(r, ec.N - s) + bytes([ourtx.SIGHASH_ALL])
    check("...and the high-S form is a different encoding entirely",
          high_s != sig and len(high_s) >= len(sig))

    mangled = bytearray(sig)
    mangled[10] ^= 0x01
    check("a mangled signature is rejected",
          not runs(push(bytes(mangled)) + push(key.pubkey), spk, spend))

    wrong_flag = ec.der_encode(r, s) + b"\x02"                 # SIGHASH_NONE byte
    check("the same signature under a different sighash byte is rejected",
          not runs(push(wrong_flag) + push(key.pubkey), spk, spend))

    other = root.derive("m/44h/0h/0h/0/1")
    check("the right signature with the wrong pubkey is rejected",
          not runs(push(sig) + push(other.pubkey), spk, spend))

    # A signature over a different transaction must not verify here — this is
    # the property the whole device rests on.
    _, elsewhere = _spend_of(spk, amount=999_999)
    d2 = elsewhere.sighash_legacy(0, spk)
    r2, s2, _ = ec.ecdsa_sign(d2, key.seckey)
    lifted = ec.der_encode(r2, s2) + bytes([ourtx.SIGHASH_ALL])
    check("a signature lifted from another transaction is rejected",
          not runs(push(lifted) + push(key.pubkey), spk, spend))

    # ---- bare multisig — the same code path a p2wsh script runs through --
    print("\n bare m-of-n multisig")
    cosigners = [root] + [bip32.from_mnemonic(bip39.entropy_to_mnemonic(bytes([n]) * 16))
                          for n in (0x21, 0x22)]
    keys = [r_.derive("m/48h/0h/0h/2h/0/0") for r_ in cosigners]
    # BIP-67 ordering, which is what addresses.multisig_script is given.
    ordered = sorted(keys, key=lambda k: k.pubkey)
    witness_script = addresses.multisig_script(2, [k.pubkey for k in ordered])
    _, ms_spend = _spend_of(witness_script)
    ms_digest = ms_spend.sighash_legacy(0, witness_script)

    def sig_of(k):
        rr, ss, _ = ec.ecdsa_sign(ms_digest, k.seckey)
        return ec.der_encode(rr, ss) + bytes([ourtx.SIGHASH_ALL])

    sigs = [sig_of(k) for k in ordered[:2]]
    # The leading empty push is OP_CHECKMULTISIG's off-by-one, and NULLDUMMY
    # requires it to be empty rather than merely present.
    good = b"\x00" + b"".join(push(x) for x in sigs)
    check("two of three signatures satisfy the script",
          runs(good, witness_script, ms_spend))

    check("signatures out of script order are rejected",
          not runs(b"\x00" + b"".join(push(x) for x in reversed(sigs)),
                   witness_script, ms_spend))
    check("one signature short is rejected",
          not runs(b"\x00" + push(sigs[0]), witness_script, ms_spend))
    check("a non-empty dummy is rejected, as NULLDUMMY requires",
          not runs(b"\x01\x01" + b"".join(push(x) for x in sigs),
                   witness_script, ms_spend))

    outsider = bip32.from_mnemonic(bip39.entropy_to_mnemonic(b"\x99" * 16)) \
        .derive("m/48h/0h/0h/2h/0/0")
    rr, ss, _ = ec.ecdsa_sign(ms_digest, outsider.seckey)
    intruder = ec.der_encode(rr, ss) + bytes([ourtx.SIGHASH_ALL])
    check("a signature from outside the quorum is rejected",
          not runs(b"\x00" + push(sigs[0]) + push(intruder),
                   witness_script, ms_spend))

    # ---- what this suite deliberately does not claim --------------------
    print("\n scope")
    check("this interpreter has no witness support, and we do not pretend it does",
          not hasattr(__import__("bitcoin.core.scripteval", fromlist=["x"]),
                      "SCRIPT_VERIFY_WITNESS"))
    print("      segwit v0 and taproot rest on the published BIP-143 and")
    print("      BIP-341 vectors, and on byte-for-byte agreement with embit.")
    print("      A node settles it; only a real transaction does that.")

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
