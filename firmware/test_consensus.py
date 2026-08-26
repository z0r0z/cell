#!/usr/bin/env python3
"""Do our signatures actually satisfy the scripts they are meant to?

Everything else in this repo checks that we compute what the specifications
say. That is necessary and it is not the same question. A signature can match
a published sighash vector exactly and still fail on the network, because what
a node does is not compare digests — it runs the script, and the script has
opinions about DER encoding, about the S value, about a dummy element nobody
reads, about whether a witness pubkey is compressed.

So this file hands our output to code written by somebody else and asks
whether it is satisfied. Two second opinions, neither a dependency of this
firmware — a second opinion that shared our code would not be one:

    python-bitcointx    a script interpreter WITH witness support. Runs
                        p2pkh, bare multisig, p2wpkh, p2sh-p2wpkh and p2wsh
                        under the flags a node applies.
    libsecp256k1        via coincurve. The reference implementation Bitcoin
                        Core itself signs with, used here for BIP-340 and the
                        BIP-341 output key tweak.

WHAT IS STILL NOT COVERED. Taproot SCRIPT execution — no interpreter available
here implements it, so what is checked there is the signature and the tweak
rather than the spend running end to end. And nothing here is a node: mempool
policy, standardness, and the actual acceptance of a broadcast transaction are
settled by one testnet spend and by nothing else. VALIDATION.md keeps that
open.

Both libraries are optional and the suite skips without them, because they
pull native shared objects that have no business being test dependencies:

    pip install python-bitcointx coincurve
"""

from __future__ import annotations

import sys

import addresses
import bip32
import bip39
import secp256k1 as ec
import tx as ourtx
from hashes import hash160, tagged

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon " \
           "abandon abandon abandon abandon about"
DEST = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
AMOUNT = 100_000

FAILURES: list[str] = []
SKIPPED: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


def _libsecp_path() -> str | None:
    """Find a libsecp256k1 for python-bitcointx to load.

    coincurve ships one inside its wheel, which saves asking anyone to build
    it. Falling back to the system loader covers a distro package.
    """
    try:
        import glob
        import os

        import coincurve
        found = glob.glob(os.path.join(os.path.dirname(coincurve.__file__),
                                       "*secp256k1*"))
        if found:
            return found[0]
    except ImportError:
        pass
    from ctypes.util import find_library
    return find_library("secp256k1")


def _interpreter():
    """The witness-capable interpreter, or None if it is not installed."""
    try:
        import bitcointx
        path = _libsecp_path()
        if path:
            bitcointx.set_custom_secp256k1_path(path)
        from bitcointx.core import CTransaction
        from bitcointx.core.key import CPubKey            # forces the native load
        from bitcointx.core.script import CScript, CScriptWitness
        from bitcointx.core.scripteval import (VerifyScript,
                                               SCRIPT_VERIFY_FLAGS_BY_NAME)
        del CPubKey
    except Exception:                                           # noqa: BLE001
        return None
    # What a node applies to a standard transaction. LOW_S and NULLFAIL are the
    # two most likely to catch a home-made signer; WITNESS_PUBKEYTYPE rejects
    # an uncompressed key in a witness, which is non-standard and would strand
    # a spend for a reason nobody could see on the screen.
    names = ("P2SH", "DERSIG", "LOW_S", "STRICTENC", "NULLDUMMY", "CLEANSTACK",
             "WITNESS", "NULLFAIL", "WITNESS_PUBKEYTYPE", "MINIMALIF")
    flags = tuple(SCRIPT_VERIFY_FLAGS_BY_NAME[n] for n in names)
    return VerifyScript, CScript, CScriptWitness, CTransaction, flags


def _spend_of(script_pubkey: bytes, amount: int = AMOUNT):
    parent = ourtx.Transaction(
        2, [ourtx.TxIn(b"\x11" * 32, 0)], [ourtx.TxOut(amount, script_pubkey)], 0)
    return ourtx.Transaction(
        2, [ourtx.TxIn(parent.txid(), 0)],
        [ourtx.TxOut(amount - 10_000, addresses.address_to_script(DEST))], 0)


def push(b: bytes) -> bytes:
    if len(b) >= 0x4C:
        raise AssertionError("test pushes are all short")
    return bytes([len(b)]) + b


def main() -> int:
    print("Consensus — does independent code accept what we produce?\n")
    root = bip32.from_mnemonic(MNEMONIC)
    parts = _interpreter()

    if parts is None:
        SKIPPED.append("script execution — pip install python-bitcointx coincurve")
        print(" script execution                                          SKIP")
    else:
        VerifyScript, CScript, CScriptWitness, CTransaction, flags = parts

        def runs(spk, script_sig, spend, witness=(), amount=AMOUNT):
            spend.vin[0].script_sig = script_sig
            spend.vin[0].witness = list(witness)
            txTo = CTransaction.deserialize(spend.serialize())
            try:
                VerifyScript(CScript(script_sig), CScript(spk), txTo, 0, flags,
                             amount=amount, witness=CScriptWitness(list(witness)))
                return True
            except Exception:                                   # noqa: BLE001
                return False

        # ---- p2pkh ----
        print(" legacy — pay-to-pubkey-hash")
        key = root.derive("m/44h/0h/0h/0/0")
        spk = addresses.p2pkh_script(key.pubkey)
        spend = _spend_of(spk)
        r, s, _ = ec.ecdsa_sign(spend.sighash_legacy(0, spk), key.seckey)
        sig = ec.der_encode(r, s) + bytes([ourtx.SIGHASH_ALL])

        check("the script runs and the signature satisfies it",
              runs(spk, push(sig) + push(key.pubkey), spend))
        check("a high-S signature is rejected, as relay policy would",
              not runs(spk, push(ec.der_encode(r, ec.N - s)
                                 + bytes([ourtx.SIGHASH_ALL]))
                       + push(key.pubkey), spend))
        mangled = bytearray(sig)
        mangled[10] ^= 0x01
        check("a mangled signature is rejected",
              not runs(spk, push(bytes(mangled)) + push(key.pubkey), spend))
        check("the same signature under another sighash byte is rejected",
              not runs(spk, push(ec.der_encode(r, s) + b"\x02")
                       + push(key.pubkey), spend))
        check("the right signature with the wrong pubkey is rejected",
              not runs(spk, push(sig)
                       + push(root.derive("m/44h/0h/0h/0/1").pubkey), spend))
        lifted = _spend_of(spk, amount=999_999)
        r2, s2, _ = ec.ecdsa_sign(lifted.sighash_legacy(0, spk), key.seckey)
        check("a signature lifted from another transaction is rejected",
              not runs(spk, push(ec.der_encode(r2, s2)
                                 + bytes([ourtx.SIGHASH_ALL]))
                       + push(key.pubkey), spend))

        # ---- bare multisig ----
        print("\n legacy — bare m-of-n multisig")
        cosigners = [root] + [bip32.from_mnemonic(
            bip39.entropy_to_mnemonic(bytes([n]) * 16)) for n in (0x21, 0x22)]
        ordered = sorted((c.derive("m/48h/0h/0h/2h/0/0") for c in cosigners),
                         key=lambda k: k.pubkey)
        ws = addresses.multisig_script(2, [k.pubkey for k in ordered])
        ms_spend = _spend_of(ws)
        ms_digest = ms_spend.sighash_legacy(0, ws)

        def ms_sig(k, digest=None):
            rr, ss, _ = ec.ecdsa_sign(ms_digest if digest is None else digest,
                                      k.seckey)
            return ec.der_encode(rr, ss) + bytes([ourtx.SIGHASH_ALL])

        sigs = [ms_sig(k) for k in ordered[:2]]
        outsider = bip32.from_mnemonic(bip39.entropy_to_mnemonic(b"\x99" * 16)) \
            .derive("m/48h/0h/0h/2h/0/0")

        check("two of three signatures satisfy the script",
              runs(ws, b"\x00" + b"".join(push(x) for x in sigs), ms_spend))
        check("signatures out of script order are rejected",
              not runs(ws, b"\x00" + b"".join(push(x) for x in reversed(sigs)),
                       ms_spend))
        check("one signature short is rejected",
              not runs(ws, b"\x00" + push(sigs[0]), ms_spend))
        check("a non-empty dummy is rejected, as NULLDUMMY requires",
              not runs(ws, b"\x01\x01" + b"".join(push(x) for x in sigs),
                       ms_spend))
        check("a signature from outside the quorum is rejected",
              not runs(ws, b"\x00" + push(sigs[0]) + push(ms_sig(outsider)),
                       ms_spend))

        # ---- segwit v0 ----
        print("\n segwit v0 — witness execution")
        wk = root.derive("m/84h/0h/0h/0/0")
        w_spk = addresses.p2wpkh_script(wk.pubkey)
        w_spend = _spend_of(w_spk)
        code = b"\x76\xa9\x14" + hash160(wk.pubkey) + b"\x88\xac"
        wr, wsg, _ = ec.ecdsa_sign(w_spend.sighash_segwit_v0(0, code, AMOUNT),
                                   wk.seckey)
        wsig = ec.der_encode(wr, wsg) + bytes([ourtx.SIGHASH_ALL])

        check("p2wpkh: the witness satisfies the program",
              runs(w_spk, b"", w_spend, witness=(wsig, wk.pubkey)))

        # BIP-143 commits to the input's amount. A signature made over the
        # wrong one is the fee-inflation attack seen from the other side, and
        # the interpreter must reject it.
        br, bs, _ = ec.ecdsa_sign(
            w_spend.sighash_segwit_v0(0, code, AMOUNT + 1), wk.seckey)
        check("p2wpkh: a signature over the wrong amount is rejected",
              not runs(w_spk, b"", w_spend, witness=(
                  ec.der_encode(br, bs) + bytes([ourtx.SIGHASH_ALL]), wk.pubkey)))
        check("p2wpkh: an uncompressed key is rejected (WITNESS_PUBKEYTYPE)",
              not runs(w_spk, b"", w_spend, witness=(
                  wsig, ec.ser_uncompressed(ec.pubkey_point(wk.seckey)))))

        redeem = addresses.p2wpkh_script(wk.pubkey)
        sh_spk = addresses.p2sh_script(redeem)
        sh_spend = _spend_of(sh_spk)
        sr, ss2, _ = ec.ecdsa_sign(sh_spend.sighash_segwit_v0(0, code, AMOUNT),
                                   wk.seckey)
        check("p2sh-p2wpkh: the wrapped witness satisfies the program",
              runs(sh_spk, push(redeem), sh_spend,
                   witness=(ec.der_encode(sr, ss2) + bytes([ourtx.SIGHASH_ALL]),
                            wk.pubkey)))

        wsh_spk = addresses.p2wsh_script(ws)
        wsh_spend = _spend_of(wsh_spk)
        wsh_digest = wsh_spend.sighash_segwit_v0(0, ws, AMOUNT)
        wsh_sigs = [ms_sig(k, wsh_digest) for k in ordered[:2]]
        check("p2wsh 2-of-3: the witness stack satisfies the script",
              runs(wsh_spk, b"", wsh_spend, witness=(b"", *wsh_sigs, ws)))
        check("p2wsh 2-of-3: a swapped co-signer is rejected",
              not runs(wsh_spk, b"", wsh_spend, witness=(
                  b"", wsh_sigs[0], ms_sig(outsider, wsh_digest), ws)))
        check("p2wsh 2-of-3: a witness script other than the committed one "
              "is rejected",
              not runs(wsh_spk, b"", wsh_spend, witness=(
                  b"", *wsh_sigs,
                  addresses.multisig_script(
                      2, sorted([ordered[0].pubkey, ordered[1].pubkey,
                                 outsider.pubkey])))))

    # ---- taproot, against libsecp256k1 ----
    print("\n taproot — against libsecp256k1, the reference implementation")
    try:
        from coincurve import PrivateKey, PublicKeyXOnly
    except ImportError:
        SKIPPED.append("taproot cross-check — pip install coincurve")
        print("  libsecp256k1 via coincurve                                SKIP")
    else:
        tk = root.derive("m/86h/0h/0h/0/0")
        internal = ec.schnorr_pubkey(tk.seckey)
        ours, _parity = ec.taproot_tweak_pubkey(internal)

        theirs = PublicKeyXOnly(internal)
        theirs.tweak_add(tagged("TapTweak", internal))
        check("our BIP-341 output key equals libsecp256k1's tweak_add",
              theirs.format() == ours)

        t_spk = addresses.p2tr_script(ours)
        t_spend = _spend_of(t_spk)
        t_digest = t_spend.sighash_taproot(0, [AMOUNT], [t_spk])
        tweaked = ec.taproot_tweak_seckey(tk.seckey)
        our_sig = ec.schnorr_sign(t_digest, tweaked)

        check("libsecp256k1 verifies our BIP-340 signature",
              PublicKeyXOnly(ours).verify(our_sig, t_digest))
        check("we verify libsecp256k1's signature over the same digest",
              ec.schnorr_verify(t_digest, ours,
                                PrivateKey(tweaked).sign_schnorr(t_digest)))
        check("libsecp256k1 rejects a tampered signature",
              not PublicKeyXOnly(ours).verify(
                  our_sig[:-1] + bytes([our_sig[-1] ^ 1]), t_digest))
        other = _spend_of(t_spk, amount=999_999)
        check("libsecp256k1 rejects it over a different transaction",
              not PublicKeyXOnly(ours).verify(
                  our_sig, other.sighash_taproot(0, [999_999], [t_spk])))
        # Signing with the internal key instead of the tweaked one is the
        # mistake that produces a signature for a key nobody funded.
        check("the untweaked key does not satisfy the output key",
              not PublicKeyXOnly(ours).verify(
                  ec.schnorr_sign(t_digest, tk.seckey), t_digest))

    # ---- the same questions, over many keys instead of one ----
    #
    # Everything above pins one key against libsecp256k1, and the published
    # vectors pin a handful more. Neither says much about the paths that only
    # SOME keys take: a recovery id with its high bit set, a grind that has to
    # retry, a DER integer that needs a padding byte. Those are per-key
    # properties, so they want a sweep rather than a vector.
    #
    # Every comparison here is byte equality against the implementation
    # Bitcoin Core signs with, not agreement with ourselves.
    print("\n differential — the signing core against libsecp256k1, many keys")
    try:
        from coincurve import PrivateKey, PublicKey
    except ImportError:
        SKIPPED.append("differential sweep — pip install coincurve")
        print("  libsecp256k1 via coincurve                                SKIP")
    else:
        import hashlib as _hl
        from collections import Counter
        n_keys, mismatch = 300, Counter()
        for i in range(n_keys):
            sk = _hl.sha256(f"differential-{i}".encode()).digest()
            if not 1 <= int.from_bytes(sk, "big") <= ec.N - 1:
                continue                        # astronomically unlikely
            msg = _hl.sha256(f"message-{i}".encode()).digest()
            ref = PrivateKey(sk)

            if ec.pubkey_compressed(sk) != ref.public_key.format(compressed=True):
                mismatch["compressed pubkey"] += 1
            if ec.ser_uncompressed(ec.pubkey_point(sk)) != \
                    ref.public_key.format(compressed=False):
                mismatch["uncompressed pubkey"] += 1

            # RFC 6979 is deterministic, so an ungrounded signature is not
            # merely valid -- it is the SAME 64 bytes libsecp256k1 produces.
            r, sg, rec = ec.ecdsa_sign(msg, sk, grind_low_r=False)
            ours64 = r.to_bytes(32, "big") + sg.to_bytes(32, "big")
            theirs = ref.sign_recoverable(msg, hasher=None)
            if ours64 != theirs[:64]:
                mismatch["RFC 6979 signature"] += 1
            if theirs[64] != rec:
                mismatch["recovery id"] += 1
            if PublicKey.from_signature_and_message(
                    ours64 + bytes([rec]), msg,
                    hasher=None).format() != ec.pubkey_compressed(sk):
                mismatch["they recover our signature"] += 1
            if ec.ecdsa_recover(msg, r, sg, rec) != ec.pubkey_compressed(sk):
                mismatch["we recover our own"] += 1

            # The ground signature is ours alone, so it is checked by being
            # ACCEPTED rather than by being equal -- through our DER encoder
            # and their parser.
            rg, sgg, _ = ec.ecdsa_sign(msg, sk)
            if rg >> 255:
                mismatch["low-R grinding"] += 1
            if not ref.public_key.verify(ec.der_encode(rg, sgg), msg, hasher=None):
                mismatch["our DER, their verify"] += 1

            xo = ec.schnorr_pubkey(sk)
            out_key, parity = ec.taproot_tweak_pubkey(xo)
            their_out = PublicKey.from_point(*ec.lift_x(xo)).add(
                tagged("TapTweak", xo)).format(compressed=True)
            if their_out[1:] != out_key:
                mismatch["BIP-341 output key"] += 1
            if (their_out[0] == 3) != bool(parity):
                mismatch["BIP-341 output parity"] += 1
            if ec.schnorr_pubkey(ec.taproot_tweak_seckey(sk)) != out_key:
                mismatch["secret and public tweak"] += 1

        if mismatch:
            print("      " + ", ".join(f"{k} x{v}"
                                       for k, v in mismatch.most_common()))
        check(f"{n_keys} keys agree with libsecp256k1 byte for byte",
              not mismatch)

    print("\n" + "-" * 66)
    if SKIPPED:
        print("skipped, because a second opinion is optional here:")
        for item in SKIPPED:
            print(f"  - {item}")
        print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS" + (" (what ran)" if SKIPPED else ""))
    print("\nTaproot SCRIPT execution is still uncovered — no interpreter here")
    print("implements it. And none of this is a node: standardness and actual")
    print("acceptance are settled by one testnet spend and nothing else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
