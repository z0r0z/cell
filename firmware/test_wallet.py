#!/usr/bin/env python3
"""End-to-end wallet tests, and the attacks a hardware wallet must survive.

The first half proves the happy path: provision a seed, receive a PSBT or an
Ethereum transaction, run the whole unlock chain, produce a signature that
verifies. The second half is the part that matters more — a list of the ways
hardware wallets have actually lost people's money, each one written as a
hostile input that the device must refuse:

    fee inflation            a lying witness_utxo turning your coins into fee
    change substitution      "change" the wallet cannot derive
    path lying               a real key quoted at a path that does not produce it
    sighash downgrade        SIGHASH_NONE / SINGLE / ANYONECANPAY
    address substitution     a mutated destination that still decodes
    unrenderable operations  anything the owner could not have read
    chain-id replay          an Ethereum signature valid on another chain
    calldata smuggling       an EVM call dressed as a transfer
    seed tampering           a modified blob, a wrong PIN, a foreign device

A refusal is the pass condition for every one of them.
"""

from __future__ import annotations

import hashlib
import sys

import addresses
import bip32
import bip39
import eth
import ops
import psbt as psbtmod
import secp256k1 as ec
import signer
import tx as txmod
import wallet
from bip32 import ExtendedKey
from policy import Policy, Tier
from psbt import PSBT
from se import MAX_PIN_ATTEMPTS, SoftSE
from tx import Transaction, TxIn, TxOut, ser_compact

MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about")
PIN = "12345678"
FW = hashlib.sha256(b"test firmware").digest()
CAL = hashlib.sha256(b"test thresholds").digest()

FAILURES: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


def refuses(label: str, fn, *exc) -> None:
    """The pass condition is a refusal, and a refusal that says why."""
    exc = exc or (Exception,)
    try:
        fn()
        check(label, False)
    except exc as e:                                            # noqa: BLE001
        check(label, bool(str(e)))


# --------------------------------------------------------------------------
# A minimal PSBT builder — test scaffolding, not firmware
# --------------------------------------------------------------------------


def _kv(keytype: int, keydata: bytes = b"") -> bytes:
    return bytes([keytype]) + keydata


def build_psbt(root: ExtendedKey, script_type: str, *,
               in_amounts=(200_000,), send=150_000, change=45_000,
               dest="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
               change_index=0, include_parent=True,
               lie_about_amount=None, change_path=None,
               claimed_path=None, sighash_type=None,
               extra_outputs=()) -> bytes:
    """Assemble a PSBT the way a coordinator would, honestly or otherwise."""
    acct_path = wallet.account_path(script_type)
    acct = root.derive(acct_path)
    fp = root.fingerprint()

    def spk_for(node):
        if script_type == "p2wpkh":
            return addresses.p2wpkh_script(node.pubkey)
        if script_type == "p2pkh":
            return addresses.p2pkh_script(node.pubkey)
        if script_type == "p2sh-p2wpkh":
            return addresses.p2sh_p2wpkh_script(node.pubkey)
        if script_type == "p2tr":
            out, _ = ec.taproot_tweak_pubkey(node.pubkey[1:])
            return addresses.p2tr_script(out)
        raise AssertionError(script_type)

    parents, vin = [], []
    for n, amt in enumerate(in_amounts):
        node = acct.derive([0, n])
        parent = Transaction(2, [TxIn(bytes([0x11 + n]) * 32, 0)],
                             [TxOut(amt, spk_for(node))], 0)
        parents.append(parent)
        vin.append(TxIn(parent.txid(), 0))

    ch = acct.derive(change_path or [1, change_index])
    vout = [TxOut(send, addresses.address_to_script(dest))]
    if change:
        vout.append(TxOut(change, spk_for(ch)))
    for amt, addr in extra_outputs:
        vout.append(TxOut(amt, addresses.address_to_script(addr)))

    unsigned = Transaction(2, vin, vout, 0)
    p = PSBT(unsigned)
    p.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = unsigned.serialize(witness=False)

    for n, parent in enumerate(parents):
        node = acct.derive([0, n])
        m = p.inputs[n]
        if include_parent:
            m[_kv(psbtmod.IN_NON_WITNESS_UTXO)] = parent.serialize()
        amt = lie_about_amount if (lie_about_amount and n == 0) else parent.vout[0].value
        if script_type != "p2pkh":
            m[_kv(psbtmod.IN_WITNESS_UTXO)] = (
                amt.to_bytes(8, "little")
                + ser_compact(len(parent.vout[0].script_pubkey))
                + parent.vout[0].script_pubkey)
        if script_type == "p2sh-p2wpkh":
            m[_kv(psbtmod.IN_REDEEM_SCRIPT)] = addresses.p2wpkh_script(node.pubkey)
        path = claimed_path or (bip32.parse_path(acct_path) + [0, n])
        origin = fp + b"".join(i.to_bytes(4, "little") for i in path)
        if script_type == "p2tr":
            m[_kv(psbtmod.IN_TAP_INTERNAL_KEY)] = node.pubkey[1:]
            m[_kv(psbtmod.IN_TAP_BIP32_DERIVATION, node.pubkey[1:])] = b"\x00" + origin
        else:
            m[_kv(psbtmod.IN_BIP32_DERIVATION, node.pubkey)] = origin
        if sighash_type is not None:
            m[_kv(psbtmod.IN_SIGHASH_TYPE)] = sighash_type.to_bytes(4, "little")

    if change:
        m = p.outputs[1]
        cpath = bip32.parse_path(acct_path) + (change_path or [1, change_index])
        origin = fp + b"".join(i.to_bytes(4, "little") for i in cpath)
        if script_type == "p2tr":
            m[_kv(psbtmod.OUT_TAP_INTERNAL_KEY)] = ch.pubkey[1:]
            m[_kv(psbtmod.OUT_TAP_BIP32_DERIVATION, ch.pubkey[1:])] = b"\x00" + origin
        else:
            m[_kv(psbtmod.OUT_BIP32_DERIVATION, ch.pubkey)] = origin
            if script_type == "p2sh-p2wpkh":
                m[_kv(psbtmod.OUT_REDEEM_SCRIPT)] = addresses.p2wpkh_script(ch.pubkey)
    return p.serialize()




def to_v2(blob: bytes) -> bytes:
    """Re-express a version 0 PSBT as BIP-370 version 2.

    Test scaffolding. The device reads both dialects and must reach the same
    conclusions about either, which is exactly what makes converting a PSBT we
    already have assertions about the useful thing to do here.
    """
    p = PSBT.parse(blob)
    out = PSBT(p.tx)
    out.globals = {k: v for k, v in p.globals.items()
                   if k != _kv(psbtmod.GLOBAL_UNSIGNED_TX)}
    out.globals[_kv(psbtmod.GLOBAL_VERSION)] = (2).to_bytes(4, "little")
    out.globals[_kv(psbtmod.GLOBAL_TX_VERSION)] = p.tx.version.to_bytes(4, "little")
    out.globals[_kv(psbtmod.GLOBAL_FALLBACK_LOCKTIME)] = \
        p.tx.locktime.to_bytes(4, "little")
    out.globals[_kv(psbtmod.GLOBAL_INPUT_COUNT)] = ser_compact(len(p.tx.vin))
    out.globals[_kv(psbtmod.GLOBAL_OUTPUT_COUNT)] = ser_compact(len(p.tx.vout))
    out.inputs = [dict(m) for m in p.inputs]
    out.outputs = [dict(m) for m in p.outputs]
    for m, vin in zip(out.inputs, p.tx.vin):
        m[_kv(psbtmod.IN_PREVIOUS_TXID)] = vin.txid
        m[_kv(psbtmod.IN_OUTPUT_INDEX)] = vin.vout.to_bytes(4, "little")
        m[_kv(psbtmod.IN_SEQUENCE)] = vin.sequence.to_bytes(4, "little")
    for m, vout in zip(out.outputs, p.tx.vout):
        m[_kv(psbtmod.OUT_AMOUNT)] = vout.value.to_bytes(8, "little")
        m[_kv(psbtmod.OUT_SCRIPT)] = vout.script_pubkey
    return out.serialize()


# --------------------------------------------------------------------------
# Multisig scaffolding
# --------------------------------------------------------------------------

COSIGNER_WORDS = [
    bip39.entropy_to_mnemonic(bytes([n]) * 16) for n in (0x21, 0x22, 0x23)
]


def multisig_parts(ours: ExtendedKey, n_others: int = 2, threshold: int = 2,
                   wrapped: bool = False, network: str = "mainnet"):
    """Our device plus n co-signers, as the wallet layer would record them."""
    st = "multisig-p2sh-p2wsh" if wrapped else "multisig-p2wsh"
    path = wallet.multisig_account_path(st, 0, network)
    members = [(ours, path)]
    for w in COSIGNER_WORDS[:n_others]:
        members.append((bip32.from_mnemonic(w), path))
    cosigners = [
        wallet.CoSigner(label=f"signer{i}", fingerprint=root.fingerprint().hex(),
                        path=pth, xpub=root.derive(pth).neutered().serialize("xpub"))
        for i, (root, pth) in enumerate(members)]
    ms = wallet.Multisig(label="family", threshold=threshold, cosigners=cosigners,
                         sorted_keys=True, wrapped=wrapped, network=network)
    return ms, members


def multisig_script_at(ms, members, branch: int, index: int,
                       swap: ExtendedKey | None = None,
                       sorted_keys: bool | None = None) -> tuple[bytes, list]:
    """The witness script for one address, and the (pubkey, path) pairs."""
    pairs = []
    for i, (root_, pth) in enumerate(members):
        src = swap if (swap is not None and i == len(members) - 1) else root_
        node = src.derive(pth).derive([branch, index])
        pairs.append((src.fingerprint(), bip32.parse_path(pth) + [branch, index],
                      node.pubkey))
    keys = [pk for _, _, pk in pairs]
    use_sorted = ms.sorted_keys if sorted_keys is None else sorted_keys
    script = addresses.multisig_script(ms.threshold,
                                       sorted(keys) if use_sorted else keys)
    return script, pairs


def build_multisig_psbt(ms, members, *, in_amount=200_000, send=150_000,
                        change=45_000, change_swap=None, change_suffix=None,
                        change_sorted=None, omit_witness_script=False,
                        break_witness_script=False,
                        dest="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") -> bytes:
    in_script, in_pairs = multisig_script_at(ms, members, 0, 0)
    ch_script, ch_pairs = multisig_script_at(
        ms, members, 1, 0, swap=change_swap, sorted_keys=change_sorted)
    if change_suffix is not None:
        # Quote one co-signer at a different index than the rest.
        fp, path, pk = ch_pairs[-1]
        ch_pairs[-1] = (fp, path[:-1] + [change_suffix], pk)

    def spk(script):
        inner = addresses.p2wsh_script(script)
        return addresses.p2sh_script(inner) if ms.wrapped else inner

    parent = Transaction(2, [TxIn(b"\x31" * 32, 0)],
                         [TxOut(in_amount, spk(in_script))], 0)
    vout = [TxOut(send, addresses.address_to_script(dest))]
    if change:
        vout.append(TxOut(change, spk(ch_script)))
    unsigned = Transaction(2, [TxIn(parent.txid(), 0)], vout, 0)

    p = PSBT(unsigned)
    p.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = unsigned.serialize(witness=False)
    m = p.inputs[0]
    m[_kv(psbtmod.IN_NON_WITNESS_UTXO)] = parent.serialize()
    m[_kv(psbtmod.IN_WITNESS_UTXO)] = (
        in_amount.to_bytes(8, "little")
        + ser_compact(len(parent.vout[0].script_pubkey)) + parent.vout[0].script_pubkey)
    m[_kv(psbtmod.IN_WITNESS_SCRIPT)] = in_script
    if ms.wrapped:
        m[_kv(psbtmod.IN_REDEEM_SCRIPT)] = addresses.p2wsh_script(in_script)
    for fp, path, pk in in_pairs:
        m[_kv(psbtmod.IN_BIP32_DERIVATION, pk)] = (
            fp + b"".join(i.to_bytes(4, "little") for i in path))

    if change:
        o = p.outputs[1]
        if not omit_witness_script:
            o[_kv(psbtmod.OUT_WITNESS_SCRIPT)] = (
                ch_script[:-1] + b"\xac" if break_witness_script else ch_script)
        if ms.wrapped:
            o[_kv(psbtmod.OUT_REDEEM_SCRIPT)] = addresses.p2wsh_script(ch_script)
        for fp, path, pk in ch_pairs:
            o[_kv(psbtmod.OUT_BIP32_DERIVATION, pk)] = (
                fp + b"".join(i.to_bytes(4, "little") for i in path))
    return p.serialize()


# --------------------------------------------------------------------------


def make_device(pin: str = PIN):
    se = SoftSE(pin=pin)
    prov = wallet.provision(MNEMONIC, se, pin,
                            script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh",
                                          "p2pkh"))
    return se, prov


def gate_ok(_tier):
    return True, {"gate_scores": {"G1": 0.98, "G6": 0.97},
                  "features": {"soret": 0.41}}


def run_psbt(blob, se, prov, *, pin=PIN, confirm=None, pol=None, **kw):
    return wallet.sign_psbt(blob, prov, se, pol or Policy(), FW, CAL,
                            confirm or (lambda _lines: True), gate_ok, pin, **kw)


def main() -> int:
    print("Wallet — end to end, then every footgun we could name\n")

    se, prov = make_device()
    root = bip32.from_mnemonic(MNEMONIC)
    thief = bip32.from_mnemonic(bip39.entropy_to_mnemonic(b"\x07" * 16))

    # ---- provisioning -------------------------------------------------
    print(" provisioning")
    check("master fingerprint recorded", prov.master_fingerprint == root.fingerprint())
    check("accounts are watch-only",
          all(ExtendedKey.deserialize(a.xpub).seckey is None for a in prov.accounts))
    packed = prov.seed_pair.pack()
    check("the seed store does not contain the words",
          MNEMONIC.encode() not in packed and b"abandon" not in packed)
    # Two blobs, always. With no duress PIN asked for, the second is a real
    # mnemonic under a key nobody can derive -- so the store's shape says
    # nothing about whether this device has a decoy. See duress.py.
    check("two seeds are wrapped even with no duress PIN",
          len(prov.seed_pair.primary) > 0
          and len(prov.seed_pair.secondary) == len(prov.seed_pair.primary))
    check("account xpub matches the seed",
          prov.account_for("p2wpkh").xpub
          == root.derive("m/84h/0h/0h").neutered().serialize("xpub"))
    refuses("refuses to provision an invalid mnemonic",
            lambda: wallet.provision("abandon " * 11 + "abandon", SoftSE(), PIN),
            wallet.WalletError)

    # ---- the happy path, on every script type -------------------------
    print("\n signing, each script type")
    for st in ("p2wpkh", "p2sh-p2wpkh", "p2pkh", "p2tr"):
        blob = build_psbt(root, st)
        res = run_psbt(blob, se, prov)
        signed = PSBT.parse(res.psbt)
        acct = root.derive(wallet.account_path(st)).derive([0, 0])
        infos = [signed._input_info(0, root)]
        digest = signed.sighash(0, infos)
        if st == "p2tr":
            sig = signed.inputs[0][bytes([psbtmod.IN_TAP_KEY_SIG])]
            out, _ = ec.taproot_tweak_pubkey(acct.pubkey[1:])
            good = ec.schnorr_verify(digest, out, sig)
        else:
            sig = signed.inputs[0][bytes([psbtmod.IN_PARTIAL_SIG]) + acct.pubkey]
            good = (sig[-1] == txmod.SIGHASH_ALL
                    and ec.ecdsa_verify(digest, acct.pubkey, *ec.der_decode(sig[:-1])))
        check(f"{st}: signature verifies against the sighash", good)
        check(f"{st}: change recognised as ours", res.display and any(
            "your wallet" in ln for ln in res.display))
        check(f"{st}: attestation rides in the PSBT",
              signed.get_proprietary(b"CELL", 1) is not None)


    # ---- multisig: the quorum the attestation story depends on ---------
    print("\n multisig")
    ms, members = multisig_parts(root)
    prov.register_multisig(ms)
    ms_blob = build_multisig_psbt(ms, members)

    ms_lines = {}
    res = run_psbt(ms_blob, se, prov,
                   confirm=lambda ln: ms_lines.setdefault("l", ln) is None or True)
    signed = PSBT.parse(res.psbt)
    signed.descriptors = prov.descriptors()
    infos = [signed._input_info(0, root)]
    digest = signed.sighash(0, infos)
    our_key = root.derive(wallet.multisig_account_path("multisig-p2wsh")).derive([0, 0])
    sig = signed.inputs[0].get(bytes([psbtmod.IN_PARTIAL_SIG]) + our_key.pubkey)
    check("2-of-3 p2wsh: our partial signature is present", sig is not None)
    check("2-of-3 p2wsh: it verifies against the BIP-143 sighash",
          bool(sig) and sig[-1] == txmod.SIGHASH_ALL
          and ec.ecdsa_verify(digest, our_key.pubkey, *ec.der_decode(sig[:-1])))
    check("2-of-3 p2wsh: only our key is signed for",
          len([k for k in signed.inputs[0] if k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])]) == 1)
    mtxt = "\n".join(ms_lines["l"])
    check("the quorum is shown to the owner", "MULTISIG 2 of 3" in mtxt)
    check("and which signature this is", "signature 1 of 2" in mtxt)
    check("multisig change is recognised as ours", "-> your wallet" in mtxt)

    # An unregistered quorum must be refused, not signed on the strength of
    # holding one of its keys.
    bare = wallet.Provisioning(seed_pair=prov.seed_pair, accounts=prov.accounts,
                               master_fingerprint=prov.master_fingerprint)
    refuses("an unregistered quorum is refused",
            lambda: run_psbt(ms_blob, se, bare), psbtmod.BadPSBT)

    # THE ATTACK registration exists to stop: a change output holding one key
    # of ours and the rest an attacker's.
    swapped = build_multisig_psbt(ms, members, change_swap=thief)
    sw_lines = {}
    run_psbt(swapped, se, prov,
             confirm=lambda ln: sw_lines.setdefault("l", ln) is None or True)
    check("change with a substituted co-signer is NOT called ours",
          "WARNING" in "\n".join(sw_lines["l"])
          and "-> your wallet" not in "\n".join(sw_lines["l"]))

    # The subtler variants: same keys, wrong derivation suffix; same keys,
    # wrong ordering. Both produce a real script that is not our address.
    for label, kw in [("a co-signer quoted at a different index",
                       {"change_suffix": 9}),
                      ("the BIP-67 ordering flipped", {"change_sorted": False}),
                      ("no witness script at all", {"omit_witness_script": True}),
                      ("a witness script that is not m-of-n",
                       {"break_witness_script": True})]:
        lines = {}
        run_psbt(build_multisig_psbt(ms, members, **kw), se, prov,
                 confirm=lambda ln: lines.setdefault("l", ln) is None or True)
        check(f"change is refused when {label}",
              "WARNING" in "\n".join(lines["l"]))

    # Registration itself must refuse a quorum we are not in, or one whose
    # entry for us quotes an xpub this seed does not derive.
    outsider = wallet.Multisig(
        label="not-ours", threshold=2,
        cosigners=[wallet.CoSigner(label=f"x{i}", fingerprint=r.fingerprint().hex(),
                                   path=wallet.multisig_account_path("multisig-p2wsh"),
                                   xpub=r.derive(wallet.multisig_account_path(
                                       "multisig-p2wsh")).neutered().serialize("xpub"))
                   for i, r in enumerate([bip32.from_mnemonic(w)
                                          for w in COSIGNER_WORDS])])
    refuses("registering a quorum we are not in is refused",
            lambda: prov.register_multisig(outsider), wallet.WalletError)

    liar = wallet.Multisig(
        label="liar", threshold=2,
        cosigners=[wallet.CoSigner(label="us", fingerprint=prov.master_fingerprint.hex(),
                                   path=wallet.multisig_account_path("multisig-p2wsh"),
                                   xpub=thief.derive(wallet.multisig_account_path(
                                       "multisig-p2wsh")).neutered().serialize("xpub")),
                   ms.cosigners[1], ms.cosigners[2]])
    refuses("a quorum quoting a foreign xpub under our fingerprint is refused",
            lambda: prov.register_multisig(liar), wallet.WalletError)
    refuses("a 4-of-3 quorum is refused",
            lambda: wallet.Multisig(label="z", threshold=4,
                                    cosigners=ms.cosigners).check(),
            wallet.WalletError)
    refuses("a duplicate label is refused",
            lambda: prov.register_multisig(ms), wallet.WalletError)

    # p2sh-wrapped multisig, because BIP-48 defines both and a wallet that
    # only handles the native one silently fails on half of them.
    se2, prov2 = make_device()
    ms_w, members_w = multisig_parts(root, wrapped=True)
    prov2.register_multisig(ms_w)
    resw = run_psbt(build_multisig_psbt(ms_w, members_w), se2, prov2)
    check("p2sh-p2wsh multisig signs too", resw.signatures == 1)


    # ---- PSBT version 2 -------------------------------------------------
    print("\n psbt version 2 (BIP-370)")
    v0 = build_psbt(root, "p2wpkh")
    v2 = to_v2(v0)
    check("a v2 PSBT has no global unsigned transaction",
          PSBT.parse(v2).globals.get(_kv(psbtmod.GLOBAL_UNSIGNED_TX)) is None)
    check("the rebuilt transaction is identical to the v0 one",
          PSBT.parse(v2).tx.serialize(witness=False)
          == PSBT.parse(v0).tx.serialize(witness=False))

    r0 = run_psbt(v0, se, prov)
    r2 = run_psbt(v2, se, prov)
    check("v2 produces the same signature as v0",
          [v for m in PSBT.parse(r2.psbt).inputs for k, v in sorted(m.items())
           if k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])]
          == [v for m in PSBT.parse(r0.psbt).inputs for k, v in sorted(m.items())
              if k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])])
    check("...and comes back as v2, not silently downgraded",
          PSBT.parse(r2.psbt).psbt_version == 2
          and PSBT.parse(r2.psbt).globals.get(
              _kv(psbtmod.GLOBAL_UNSIGNED_TX)) is None)
    check("a v0 PSBT still reports as v0", PSBT.parse(r0.psbt).psbt_version == 0)

    # v2 must be verified exactly as hard as v0.
    refuses("a v2 PSBT paying two destinations is refused the same way",
            lambda: run_psbt(to_v2(build_psbt(
                root, "p2wpkh", send=100_000, change=45_000,
                extra_outputs=((50_000, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce"
                                        "4xj0gdcccefvpysxf3qccfmv3"),))),
                se, prov), psbtmod.BadPSBT)
    refuses("a v2 PSBT with a lying witness UTXO is refused the same way",
            lambda: run_psbt(to_v2(build_psbt(root, "p2wpkh",
                                              lie_about_amount=9_000_000)),
                             se, prov), psbtmod.BadPSBT)

    # Malformed v2 must be refused rather than half-read.
    def broken(drop=None, mangle=None):
        p = PSBT.parse(v2)
        if drop:
            p.inputs[0].pop(_kv(drop), None) or p.globals.pop(_kv(drop), None)
        if mangle:
            key, val = mangle
            (p.globals if key == psbtmod.GLOBAL_TX_VERSION
             else p.inputs[0])[_kv(key)] = val
        return p.serialize()

    for label, blob_ in [
        ("no input count", broken(drop=psbtmod.GLOBAL_INPUT_COUNT)),
        ("no previous txid", broken(drop=psbtmod.IN_PREVIOUS_TXID)),
        ("no output index", broken(drop=psbtmod.IN_OUTPUT_INDEX)),
        ("a short transaction version",
         broken(mangle=(psbtmod.GLOBAL_TX_VERSION, b"\x02"))),
        ("a short previous txid",
         broken(mangle=(psbtmod.IN_PREVIOUS_TXID, b"\x11" * 31))),
    ]:
        refuses(f"refuses a v2 PSBT with {label}",
                lambda b=blob_: PSBT.parse(b), psbtmod.BadPSBT)

    # Both locktime rules.
    lock = PSBT.parse(v2)
    lock.inputs[0][_kv(psbtmod.IN_REQUIRED_HEIGHT_LOCKTIME)] = (800000).to_bytes(4, "little")
    check("a required height locktime overrides the fallback",
          PSBT.parse(lock.serialize()).tx.locktime == 800000)
    lock.inputs[0][_kv(psbtmod.IN_REQUIRED_TIME_LOCKTIME)] = (1700000000).to_bytes(4, "little")
    refuses("requiring both a height and a time locktime is refused",
            lambda: PSBT.parse(lock.serialize()), psbtmod.BadPSBT)

    # A version we do not read must be named, not guessed at.
    unknown = PSBT.parse(v2)
    unknown.globals[_kv(psbtmod.GLOBAL_VERSION)] = (3).to_bytes(4, "little")
    refuses("an unknown PSBT version is refused by name",
            lambda: PSBT.parse(unknown.serialize()), psbtmod.BadPSBT)

    # ---- taproot script-path --------------------------------------------
    print("\n taproot script-path")
    sp = PSBT.parse(build_psbt(root, "p2tr", include_parent=False))
    # An output key that is not the tweak of our internal key means a script
    # path is in play. The device holds no leaf scripts and could not render
    # one, so it must refuse rather than sign into a tree it cannot describe.
    foreign, _ = ec.taproot_tweak_pubkey(
        thief.derive("m/86h/0h/0h/0/0").pubkey[1:])
    spk = addresses.p2tr_script(foreign)
    parent = Transaction.parse(sp.inputs[0][_kv(psbtmod.IN_NON_WITNESS_UTXO)]) \
        if _kv(psbtmod.IN_NON_WITNESS_UTXO) in sp.inputs[0] else None
    sp.inputs[0][_kv(psbtmod.IN_WITNESS_UTXO)] = (
        (200_000).to_bytes(8, "little") + ser_compact(len(spk)) + spk)
    del parent
    refuses("refuses a taproot input whose output key is not our tweak",
            lambda: run_psbt(sp.serialize(), se, prov), psbtmod.BadPSBT)

    # ---- what the owner is shown --------------------------------------
    print("\n what the owner sees")
    shown = {}

    def capture(lines):
        shown["lines"] = lines
        return True

    res = run_psbt(build_psbt(root, "p2wpkh"), se, prov, confirm=capture)
    text = "\n".join(shown["lines"])
    check("destination shown in full, never abbreviated",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in text.replace("\n", "")
          .replace(" ", "") and "..." not in text)
    check("fee is displayed", "fee" in text)
    check("the amount is exact", "0.00150000 BTC" in text)
    check("the tier is stated", "requires" in text)
    check("every line fits the display",
          all(len(ln) <= ops.DISPLAY_COLS for ln in shown["lines"]))
    check("cancelling at the prompt signs nothing",
          _refused(lambda: run_psbt(build_psbt(root, "p2wpkh"), se, prov,
                                    confirm=lambda _l: False)))

    # ---- FOOTGUN: fee inflation ---------------------------------------
    print("\n footgun: fee inflation")
    refuses("witness_utxo alone is refused for segwit v0",
            lambda: run_psbt(build_psbt(root, "p2wpkh", include_parent=False),
                             se, prov), psbtmod.BadPSBT)
    refuses("a witness_utxo that disagrees with the parent is refused",
            lambda: run_psbt(build_psbt(root, "p2wpkh", lie_about_amount=9_000_000),
                             se, prov), psbtmod.BadPSBT)

    # A parent transaction that is not the one being spent.
    tampered = PSBT.parse(build_psbt(root, "p2wpkh"))
    other_parent = Transaction(2, [TxIn(b"\x99" * 32, 0)],
                               [TxOut(999_999, addresses.p2wpkh_script(root.pubkey))], 0)
    tampered.inputs[0][bytes([psbtmod.IN_NON_WITNESS_UTXO])] = other_parent.serialize()
    refuses("a parent transaction with the wrong txid is refused",
            lambda: run_psbt(tampered.serialize(), se, prov), psbtmod.BadPSBT)

    # Taproot may use a witness_utxo, because BIP-341 commits to all amounts.
    ok_tr = run_psbt(build_psbt(root, "p2tr", include_parent=False), se, prov)
    check("taproot accepts a witness_utxo (BIP-341 covers every amount)",
          ok_tr.signatures == 1)

    # ---- FOOTGUN: change substitution ---------------------------------
    print("\n footgun: change substitution")
    stolen = PSBT.parse(build_psbt(root, "p2wpkh"))
    thief_key = thief.derive("m/84h/0h/0h/1/0")
    stolen.tx.vout[1].script_pubkey = addresses.p2wpkh_script(thief_key.pubkey)
    stolen.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = \
        stolen.tx.serialize(witness=False)
    lines = {}
    res = run_psbt(stolen.serialize(), se, prov,
                   confirm=lambda ln: lines.setdefault("l", ln) is None or True)
    txt = "\n".join(lines["l"])
    check("change we cannot derive is shown as a WARNING", "WARNING" in txt)
    check("...and its address is shown in full",
          addresses.script_to_address(stolen.tx.vout[1].script_pubkey)
          in txt.replace("\n", "").replace(" ", ""))
    check("...and it is not called change to the owner",
          "-> your wallet" not in txt)

    # TWO outputs labelled as change that we cannot derive. BitcoinSpend has a
    # single change line, so the second address used to overwrite the first
    # while its value was still added to the total: the owner saw the correct
    # total and only one of the two addresses the money went to. Refused now.
    two = PSBT.parse(build_psbt(
        root, "p2wpkh", send=100_000, change=45_000,
        extra_outputs=((40_000, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),)))
    for idx, sub in ((1, 0), (2, 1)):
        tk = thief.derive([1, sub])
        two.tx.vout[idx].script_pubkey = addresses.p2wpkh_script(tk.pubkey)
        two.outputs[idx] = {_kv(psbtmod.OUT_BIP32_DERIVATION, tk.pubkey):
                            root.fingerprint() + b"".join(
                                i.to_bytes(4, "little")
                                for i in bip32.parse_path("m/84h/0h/0h/1/0"))}
    two.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = two.tx.serialize(witness=False)
    refuses("two underivable change outputs are refused, not summed",
            lambda: run_psbt(two.serialize(), se, prov), psbtmod.BadPSBT)

    # The subtler version: the change output really is ours, but the PSBT
    # quotes it at a path that does not derive it. A wallet that trusts the
    # quoted path over its own arithmetic accepts a substituted key here.
    lied = PSBT.parse(build_psbt(root, "p2wpkh"))
    ch_key = root.derive("m/84h/0h/0h/1/0").pubkey
    origin = root.fingerprint() + b"".join(
        i.to_bytes(4, "little")
        for i in bip32.parse_path("m/84h/0h/0h/1/7"))          # wrong index
    lied.outputs[1] = {_kv(psbtmod.OUT_BIP32_DERIVATION, ch_key): origin}
    lie_lines = {}
    run_psbt(lied.serialize(), se, prov,
             confirm=lambda ln: lie_lines.setdefault("l", ln) is None or True)
    check("a key quoted at a path that does not derive it is not change",
          "WARNING" in "\n".join(lie_lines["l"]))

    # And the honest version of the same output must still be recognised, so
    # the check above is not passing merely because everything is refused.
    honest = {}
    run_psbt(build_psbt(root, "p2wpkh", change_index=7), se, prov,
             confirm=lambda ln: honest.setdefault("l", ln) is None or True)
    check("a correctly quoted change path is accepted",
          "-> your wallet" in "\n".join(honest["l"]))

    # ---- FOOTGUN: sighash downgrade -----------------------------------
    print("\n footgun: sighash downgrade")
    for name, flag in [("SIGHASH_NONE", 0x02), ("SIGHASH_SINGLE", 0x03),
                       ("ANYONECANPAY|ALL", 0x81), ("ANYONECANPAY|NONE", 0x82)]:
        refuses(f"refuses {name}",
                lambda f=flag: run_psbt(build_psbt(root, "p2wpkh", sighash_type=f),
                                        se, prov), psbtmod.BadPSBT)
    ok_all = run_psbt(build_psbt(root, "p2wpkh", sighash_type=0x01), se, prov)
    check("an explicit SIGHASH_ALL is accepted", ok_all.signatures == 1)

    # Taproot spells SIGHASH_ALL two ways and they are not the same signature.
    # BIP-341 puts the flag byte INTO the digest and BIP-341/371 append it
    # after the 64, so a device that accepts an explicit 0x01 and then signs
    # the DEFAULT digest emits something no node will ever accept -- and it
    # verifies perfectly against itself, which is why only an independently
    # recomputed digest catches it.
    for declared, want_len in ((None, 64), (0x00, 64), (0x01, 65)):
        blob = build_psbt(root, "p2tr", sighash_type=declared)
        signed = PSBT.parse(run_psbt(blob, se, prov).psbt)
        sig = signed.inputs[0][bytes([psbtmod.IN_TAP_KEY_SIG])]
        info = signed._input_info(0, root)
        ht = txmod.SIGHASH_DEFAULT if declared in (None, 0x00) else txmod.SIGHASH_ALL
        want = signed.tx.sighash_taproot(
            0, [info.amount], [info.script_pubkey], hashtype=ht)
        out_key, _ = ec.taproot_tweak_pubkey(
            root.derive(wallet.account_path("p2tr")).derive([0, 0]).pubkey[1:])
        name = "default" if declared is None else f"{declared:#04x}"
        check(f"p2tr sighash {name}: {want_len}-byte signature",
              len(sig) == want_len
              and (want_len == 64 or sig[64] == txmod.SIGHASH_ALL))
        check(f"p2tr sighash {name}: verifies against the consensus digest",
              ec.schnorr_verify(want, out_key, sig[:64]))

    # ---- FOOTGUN: a multisig the device cannot describe ----------------
    #
    # The witness spellings of a bare m-of-n are refused unless the quorum is
    # registered. The LEGACY p2sh spelling reaches the same script through a
    # redeem script and no witness script at all, so a check written against
    # `witness_script` walks straight past it: signed with nothing registered,
    # and rendered with no MULTISIG line to tell the owner they were one
    # signature in somebody's quorum.
    print("\n footgun: a multisig the device cannot describe")
    _ms_path = wallet.multisig_account_path("multisig-p2wsh")
    _mine = root.derive(_ms_path).derive([0, 0])
    _theirs = [ec.pubkey_compressed(hashlib.sha256(x).digest()) for x in (b"x", b"y")]
    _redeem = addresses.multisig_script(2, sorted([_mine.pubkey] + _theirs))
    _spk = addresses.p2sh_script(_redeem)
    _parent = Transaction(2, [TxIn(b"\x33" * 32, 0)], [TxOut(200_000, _spk)], 0)
    _un = Transaction(2, [TxIn(_parent.txid(), 0)],
                      [TxOut(150_000, addresses.address_to_script(
                          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))], 0)
    _p = PSBT(_un)
    _p.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = _un.serialize(witness=False)
    _p.inputs[0][_kv(psbtmod.IN_NON_WITNESS_UTXO)] = _parent.serialize()
    _p.inputs[0][_kv(psbtmod.IN_REDEEM_SCRIPT)] = _redeem
    _p.inputs[0][_kv(psbtmod.IN_BIP32_DERIVATION, _mine.pubkey)] = (
        root.fingerprint()
        + b"".join(i.to_bytes(4, "little")
                   for i in bip32.parse_path(_ms_path) + [0, 0]))
    refuses("refuses a bare multisig wrapped in a legacy p2sh",
            lambda: run_psbt(_p.serialize(), se, prov), psbtmod.BadPSBT)

    # ---- FOOTGUN: change that leaves, counted as change that returns ---
    #
    # A PSBT can carry BOTH: an output we rederived (comes back) and one the
    # host merely labelled as change and we cannot derive (does not). Summing
    # them put a foreign address on screen beside a figure that included money
    # coming home, and left TOTAL reporting only amount+fee -- 0.00005000 BTC
    # over a transaction that moved a whole coin.
    print("\n footgun: two kinds of change")
    _acct = root.derive(wallet.account_path("p2wpkh"))
    _in, _ch = _acct.derive([0, 0]), _acct.derive([1, 0])
    _thief = ec.pubkey_compressed(hashlib.sha256(b"thief-change").digest())
    _parent2 = Transaction(2, [TxIn(b"\x44" * 32, 0)],
                           [TxOut(1_000_000, addresses.p2wpkh_script(_in.pubkey))], 0)
    _un2 = Transaction(2, [TxIn(_parent2.txid(), 0)], [
        TxOut(1_000, addresses.address_to_script(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")),
        TxOut(10_000, addresses.p2wpkh_script(_ch.pubkey)),
        TxOut(985_000, addresses.p2wpkh_script(_thief))], 0)
    _p2 = PSBT(_un2)
    _p2.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = _un2.serialize(witness=False)
    _p2.inputs[0][_kv(psbtmod.IN_NON_WITNESS_UTXO)] = _parent2.serialize()
    _base = bip32.parse_path(wallet.account_path("p2wpkh"))
    _origin = lambda tail: root.fingerprint() + b"".join(
        i.to_bytes(4, "little") for i in _base + tail)
    _p2.inputs[0][_kv(psbtmod.IN_BIP32_DERIVATION, _in.pubkey)] = _origin([0, 0])
    _p2.outputs[1][_kv(psbtmod.OUT_BIP32_DERIVATION, _ch.pubkey)] = _origin([1, 0])
    _p2.outputs[2][_kv(psbtmod.OUT_BIP32_DERIVATION, _thief)] = _origin([0, 9])
    _sum = PSBT.parse(_p2.serialize()).summarize(root)
    _sp = _sum.spend
    check("change we derived is kept apart from change we did not",
          _sp.change_sats == 10_000 and _sp.unverified_sats == 985_000)
    check("the underivable output is priced as leaving",
          _sp.amount_for_policy() == 1_000 + _sum.fee + 985_000)
    _screen = ops.render_for_display(_sp, reserve=ops.CONFIRM_FOOTER_ROWS)
    check("TOTAL on screen is what actually leaves the wallet",
          f"TOTAL    {ops.format_btc(_sp.amount_for_policy())}"
          in "\n".join(_screen))
    check("...and the returning change still says so",
          any("-> your wallet" in ln for ln in _screen))
    # Joined with the indent stripped: wrap_full breaks a long address across
    # lines deliberately, and the property under test is that every character
    # of it is on the panel — not that it fits on one row.
    check("...and the address we cannot prove is shown in full, in amber",
          any("WARNING" in ln for ln in _screen)
          and addresses.script_to_address(addresses.p2wpkh_script(_thief))
          in "".join(ln.strip() for ln in _screen))

    # ---- FOOTGUN: things the owner could not read ---------------------
    print("\n footgun: unrenderable transactions")
    refuses("refuses a batched payment it cannot show line by line",
            lambda: run_psbt(build_psbt(root, "p2wpkh", send=100_000, change=45_000,
                                        extra_outputs=((50_000,
                                                        "bc1qrp33g0q5c5txsp9arysrx4k"
                                                        "6zdkfs4nce4xj0gdcccefvpysx"
                                                        "f3qccfmv3"),)),
                             se, prov), psbtmod.BadPSBT)
    op_ret = PSBT.parse(build_psbt(root, "p2wpkh"))
    op_ret.tx.vout[0].script_pubkey = b"\x6a\x04dead"
    op_ret.globals[_kv(psbtmod.GLOBAL_UNSIGNED_TX)] = op_ret.tx.serialize(witness=False)
    refuses("refuses an output with no address to display",
            lambda: run_psbt(op_ret.serialize(), se, prov), psbtmod.BadPSBT)

    # ---- FOOTGUN: nothing to sign -------------------------------------
    print("\n footgun: signing for someone else")
    foreign = build_psbt(thief, "p2wpkh")
    refuses("refuses a PSBT holding none of our keys",
            lambda: run_psbt(foreign, se, prov), wallet.WalletError)

    # ---- FOOTGUN: malformed input -------------------------------------
    print("\n footgun: malformed and hostile encodings")
    good = build_psbt(root, "p2wpkh")
    refuses("refuses a truncated PSBT", lambda: run_psbt(good[:-6], se, prov),
            psbtmod.BadPSBT, txmod.BadTransaction)
    refuses("refuses trailing bytes", lambda: run_psbt(good + b"\x00", se, prov),
            psbtmod.BadPSBT, txmod.BadTransaction)
    refuses("refuses a missing magic", lambda: run_psbt(b"xxxx\xff" + good[5:], se, prov),
            psbtmod.BadPSBT)
    refuses("refuses a duplicate key in a map",
            lambda: PSBT.parse(_with_duplicate_key(good)), psbtmod.BadPSBT)
    refuses("refuses an already-signed unsigned transaction",
            lambda: PSBT.parse(_with_scriptsig(good)), psbtmod.BadPSBT)

    # ---- duress, through the whole device -----------------------------
    #
    # duress.py has its own suite, but until now nothing joined it to the
    # wallet: `wallet.provision` wrote one blob and the signer opened one, so
    # the module was correct and unreachable. These checks are the seam. What
    # they prove is that the SAME call, with a different PIN, signs from a
    # different seed -- no branch, no mode, no flag.
    print("\n duress: a second PIN, a second wallet")
    DPIN = "87654321"
    DECOY = bip39.entropy_to_mnemonic(b"\x5a" * 32)
    dse = SoftSE(pin=PIN, duress_pin=DPIN)
    dprov = wallet.provision(MNEMONIC, dse, PIN, duress_pin=DPIN, decoy=DECOY)
    decoy_root = bip32.from_mnemonic(DECOY)

    # A spend of the REAL wallet's coins, and a spend of the DECOY's. Which
    # wallet a PSBT is for is read off the origin fingerprints it quotes, not
    # off the PIN -- the PIN comes after rendering and cannot be consulted in
    # time. A coercer who has been shown the decoy builds against the decoy.
    real_psbt = build_psbt(root, "p2wpkh")
    decoy_psbt = build_psbt(decoy_root, "p2wpkh")

    real_sig = run_psbt(real_psbt, dse, dprov, pin=PIN)
    decoy_sig = run_psbt(decoy_psbt, dse, dprov, pin=DPIN)
    check("the normal PIN signs the real wallet's spend", real_sig is not None)
    check("the duress PIN signs the decoy's — no refusal, no hesitation",
          decoy_sig is not None)

    # The decoy's signature has to come from the DECOY key. A duress PIN that
    # quietly signs with the real key is worse than no duress PIN at all.
    def _sig_pubkeys(blob):
        return {k[1:] for k in psbtmod.PSBT.parse(blob.psbt).inputs[0]
                if k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])}
    decoy_key = decoy_root.derive(wallet.account_path("p2wpkh")).derive([0, 0])
    real_key = root.derive(wallet.account_path("p2wpkh")).derive([0, 0])
    check("...signed by the decoy's key",
          decoy_key.pubkey in _sig_pubkeys(decoy_sig))
    check("...and the real spend by the real one",
          real_key.pubkey in _sig_pubkeys(real_sig))
    check("neither signature is the other's key",
          real_key.pubkey not in _sig_pubkeys(decoy_sig)
          and decoy_key.pubkey not in _sig_pubkeys(real_sig))

    # The decoy is a whole wallet, so its own change is recognised as change.
    # If it were not, every duress spend would show the coercer a WARNING and
    # the mechanism would announce itself the first time it was used.
    dshown = {}
    run_psbt(decoy_psbt, dse, dprov, pin=DPIN,
             confirm=lambda ln: dshown.setdefault("l", ln) is None or True)
    dtxt = "\n".join(dshown["l"])
    check("the decoy's change is recognised as the decoy's own",
          "-> your wallet" in dtxt and "WARNING" not in dtxt)

    # Crossing the wires must fail closed rather than sign something. The
    # refusal lands after the gate rather than before it, and that is not an
    # oversight: which seed a PIN opens is not knowable until the PIN is
    # entered, and the PIN is deliberately the last thing asked for. What
    # matters is that it is a refusal and a readable one -- app.py turns a
    # WalletError into a screen, never a traceback.
    def _fails(fn):
        try:
            fn()
            return False
        except (signer.Refused, wallet.WalletError):
            return True

    check("the duress PIN cannot sign the real wallet's spend",
          _fails(lambda: run_psbt(real_psbt, dse, dprov, pin=DPIN)))
    check("...and the normal PIN cannot sign the decoy's",
          _fails(lambda: run_psbt(decoy_psbt, dse, dprov, pin=PIN)))

    check("both PINs restore the attempt budget the same way",
          dse.attempts_remaining() == MAX_PIN_ATTEMPTS)

    # A device provisioned WITHOUT a duress PIN must be shaped identically to
    # one provisioned with it. This is what stops "does this device have a
    # decoy" being answerable by looking at the card.
    check("the seed store is the same size either way",
          len(dprov.seed_pair.pack()) == len(prov.seed_pair.pack()))
    check("...and every device records a decoy account for each of its own",
          len(prov.decoy_accounts) == len(prov.accounts)
          and len(dprov.decoy_accounts) == len(dprov.accounts))
    # The decoy of a device with no duress PIN is a real, well-formed wallet
    # that no PIN can reach. Its accounts are recorded, so the record looks the
    # same as a device that has one -- but nothing opens its seed.
    check("a device with no duress PIN still records a decoy wallet",
          prov.decoy_fingerprint not in (b"", b"\x00\x00\x00\x00")
          and prov.decoy_fingerprint != prov.master_fingerprint)
    # ...and its seed is sealed: the normal PIN's key opens exactly one of the
    # two blobs. The other was wrapped under 32 random bytes that were never
    # stored, so nothing opens it, ever.
    import seedstore as _ss
    se.verify_pin(PIN)
    _key = se.kdf(signer.unwrap_context(PIN))
    opened = 0
    for _blob in prov.seed_pair.blobs():
        try:
            _ss.unwrap(_blob, _key)
            opened += 1
        except Exception:                                       # noqa: BLE001
            pass
    check("...and its seed is sealed under a key that was never stored",
          opened == 1)

    # THROUGH THE FILES ON THE CARD, not just in memory. The decoy's accounts
    # and fingerprint have to survive a power cycle: without them the device
    # unwraps the decoy seed after a reboot and then refuses to sign with it,
    # because signing checks the seed against a recorded fingerprint. Duress
    # would work until the first power cycle and then silently stop, which is
    # the worst way for this particular feature to fail.
    import sys as _sys, tempfile as _tf
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "tools"))
    import provision as _pt
    with _tf.TemporaryDirectory() as _d:
        _out = _P(_d)
        (_out / _pt.BLOB).write_bytes(dprov.seed_pair.pack())
        _pt._save(_out, dprov, "mainnet")
        reloaded = _pt.load(_out)
        check("the decoy survives a round trip through the card",
              reloaded.decoy_fingerprint == dprov.decoy_fingerprint
              and len(reloaded.decoy_accounts) == len(dprov.decoy_accounts))
        check("...and both seeds come back byte for byte",
              reloaded.seed_pair.blobs() == dprov.seed_pair.blobs())
        check("...and the reloaded device still signs the decoy's spend",
              run_psbt(decoy_psbt, dse, reloaded, pin=DPIN) is not None)

    # ---- FOOTGUN: the seed at rest ------------------------------------
    print("\n footgun: the seed at rest")
    refuses("a wrong PIN does not unwrap the seed",
            lambda: run_psbt(good, se, prov, pin="00000000"), signer.Refused)
    import duress as duress_mod

    def _flip(blob: bytes) -> bytes:
        return blob[:-1] + bytes([blob[-1] ^ 0x01])

    # BOTH blobs, not one. wrap_pair shuffles them, so "the primary is the
    # real seed" is true about half the time -- a test that tampered with only
    # the first would pass on the tosses where it corrupted the decoy and the
    # real seed opened anyway.
    bad_prov = wallet.Provisioning(
        seed_pair=duress_mod.SeedPair(
            primary=_flip(prov.seed_pair.primary),
            secondary=_flip(prov.seed_pair.secondary)),
        accounts=prov.accounts,
        master_fingerprint=prov.master_fingerprint)
    refuses("a tampered seed blob is detected, not decrypted",
            lambda: run_psbt(good, SoftSE(pin=PIN), bad_prov),
            Exception)
    refuses("another device's chip cannot open our blob",
            lambda: run_psbt(good, SoftSE(pin=PIN), prov), Exception)

    # ---- Ethereum -----------------------------------------------------
    print("\n ethereum")
    t = eth.EthTransaction(chain_id=1, nonce=3, max_priority_fee_per_gas=10**9,
                           max_fee_per_gas=25 * 10**9, gas_limit=21000,
                           to="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                           value=10**17)
    eth_lines = {}
    r = wallet.sign_eth(t, prov, se, Policy(), FW, CAL,
                        lambda ln: eth_lines.setdefault("l", ln) is None or True,
                        gate_ok, PIN)
    etxt = "\n".join(eth_lines["l"])
    check("signs and recovers to the displayed sender",
          r.sender == addresses.eth_address(
              ExtendedKey.deserialize(prov.account_for("eth", "ethereum").xpub)
              .derive([0, 0]).pubkey))
    check("raw transaction is a typed EIP-1559 envelope", r.raw[0] == 0x02)
    check("chain id is displayed", "chain id 1" in etxt)
    check("nonce is displayed", "nonce    3" in etxt)
    check("worst-case fee is displayed", "max fee" in etxt)
    check("destination shown in full",
          "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" in etxt.replace("\n", "")
          .replace(" ", ""))

    refuses("refuses calldata dressed as a transfer",
            lambda: eth.EthTransaction(chain_id=1, nonce=0,
                                       max_priority_fee_per_gas=1,
                                       max_fee_per_gas=2, gas_limit=21000,
                                       to="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                                       value=0, data=b"\xa9\x05\x9c\xbb"),
            eth.BadEthTransaction)
    refuses("refuses an unnamed chain id",
            lambda: eth.EthTransaction(chain_id=31337, nonce=0,
                                       max_priority_fee_per_gas=1,
                                       max_fee_per_gas=2, gas_limit=21000,
                                       to="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                                       value=0), eth.BadEthTransaction)

    # The same transfer on another chain must produce a different signature,
    # or one authorisation drains every EVM chain the owner holds. Polygon is
    # not built in — the owner registers it, and registers its own ticker with
    # it, because Polygon does not denominate in ETH.
    eth.register_chain(137, "Polygon", "POL")
    t_poly = eth.EthTransaction(**{**t.__dict__, "chain_id": 137})
    check("a different chain id yields a different digest",
          t.sighash() != t_poly.sighash())
    check("a registered chain renders its own denomination",
          any("POL" in line for line in
              ops.EthereumSpend(amount_wei=t_poly.value, destination=t_poly.to,
                                chain_id=t_poly.chain_id,
                                chain_name=t_poly.chain_name(),
                                ticker=t_poly.ticker(), nonce=t_poly.nonce,
                                max_fee_wei=t_poly.max_fee_wei()).render()))

    # ---- tier policy still governs ------------------------------------
    print("\n the gate still governs")
    strict = Policy(blood_above=1)
    tiers = {}

    def note_gate(tier):
        tiers["t"] = tier
        return gate_ok(tier)

    wallet.sign_psbt(good, prov, se, strict, FW, CAL, lambda _l: True,
                     note_gate, PIN)
    check("a spend above the floor demands blood", tiers["t"] is Tier.BLOOD)

    def gate_fails(_tier):
        return False, {"message": "no pulse"}

    refuses("a failed gate signs nothing",
            lambda: wallet.sign_psbt(good, prov, se, Policy(), FW, CAL,
                                     lambda _l: True, gate_fails, PIN),
            signer.Refused)

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


def _refused(fn) -> bool:
    try:
        fn()
        return False
    except signer.Refused:
        return True


def _with_duplicate_key(blob: bytes) -> bytes:
    """Re-encode the globals map with one key repeated."""
    p = PSBT.parse(blob)
    body = b""
    for k, v in p.globals.items():
        body += ser_compact(len(k)) + k + ser_compact(len(v)) + v
    k, v = next(iter(p.globals.items()))
    body += ser_compact(len(k)) + k + ser_compact(len(v)) + v + b"\x00"
    rest = blob[blob.index(b"\x00", 5):]
    return psbtmod.PSBT_MAGIC + body + rest[1:]


def _with_scriptsig(blob: bytes) -> bytes:
    p = PSBT.parse(blob)
    p.tx.vin[0].script_sig = b"\x51"
    p.globals[bytes([psbtmod.GLOBAL_UNSIGNED_TX])] = p.tx.serialize(witness=False)
    return p.serialize()


if __name__ == "__main__":
    sys.exit(main())
