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
import attest
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
from se import SoftSE
from tx import Transaction, TxIn, TxOut, ser_compact

MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about")
PIN = "123456"
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

    # ---- provisioning -------------------------------------------------
    print(" provisioning")
    check("master fingerprint recorded", prov.master_fingerprint == root.fingerprint())
    check("accounts are watch-only",
          all(ExtendedKey.deserialize(a.xpub).seckey is None for a in prov.accounts))
    check("seed blob does not contain the words",
          MNEMONIC.encode() not in prov.seed_blob
          and b"abandon" not in prov.seed_blob)
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
              signed.get_proprietary(b"CELL\x01") is not None)

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
    thief = bip32.from_mnemonic(bip39.entropy_to_mnemonic(b"\x07" * 16))
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

    # ---- FOOTGUN: the seed at rest ------------------------------------
    print("\n footgun: the seed at rest")
    refuses("a wrong PIN does not unwrap the seed",
            lambda: run_psbt(good, se, prov, pin="000000"), signer.Refused)
    bad_prov = wallet.Provisioning(seed_blob=bytearray(prov.seed_blob),
                                   accounts=prov.accounts,
                                   master_fingerprint=prov.master_fingerprint)
    bad_prov.seed_blob = bytes(bad_prov.seed_blob[:-1]
                               + bytes([bad_prov.seed_blob[-1] ^ 0x01]))
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
    # or one authorisation drains every EVM chain the owner holds.
    t_poly = eth.EthTransaction(**{**t.__dict__, "chain_id": 137})
    check("a different chain id yields a different digest",
          t.sighash() != t_poly.sighash())

    print("\n coordinator challenge")
    nonce = "cd" * 32
    ch = ops.Challenge(nonce=nonce, purpose="coordinator/v1")
    ch_lines = {}
    cr = wallet.sign_challenge(
        ch, prov, se, Policy(), FW, CAL,
        lambda ln: ch_lines.setdefault("l", ln) is None or True,
        gate_ok, PIN)
    ctxt = "\n".join(ch_lines["l"])
    check("challenge nonce shown in full",
          nonce in ctxt.replace("\n", "").replace(" ", ""))
    check("challenge purpose shown", "coordinator/v1" in ctxt)
    check("attestation binds the challenge digest",
          attest.Attestation.unpack(cr.attestation).sighash == ch.digest())
    check("spend-key signature verifies",
          ec.schnorr_verify(cr.digest, cr.pubkey, cr.signature))
    check("challenge is Touch-default", cr.tier is Tier.TOUCH)
    refuses("unknown purpose refused before the gate",
            lambda: ops.Challenge(nonce=nonce, purpose="heir/v1").digest(),
            ops.UnrenderableOperation)

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
