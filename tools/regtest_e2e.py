#!/usr/bin/env python3
"""Sign with the firmware, and make Bitcoin Core accept it.

Everything else this repo calls a test compares our output to a specification,
to another library, or to an interpreter. This one asks the only question that
actually settles anything: does a node take it?

    Core funds an address this firmware derived
    the firmware signs a PSBT spending it, through the whole unlock chain
    Core finalises that PSBT, accepts it into the mempool, and mines it

If that round trip completes, then the derivation, the sighash, the signature,
the witness serialisation, the PSBT encoding, the fee arithmetic and the
standardness of the result are all correct together — which is a different and
stronger claim than each of them being correct separately.

It runs against a private regtest chain with no peers, so the coins are
worthless and nothing leaves the machine. It is not part of `run_tests.py`,
because it needs a Bitcoin Core binary that CI has no business downloading.
Run it by hand when you want the answer:

    tools/regtest_e2e.py --bitcoin-dir ~/bitcoin-28.0/bin

WHAT THIS CLOSES that nothing else could: taproot script execution, which no
Python interpreter available implements, and standardness — the rules a node
applies beyond consensus, where a technically valid transaction is dropped for
being unusual. Both were open in VALIDATION.md until this ran.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

import addresses                                                # noqa: E402
import bip32                                                    # noqa: E402
import psbt as psbtmod                                          # noqa: E402
import secp256k1 as ec                                          # noqa: E402
import wallet                                                   # noqa: E402
from policy import Policy                                       # noqa: E402
from se import SoftSE                                           # noqa: E402
from tx import Transaction, TxIn, TxOut, ser_compact            # noqa: E402

MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about")
PIN = "12345678"
FW = hashlib.sha256(b"regtest firmware").digest()
CAL = hashlib.sha256(b"regtest thresholds").digest()
NETWORK = "regtest"

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {label:<52}{'PASS' if ok else 'FAIL'}")
    if detail and not ok:
        print(f"      {detail}")
    if not ok:
        FAILURES.append(label)


class Core:
    """bitcoin-cli, as a callable."""

    def __init__(self, binary: Path, datadir: Path):
        self.cli = [str(binary / "bitcoin-cli"), f"-datadir={datadir}"]

    def __call__(self, *args, wallet_name: str | None = None):
        cmd = list(self.cli)
        if wallet_name:
            cmd.append(f"-rpcwallet={wallet_name}")
        cmd += [str(a) for a in args]
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"{' '.join(args[:2])}: {out.stderr.strip()}")
        text = out.stdout.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


def gate_ok(_tier):
    return True, {"gate_scores": {"G1": 0.99}, "features": {"soret": 0.42}}


def build_psbt_for(utxo: dict, node, script_type: str, dest: str,
                   send: int, change: int, ms=None, members=None,
                   sighash_type: "int | None" = None) -> bytes:
    """A PSBT spending one real regtest UTXO, as a coordinator would build it.

    `sighash_type` writes PSBT_IN_SIGHASH_TYPE. It exists for taproot, which
    spells SIGHASH_ALL two ways: absent (SIGHASH_DEFAULT, 0x00) and an explicit
    0x01. They are different digests and the second wants a 65-byte signature,
    so only a node can settle whether we got it right.
    """
    txid = bytes.fromhex(utxo["txid"])[::-1]
    vin = TxIn(txid, utxo["vout"])
    vout = [TxOut(send, addresses.address_to_script(dest, NETWORK))]
    if change:
        vout.append(TxOut(change, node["change_spk"]))
    unsigned = Transaction(2, [vin], vout, 0)

    p = psbtmod.PSBT(unsigned)
    p.globals[bytes([psbtmod.GLOBAL_UNSIGNED_TX])] = unsigned.serialize(witness=False)
    m = p.inputs[0]
    m[bytes([psbtmod.IN_NON_WITNESS_UTXO])] = bytes.fromhex(utxo["parent_hex"])
    m[bytes([psbtmod.IN_WITNESS_UTXO])] = (
        utxo["amount"].to_bytes(8, "little")
        + ser_compact(len(node["spk"])) + node["spk"])
    if node.get("redeem"):
        m[bytes([psbtmod.IN_REDEEM_SCRIPT])] = node["redeem"]
    if node.get("witness_script"):
        m[bytes([psbtmod.IN_WITNESS_SCRIPT])] = node["witness_script"]
    if sighash_type is not None:
        m[bytes([psbtmod.IN_SIGHASH_TYPE])] = sighash_type.to_bytes(4, "little")

    for fp, path, pk in node["origins"]:
        origin = fp + b"".join(i.to_bytes(4, "little") for i in path)
        if script_type == "p2tr":
            m[bytes([psbtmod.IN_TAP_INTERNAL_KEY])] = pk[1:]
            m[bytes([psbtmod.IN_TAP_BIP32_DERIVATION]) + pk[1:]] = b"\x00" + origin
        else:
            m[bytes([psbtmod.IN_BIP32_DERIVATION]) + pk] = origin

    if change:
        o = p.outputs[1]
        if node.get("change_witness_script"):
            o[bytes([psbtmod.OUT_WITNESS_SCRIPT])] = node["change_witness_script"]
        if node.get("change_redeem"):
            o[bytes([psbtmod.OUT_REDEEM_SCRIPT])] = node["change_redeem"]
        for fp, path, pk in node["change_origins"]:
            origin = fp + b"".join(i.to_bytes(4, "little") for i in path)
            if script_type == "p2tr":
                o[bytes([psbtmod.OUT_TAP_INTERNAL_KEY])] = pk[1:]
                o[bytes([psbtmod.OUT_TAP_BIP32_DERIVATION]) + pk[1:]] = \
                    b"\x00" + origin
            else:
                o[bytes([psbtmod.OUT_BIP32_DERIVATION]) + pk] = origin
    return p.serialize()


def describe(root, script_type: str, branch: int, index: int, ms=None, members=None):
    """The scriptPubKey, redeem/witness scripts and key origins for one address."""
    if ms is not None:
        acct_path = wallet.multisig_account_path(
            "multisig-p2wsh", 0, NETWORK)
        origins, keys = [], []
        for r_ in members:
            node = r_.derive(acct_path).derive([branch, index])
            origins.append((r_.fingerprint(),
                            bip32.parse_path(acct_path) + [branch, index],
                            node.pubkey))
            keys.append(node.pubkey)
        ws = addresses.multisig_script(ms.threshold, sorted(keys))
        return {"spk": addresses.p2wsh_script(ws), "witness_script": ws,
                "origins": origins}

    acct_path = wallet.account_path(script_type, 0, NETWORK)
    node = root.derive(acct_path).derive([branch, index])
    origins = [(root.fingerprint(),
                bip32.parse_path(acct_path) + [branch, index], node.pubkey)]
    info = {"origins": origins}
    if script_type == "p2wpkh":
        info["spk"] = addresses.p2wpkh_script(node.pubkey)
    elif script_type == "p2pkh":
        info["spk"] = addresses.p2pkh_script(node.pubkey)
    elif script_type == "p2sh-p2wpkh":
        info["redeem"] = addresses.p2wpkh_script(node.pubkey)
        info["spk"] = addresses.p2sh_script(info["redeem"])
    elif script_type == "p2tr":
        out, _ = ec.taproot_tweak_pubkey(node.pubkey[1:])
        info["spk"] = addresses.p2tr_script(out)
    else:
        raise ValueError(script_type)
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bitcoin-dir", required=True,
                    help="directory holding bitcoind and bitcoin-cli")
    ap.add_argument("--datadir", help="regtest datadir (a temporary one by default)")
    ap.add_argument("--no-start", action="store_true",
                    help="use a node that is already running on this datadir")
    args = ap.parse_args()

    binary = Path(args.bitcoin_dir).expanduser()
    datadir = Path(args.datadir).expanduser() if args.datadir \
        else Path(tempfile.mkdtemp(prefix="cell-regtest-"))
    core = Core(binary, datadir)

    print("Regtest end to end — the firmware signs, Bitcoin Core accepts\n")
    started_here = False
    if not args.no_start:
        started_here = start_node(binary, datadir)
    print(f"  node    {core('getblockchaininfo')['chain']}")

    try:
        return run_cases(core, datadir)
    finally:
        if started_here:
            subprocess.run([str(binary / "bitcoin-cli"), f"-datadir={datadir}",
                            "stop"], capture_output=True)


def start_node(binary: Path, datadir: Path) -> bool:
    """Start a regtest node on `datadir`, unless one is already answering.

    The script used to require a node someone else had started, which made the
    CI job three steps and meant the commonest failure was a missing
    `regtest=1` sending bitcoin-cli at mainnet's port. Owning the lifecycle
    here makes the job a one-liner and puts the settings that matter next to
    the code that depends on them.
    """
    import time
    cli = [str(binary / "bitcoin-cli"), f"-datadir={datadir}"]
    if subprocess.run(cli + ["getblockchaininfo"],
                      capture_output=True).returncode == 0:
        return False                    # somebody else's node; leave it alone

    datadir.mkdir(parents=True, exist_ok=True)
    conf = datadir / "bitcoin.conf"
    if not conf.exists():
        # txindex, because getrawtransaction on a CONFIRMED transaction fails
        # without it. fallbackfee, because regtest has no fee history and the
        # wallet refuses to send at all without one. Both are the kind of
        # setting that produces a baffling error rather than a clear one.
        conf.write_text("regtest=1\nserver=1\ntxindex=1\n"
                        "fallbackfee=0.0002\n\n[regtest]\n"
                        "listen=0\nconnect=0\ndnsseed=0\n")
    subprocess.run([str(binary / "bitcoind"), f"-datadir={datadir}", "-daemon"],
                   capture_output=True, check=True)
    for _ in range(60):
        if subprocess.run(cli + ["getblockchaininfo"],
                          capture_output=True).returncode == 0:
            return True
        time.sleep(0.5)
    raise RuntimeError("bitcoind did not answer RPC within 30 seconds")


def run_cases(core: "Core", datadir: Path) -> int:

    # Idempotent: the wallet may already exist and may already be loaded, and
    # a rerun against the same datadir is the normal case while debugging.
    if "core" not in core("listwallets"):
        try:
            core("createwallet", "core")
        except RuntimeError:
            core("loadwallet", "core")
    addr = core("getnewaddress", wallet_name="core")
    if core("getblockcount") < 101:
        core("generatetoaddress", 101, addr)
    print(f"  height  {core('getblockcount')}")

    se = SoftSE(pin=PIN)
    prov = wallet.provision(MNEMONIC, se, PIN,
                            script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh", "p2pkh"),
                            network=NETWORK)
    root = bip32.from_mnemonic(MNEMONIC)

    ms, members = None, None
    ms_cosigners = []
    import bip39
    others = [bip32.from_mnemonic(bip39.entropy_to_mnemonic(bytes([n]) * 16))
              for n in (0x41, 0x42)]
    members = [root] + others
    acct_path = wallet.multisig_account_path("multisig-p2wsh", 0, NETWORK)
    for i, r_ in enumerate(members):
        ms_cosigners.append(wallet.CoSigner(
            label=f"s{i}", fingerprint=r_.fingerprint().hex(), path=acct_path,
            xpub=r_.derive(acct_path).neutered().serialize("xpub")))
    ms = wallet.Multisig(label="regtest", threshold=2, cosigners=ms_cosigners,
                         sorted_keys=True, wrapped=False, network=NETWORK)
    prov.register_multisig(ms)

    dest = core("getnewaddress", wallet_name="core")

    cases = [("p2wpkh", None, None), ("p2sh-p2wpkh", None, None),
             ("p2pkh", None, None), ("p2tr", None, None),
             # Taproot with SIGHASH_ALL written out. Worth knowing what this
             # case can and cannot show: Core MINES a 64-byte signature made
             # over the DEFAULT digest, because the two spellings commit to
             # the same transaction and a 64-byte witness simply means
             # DEFAULT. So acceptance proves nothing here and the check below
             # reads the witness bytes instead. Verified to bite by reverting
             # the fix: 64 bytes, no flag.
             ("p2tr, explicit SIGHASH_ALL", None, 0x01),
             ("p2wsh 2-of-3", ms, None)]

    for label, quorum, sighash_type in cases:
        script_type = "p2wsh" if quorum else label.split(",")[0]
        print(f"\n {label}")
        try:
            spend_info = describe(root, script_type, 0, 0, quorum,
                                  members if quorum else None)
            change_info = describe(root, script_type, 1, 0, quorum,
                                   members if quorum else None)
            our_addr = addresses.script_to_address(spend_info["spk"], NETWORK)

            # Core funds the address our firmware derived. If our derivation
            # or our address encoding were wrong, the coins would land
            # somewhere we cannot spend and the rest would fail.
            fund_txid = core("sendtoaddress", our_addr, "0.01", wallet_name="core")
            core("generatetoaddress", 1, addr)
            raw = core("getrawtransaction", fund_txid, 2)
            vout = next(v["n"] for v in raw["vout"]
                        if v["scriptPubKey"]["hex"] == spend_info["spk"].hex())
            check("Core paid the address we derived", True)

            utxo = {"txid": fund_txid, "vout": vout, "amount": 1_000_000,
                    "parent_hex": core("getrawtransaction", fund_txid)}
            node = dict(spend_info)
            node["change_spk"] = change_info["spk"]
            node["change_origins"] = change_info["origins"]
            node["change_witness_script"] = change_info.get("witness_script")
            node["change_redeem"] = change_info.get("redeem")

            blob = build_psbt_for(utxo, node, script_type, dest, 600_000,
                                   395_000, sighash_type=sighash_type)

            se2 = SoftSE(pin=PIN)
            prov2 = wallet.provision(MNEMONIC, se2, PIN,
                                     script_types=("p2wpkh", "p2tr",
                                                   "p2sh-p2wpkh", "p2pkh"),
                                     network=NETWORK)
            if quorum:
                prov2.register_multisig(ms)

            shown: dict = {}
            result = wallet.sign_psbt(
                blob, prov2, se2, Policy(), FW, CAL,
                lambda lines: shown.setdefault("l", lines) is None or True,
                gate_ok, PIN, network=NETWORK)
            check("the firmware signed it", result.signatures >= 1)
            check("the change was recognised as ours",
                  any("your wallet" in ln for ln in shown["l"]))

            # For a 2-of-3 a second co-signer has to sign before it finalises.
            import base64
            signed_b64 = base64.b64encode(result.psbt).decode()
            if quorum:
                second = members[1]
                p2 = psbtmod.PSBT.parse(result.psbt)
                p2.descriptors = [ms.descriptor()]
                infos = [p2._input_info(0, second)]
                p2.sign(second, infos)
                signed_b64 = base64.b64encode(p2.serialize()).decode()

            # Core reads our PSBT. A format error shows up here.
            analysed = core("analyzepsbt", signed_b64)
            check("Core parses the PSBT we produced",
                  analysed.get("inputs") is not None)

            final = core("finalizepsbt", signed_b64)
            check("Core finalises it", final.get("complete") is True,
                  json.dumps(final)[:200])
            if not final.get("complete"):
                continue

            accept = core("testmempoolaccept", json.dumps([final["hex"]]))
            ok = accept[0].get("allowed") is True
            check("a node accepts it into the mempool", ok,
                  accept[0].get("reject-reason", ""))
            if not ok:
                continue

            # What the WITNESS ended up carrying. Core validates a 64-byte
            # taproot signature as SIGHASH_DEFAULT and a 65-byte one by its
            # trailing flag, and both commit to the same transaction -- so a
            # device that ignores a declared 0x01 and signs the DEFAULT digest
            # still produces a transaction Core mines. Acceptance therefore
            # proves nothing about this; only the bytes do.
            if sighash_type is not None and script_type == "p2tr":
                wit = Transaction.parse(bytes.fromhex(final["hex"])).vin[0].witness
                check(f"the witness is a {sighash_type:#04x} signature, "
                      f"65 bytes with the flag appended",
                      len(wit[0]) == 65 and wit[0][-1] == sighash_type,
                      f"{len(wit[0])} bytes, last={wit[0][-1] if wit[0] else None}")

            sent = core("sendrawtransaction", final["hex"])
            core("generatetoaddress", 1, addr)
            conf = core("getrawtransaction", sent, 2)
            check("it confirms in a block", conf.get("confirmations", 0) >= 1)

        except Exception as e:                                  # noqa: BLE001
            check(f"{label} round trip", False, f"{type(e).__name__}: {e}")

    print("\n" + "-" * 60)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS — every script type signed by the firmware was accepted and")
    print("mined by Bitcoin Core. Derivation, sighash, signature, witness")
    print("serialisation, PSBT encoding and standardness all agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
