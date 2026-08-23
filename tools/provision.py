#!/usr/bin/env python3
"""Provision a CELL device: choose a seed, wrap it, record the accounts.

Run once, with the case open, on the device itself. Everything this writes is
either encrypted or public.

    python3 tools/provision.py new  --out /boot/cell
    python3 tools/provision.py import --out /boot/cell
    python3 tools/provision.py show --dir /boot/cell

WHERE THE ENTROPY COMES FROM. `new` draws from os.urandom, which on Linux is
the kernel CSPRNG. On a device with an ATECC608B present the chip's hardware
RNG is mixed in as well — not because the kernel is suspect, but because two
independent sources mean a flaw in either one alone is survivable.

WRITE THE WORDS DOWN BEFORE YOU CONTINUE. They are shown once. There is no
"show me again" command and that is deliberate: a device that will reprint its
seed on demand is a device that will reprint it for whoever is holding it. If
you lose them, the coins are gone — the device's own copy is encrypted under a
key that dies with the chip.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

import bip39                                                    # noqa: E402
import duress                                                   # noqa: E402
import eth                                                      # noqa: E402
import seedstore                                                # noqa: E402
import signer                                                   # noqa: E402
import wallet                                                   # noqa: E402
from se import SoftSE                                           # noqa: E402

BLOB = "seed.blob"
ACCOUNTS = "accounts.json"


def _se(args):
    """The real chip if we are on the device, the stub if we are not."""
    if args.soft:
        print("! Using the SOFTWARE secure element. This is for rehearsal on a")
        print("! laptop only — it is not a security boundary, and a seed")
        print("! provisioned this way must never hold real funds.\n")
        return SoftSE(pin=args.pin, duress_pin=args.duress_pin)
    try:
        from se_atecc import ATECC608B
        return ATECC608B()
    except Exception as e:                                      # noqa: BLE001
        print(f"No usable ATECC608B: {e}\n")
        print("Re-run with --soft to rehearse without one, understanding that")
        print("the result must not hold real funds.")
        raise SystemExit(1)


def _entropy(nbytes: int, se) -> bytes:
    """Kernel randomness, XORed with the chip's if there is one.

    XOR of independent sources is at least as good as the better of them, so
    this cannot be worse than trusting one — which is the whole reason to do it.
    """
    kernel = os.urandom(nbytes)
    try:
        import cryptoauthlib as cal
        buf = bytearray(32)
        if cal.atcab_random(buf) == cal.Status.ATCA_SUCCESS:
            chip = bytes(buf) * ((nbytes // 32) + 1)
            print("  entropy: kernel CSPRNG XOR ATECC608B hardware RNG")
            return bytes(a ^ b for a, b in zip(kernel, chip[:nbytes]))
    except Exception:                                           # noqa: BLE001
        pass
    print("  entropy: kernel CSPRNG only")
    return kernel


def _confirm_words(mnemonic: str) -> None:
    """Make the owner prove they wrote the words down."""
    words = mnemonic.split()
    import random
    picks = sorted(random.SystemRandom().sample(range(len(words)), 3))
    print("\nNow put the paper away and answer three questions.")
    for i in picks:
        got = input(f"  word {i + 1}: ").strip().lower()
        if got != words[i]:
            print(f"\nThat is not word {i + 1}. Nothing has been written. "
                  f"Start again and copy the words exactly.")
            raise SystemExit(1)
    print("  ✓ backup confirmed\n")


def _refuse_if_present(args) -> None:
    """Check before generating, not after.

    Showing someone twenty-four words and then refusing to write them teaches
    them the words do not matter. The refusal has to come first.
    """
    blob = Path(args.out) / BLOB
    if blob.exists() and not args.force:
        print(f"{blob} already exists. Refusing to overwrite a seed without "
              f"--force. If you mean to replace the wallet on this device, "
              f"make sure you can still restore the old one first.")
        raise SystemExit(1)


def cmd_new(args) -> int:
    _refuse_if_present(args)
    se = _se(args)
    print("Generating a new seed.")
    strength = 32 if args.words == 24 else 16
    mnemonic = bip39.entropy_to_mnemonic(_entropy(strength, se))

    print(f"\n  YOUR {args.words} WORDS — write them on paper or steel NOW.")
    print("  They are shown once. This is the only copy you can restore from.\n")
    for i, w in enumerate(mnemonic.split(), 1):
        print(f"    {i:2}. {w}")
    if not args.no_confirm:
        _confirm_words(mnemonic)
    return _write(mnemonic, se, args)


def cmd_import(args) -> int:
    _refuse_if_present(args)
    se = _se(args)
    print("Restoring from an existing BIP-39 mnemonic.")
    mnemonic = input("  words: ").strip()
    if not bip39.validate(mnemonic):
        print("\nThat mnemonic fails its BIP-39 checksum. A word is wrong or")
        print("out of order. Nothing has been written.")
        return 1
    print("  ✓ checksum valid\n")
    return _write(mnemonic, se, args)


def _write(mnemonic: str, se, args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # The real chip has to be told the PIN before it can check one. There is no
    # change_pin anywhere: the wrapping key is derived from the PIN, so
    # changing it would strand the seed blob. Changing your PIN means
    # reprovisioning from the backup words, which is also the only path that
    # proves you still have them.
    if hasattr(se, "set_pin"):
        # Both PIN slots, always. The chip is written the same way whether or
        # not a duress PIN was asked for -- with none, slot 4 gets a secret
        # nobody can produce. See se_atecc.set_pin and duress.py.
        try:
            se.set_pin(args.pin, args.duress_pin)
        except TypeError:                                   # SoftSE, set at construction
            se.set_pin(args.pin)

    decoy = None
    if args.duress_pin:
        decoy = _decoy_mnemonic(args)

    prov = wallet.provision(mnemonic, se, args.pin, network=args.network,
                            duress_pin=args.duress_pin, decoy=decoy)

    (out / BLOB).write_bytes(prov.seed_pair.pack())
    (out / BLOB).chmod(0o600)
    _save(out, prov, args.network)

    # Prove the round trip before declaring success. Provisioning a device that
    # cannot reopen its own seed is the worst possible outcome here, and it is
    # cheap to rule out. This goes through verify_pin because the chip answers
    # the KDF only after one, and only once per one — the same path signing
    # takes, so what is proven here is what will happen later.
    stored = duress.SeedPair.unpack((out / BLOB).read_bytes())
    if not _reopens(se, stored, args.pin, mnemonic, "the seed"):
        return 1
    if args.duress_pin:
        # The decoy has to open too, and it has to open to the DECOY. A duress
        # PIN that silently opens the real wallet is worse than none at all.
        if not _reopens(se, stored, args.duress_pin, decoy, "the decoy seed"):
            return 1

    print(f"Written to {out}/")
    print(f"  {BLOB:<14} encrypted, {len(prov.seed_pair.pack())} bytes, "
          f"id {seedstore.fingerprint(prov.seed_pair.primary)}")
    print(f"  {ACCOUNTS:<14} watch-only, safe to copy")
    print(f"\n  master fingerprint {prov.master_fingerprint.hex()}")
    for a in prov.accounts:
        print(f"  {a.script_type:<12} {a.path:<20} {a.xpub[:20]}…")
    print("\n  ✓ seed re-read and verified")
    if not args.soft:
        print("\nNext: lock the ATECC608B config and data zones, seal the case,")
        print("and record the attestation pubkey (`python3 firmware/se_atecc.py")
        print("--probe`) with your co-signers.")
    return 0


def _reopens(se, stored, pin: str, expect: str, what: str) -> bool:
    """Prove the round trip before declaring success.

    Provisioning a device that cannot reopen its own seed is the worst possible
    outcome here, and it is cheap to rule out. This goes through verify_pin
    because the chip answers the KDF only after one, and only once per one --
    the same path signing takes, so what is proven here is what will happen
    later.
    """
    if not se.verify_pin(pin):
        print(f"\nFAIL — the secure element rejected a PIN it was just given.")
        return False
    try:
        reopened = duress.unwrap_any(stored, se.kdf(signer.unwrap_context(pin)))
    except duress.NoBlobOpened:
        print(f"\nFAIL — {what} was written but nothing reopens it. Nothing "
              f"about this device should be trusted; do not fund it.")
        return False
    good = bytes(reopened).decode() == bip39.normalise(expect)
    signer.zeroise(reopened)
    if not good:
        print(f"\nFAIL — {what} reads back as a different mnemonic than the "
              f"one that went in. Do not fund this device.")
    return good


def _decoy_mnemonic(args) -> str:
    """The wallet the duress PIN opens.

    THE DECOY HAS TO BE REAL, and that is a judgement this code cannot make --
    see duress.py. An empty wallet tells the coercer they were given the wrong
    PIN, which puts you back where you started and angrier. What this does is
    generate the words and make you write them down, because a decoy you
    cannot restore is a decoy you cannot fund.
    """
    print("\nThe duress PIN opens a SECOND wallet. Generating its seed.\n")
    words = bip39.entropy_to_mnemonic(os.urandom(32))
    print("  THE DECOY'S 24 WORDS — write them on separate paper NOW.\n")
    for i, w in enumerate(words.split(), 1):
        print(f"    {i:2}. {w}")
    print("\n  Fund this wallet with an amount that is plausible for you to")
    print("  hold and survivable to lose. An empty decoy protects nobody.")
    if not args.no_confirm:
        _confirm_words(words)
    return words


def _save(out: Path, prov: wallet.Provisioning, network: str) -> None:
    (out / ACCOUNTS).write_text(json.dumps({
        "master_fingerprint": prov.master_fingerprint.hex(),
        # The second wallet's watch-only half, written whether or not a duress
        # PIN was configured. Without it the device unwraps the decoy seed
        # after a reboot and then refuses to sign with it, because signing
        # checks the seed against a recorded fingerprint -- so duress would
        # work until the first power cycle and silently stop.
        "decoy_fingerprint": prov.decoy_fingerprint.hex(),
        "network": network,
        "accounts": [{"script_type": a.script_type, "path": a.path,
                      "xpub": a.xpub, "network": a.network}
                     for a in prov.accounts],
        "decoy_accounts": [{"script_type": a.script_type, "path": a.path,
                            "xpub": a.xpub, "network": a.network}
                           for a in prov.decoy_accounts],
        "multisig": [{"label": m.label, "threshold": m.threshold,
                      "sorted_keys": m.sorted_keys, "wrapped": m.wrapped,
                      "network": m.network,
                      "cosigners": [{"label": c.label, "fingerprint": c.fingerprint,
                                     "path": c.path, "xpub": c.xpub}
                                    for c in m.cosigners]}
                     for m in prov.multisig],
        "chains": [{"chain_id": cid, "name": nm, "ticker": tk}
                   for cid, (nm, tk) in sorted(prov.chains.items())],
    }, indent=2) + "\n")


class BadRecord(Exception):
    """The provisioning record could not be read.

    A distinct type so the boot path can tell "this card is damaged" from any
    other failure and say so on the screen, rather than dying with a traceback
    before a display exists. Nobody is standing at a serial console; they are
    holding a device that will not start.
    """


def load(d: Path) -> wallet.Provisioning:
    """Read a provisioned device's public record and its wrapped seed.

    Every failure in here becomes a BadRecord carrying a readable reason. The
    record lives on /boot/cell, so this is not an attack surface -- anyone who
    can edit it already holds the device. It is an availability one: a partial
    write during provisioning, or a bit flipped on an SD card that spent a year
    in a drawer, and the device stops booting. The seed is fine and the backup
    words still work; the device just has to say which of those two things has
    happened instead of exiting.
    """
    try:
        return _load(d)
    except BadRecord:
        raise
    except FileNotFoundError as e:
        raise BadRecord(f"{Path(e.filename).name} is missing from {d}") from None
    except json.JSONDecodeError as e:
        raise BadRecord(f"{ACCOUNTS} is not valid JSON (line {e.lineno})") from None
    except KeyError as e:
        raise BadRecord(f"{ACCOUNTS} has no {e.args[0]!r} field") from None
    except (TypeError, ValueError) as e:
        raise BadRecord(f"{ACCOUNTS} is malformed: {e}") from None


def _load(d: Path) -> wallet.Provisioning:
    data = json.loads((d / ACCOUNTS).read_text())
    prov = wallet.Provisioning(
        seed_pair=duress.SeedPair.unpack((d / BLOB).read_bytes()),
        master_fingerprint=bytes.fromhex(data["master_fingerprint"]),
        accounts=[wallet.Account(**a) for a in data["accounts"]],
        decoy_fingerprint=bytes.fromhex(data.get("decoy_fingerprint")
                                        or "00000000"),
        decoy_accounts=[wallet.Account(**a)
                        for a in data.get("decoy_accounts", [])])
    for m in data.get("multisig", []):
        prov.multisig.append(wallet.Multisig(
            label=m["label"], threshold=m["threshold"],
            sorted_keys=m["sorted_keys"], wrapped=m["wrapped"],
            network=m["network"],
            cosigners=[wallet.CoSigner(**c) for c in m["cosigners"]]))
    for c in data.get("chains", []):
        # Apply the owner's registrations to the signing module. Anything not
        # in here, or built in, is a chain the device refuses outright.
        eth.register_chain(c["chain_id"], c["name"], c["ticker"])
        prov.chains[c["chain_id"]] = (c["name"], c["ticker"])
    return prov


def cmd_multisig(args) -> int:
    """Register a quorum, from a file of co-signer xpubs.

    The file is one co-signer per line:

        label fingerprint path xpub

    Every co-signer has to be here, including this device — the whole point is
    that the device can rebuild the exact script your quorum produces, and it
    cannot do that from a subset. Take your own line from `provision.py show`.
    """
    d = Path(args.dir)
    prov = load(d)
    cosigners = []
    for n, line in enumerate(Path(args.cosigners).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 4:
            print(f"line {n}: expected `label fingerprint path xpub`, got "
                  f"{len(parts)} fields")
            return 1
        label, fp, path, xpub = parts
        cosigners.append(wallet.CoSigner(label=label, fingerprint=fp.lower(),
                                         path=path, xpub=xpub))

    ms = wallet.Multisig(label=args.label, threshold=args.threshold,
                         cosigners=cosigners, sorted_keys=not args.unsorted,
                         wrapped=args.wrapped, network=args.network)
    try:
        prov.register_multisig(ms)
    except wallet.WalletError as e:
        print(f"Refused: {e}")
        return 1

    _save(d, prov, args.network)
    print(f"Registered {ms.threshold}-of-{len(ms.cosigners)} {ms.label!r}"
          f"{' (p2sh-wrapped)' if ms.wrapped else ''}"
          f"{'' if ms.sorted_keys else ', unsorted keys'}")
    for c in ms.cosigners:
        mine = " <- this device" if c.fingerprint == prov.master_fingerprint.hex() else ""
        print(f"  {c.label:<12} {c.fingerprint}  {c.path}{mine}")
    print("\nThe device will now refuse any multisig input outside a registered")
    print("quorum, and will only call an output change when the whole quorum")
    print("rebuilds it. Register the same descriptor on every co-signer.")
    return 0


def cmd_chain(args) -> int:
    """Register an EVM chain by id, display name and native-token ticker.

    The device signs for the two chains it ships knowing — Ethereum and Sepolia
    — and refuses every other chain id until you run this. That refusal is the
    feature. The chain id is what the signature commits to, but the name and
    the ticker are what you read before you bleed, so they have to be your
    claim rather than something a coordinator handed the device along with the
    transaction it wants signed.

    Check the id yourself against a source you trust before you type it. A
    registration that names chain 1 "Sepolia" is a device that will take a
    blood gate for real money while telling you it is play money, and nothing
    downstream of this command can catch that for you.
    """
    d = Path(args.dir)
    prov = load(d)
    try:
        eth.register_chain(args.id, args.name, args.ticker)
    except eth.BadEthTransaction as e:
        print(f"Refused: {e}")
        return 1
    prov.chains[args.id] = (args.name, args.ticker)

    network = json.loads((d / ACCOUNTS).read_text())["network"]
    _save(d, prov, network)
    print(f"Registered chain {args.id} as {args.name!r}, denominated in "
          f"{args.ticker}.")
    print("\nConfirmation screens for this chain will now read:")
    print(f"  SEND ON {args.name.upper()}")
    print(f"  amount   1.5 {args.ticker}")
    print(f"  chain id {args.id}")
    print("\nRead that back. If the name or the ticker is wrong, it is wrong on")
    print("every transaction you will ever approve on this chain.")
    return 0


def cmd_show(args) -> int:
    d = Path(args.dir)
    data = json.loads((d / ACCOUNTS).read_text())
    print(f"master fingerprint  {data['master_fingerprint']}")
    print(f"seed blob           {seedstore.fingerprint((d / BLOB).read_bytes())}")
    for a in data["accounts"]:
        print(f"\n  {a['script_type']}  {a['path']}")
        print(f"  {a['xpub']}")
    for m in data.get("multisig", []):
        print(f"\n  quorum {m['label']}: {m['threshold']} of "
              f"{len(m['cosigners'])}")
        for c in m["cosigners"]:
            print(f"    {c['label']:<12} {c['fingerprint']}  {c['path']}")
    registered = data.get("chains", [])
    print("\n  EVM chains: Ethereum (ETH), Sepolia (test) (tETH)"
          + "".join(f", {c['name']} ({c['ticker']})" for c in registered))
    if not registered:
        print("  No chains registered beyond the built-in two; every other")
        print("  chain id is refused. Add one with `provision.py chain`.")
    print("\nThese are public. Give them to a coordinator to watch the wallet.")
    print("\nFor a multisig co-signer file, your line is:")
    for a in data["accounts"]:
        if a["script_type"].startswith("multisig"):
            print(f"  thisdevice {data['master_fingerprint']} {a['path']} {a['xpub']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn in (("new", cmd_new), ("import", cmd_import)):
        p = sub.add_parser(name)
        p.add_argument("--out", default="/boot/cell")
        p.add_argument("--pin", required=True)
        p.add_argument("--duress-pin", default=None,
                       help="a second PIN that opens a second wallet. Read "
                            "firmware/duress.py before using this — an "
                            "unfunded decoy protects nobody")
        p.add_argument("--network", default="mainnet",
                       choices=["mainnet", "testnet", "regtest"])
        p.add_argument("--soft", action="store_true",
                       help="rehearse without the ATECC608B (never for real funds)")
        p.add_argument("--force", action="store_true")
        p.add_argument("--no-confirm", action="store_true",
                       help="skip the write-it-down check (testing only)")
        if name == "new":
            p.add_argument("--words", type=int, default=24, choices=[12, 24])
        p.set_defaults(fn=fn)

    p = sub.add_parser("show")
    p.add_argument("--dir", default="/boot/cell")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("multisig", help="register a quorum")
    p.add_argument("--dir", default="/boot/cell")
    p.add_argument("--label", required=True)
    p.add_argument("--threshold", type=int, required=True)
    p.add_argument("--cosigners", required=True,
                   help="file of `label fingerprint path xpub` lines")
    p.add_argument("--network", default="mainnet",
                   choices=["mainnet", "testnet", "regtest"])
    p.add_argument("--wrapped", action="store_true", help="p2sh-p2wsh")
    p.add_argument("--unsorted", action="store_true",
                   help="do NOT sort keys (BIP-67 is the default)")
    p.set_defaults(fn=cmd_multisig)

    p = sub.add_parser("chain", help="register an EVM chain the device may sign for")
    p.add_argument("--dir", default="/boot/cell")
    p.add_argument("--id", type=int, required=True, help="EIP-155 chain id")
    p.add_argument("--name", required=True,
                   help='shown as "SEND ON <NAME>", e.g. "Arbitrum One"')
    p.add_argument("--ticker", required=True,
                   help="native token symbol, e.g. ETH or POL")
    p.set_defaults(fn=cmd_chain)

    args = ap.parse_args()
    if getattr(args, "pin", None) is not None and not args.pin.isdigit():
        print("The PIN must be digits — it is entered on four buttons.")
        return 1
    if getattr(args, "duress_pin", None) is not None:
        if not args.duress_pin.isdigit():
            print("The duress PIN must be digits too.")
            return 1
        if args.duress_pin == args.pin:
            print("The duress PIN must differ from the normal one.")
            return 1
    for label in ("pin", "duress_pin"):
        value = getattr(args, label, None)
        if value is not None and len(value) < 8:
            print("Use at least eight digits. Ten attempts is a firmware rule;")
            print("what the chip enforces is that its counter stops at")
            print("2,097,151 uses, so a keyspace smaller than that is one an")
            print("attacker with their own firmware can walk through. 10^6")
            print("fits inside it and 10^8 does not. See se_atecc.py.")
            return 1
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
