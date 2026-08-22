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
        return SoftSE(pin=args.pin)
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
    prov = wallet.provision(mnemonic, se, args.pin, network=args.network)

    (out / BLOB).write_bytes(prov.seed_blob)
    (out / BLOB).chmod(0o600)
    _save(out, prov, args.network)

    # Prove the round trip before declaring success. Provisioning a device that
    # cannot reopen its own seed is the worst possible outcome here, and it is
    # cheap to rule out. This goes through verify_pin because the chip answers
    # the KDF only after one, and only once per one — the same path signing
    # takes, so what is proven here is what will happen later.
    if not se.verify_pin(args.pin):
        print("\nFAIL — the secure element rejected the PIN it was just given.")
        return 1
    reopened = seedstore.unwrap((out / BLOB).read_bytes(),
                                se.kdf(signer.unwrap_context(args.pin)))
    if bytes(reopened).decode() != bip39.normalise(mnemonic):
        print("\nFAIL — the seed was written but does not read back. Nothing "
              "about this device should be trusted; do not fund it.")
        return 1
    signer.zeroise(reopened)

    print(f"Written to {out}/")
    print(f"  {BLOB:<14} encrypted, {len(prov.seed_blob)} bytes, "
          f"id {seedstore.fingerprint(prov.seed_blob)}")
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


def _save(out: Path, prov: wallet.Provisioning, network: str) -> None:
    (out / ACCOUNTS).write_text(json.dumps({
        "master_fingerprint": prov.master_fingerprint.hex(),
        "network": network,
        "accounts": [{"script_type": a.script_type, "path": a.path,
                      "xpub": a.xpub, "network": a.network}
                     for a in prov.accounts],
        "multisig": [{"label": m.label, "threshold": m.threshold,
                      "sorted_keys": m.sorted_keys, "wrapped": m.wrapped,
                      "network": m.network,
                      "cosigners": [{"label": c.label, "fingerprint": c.fingerprint,
                                     "path": c.path, "xpub": c.xpub}
                                    for c in m.cosigners]}
                     for m in prov.multisig],
    }, indent=2) + "\n")


def load(d: Path) -> wallet.Provisioning:
    """Read a provisioned device's public record and its wrapped seed."""
    data = json.loads((d / ACCOUNTS).read_text())
    prov = wallet.Provisioning(
        seed_blob=(d / BLOB).read_bytes(),
        master_fingerprint=bytes.fromhex(data["master_fingerprint"]),
        accounts=[wallet.Account(**a) for a in data["accounts"]])
    for m in data.get("multisig", []):
        prov.multisig.append(wallet.Multisig(
            label=m["label"], threshold=m["threshold"],
            sorted_keys=m["sorted_keys"], wrapped=m["wrapped"],
            network=m["network"],
            cosigners=[wallet.CoSigner(**c) for c in m["cosigners"]]))
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

    args = ap.parse_args()
    if getattr(args, "pin", None) is not None and not args.pin.isdigit():
        print("The PIN must be digits — it is entered on four buttons.")
        return 1
    if getattr(args, "pin", None) is not None and len(args.pin) < 6:
        print("Use at least six digits. The chip allows ten attempts before it")
        print("wipes, so a short PIN is the weakest link in the whole device.")
        return 1
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
