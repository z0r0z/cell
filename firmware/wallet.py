"""The wallet layer — where the unlock chain finally meets a real key.

signer.py has always taken `unwrap_seed` and `sign_digest` as injected
callables, so the unlock chain could be tested without a seed. This file
supplies them for real, and adds nothing to the chain: the order in
signer.EXPECTED_ORDER still governs, the gate still runs before the unwrap,
and the seed still exists as a mutable buffer that is zeroised on every path
out — including the ones that raise.

Two entry points, one per chain:

    sign_psbt   Bitcoin. The PSBT is analysed BEFORE anything is unlocked, so
                what the owner confirms is computed from their own seed's
                public keys, and the seed itself is only unwrapped after they
                have confirmed and the gate has passed.
    sign_eth    Ethereum. The transaction is built on the device from
                displayed fields, and the digest is computed from what was
                built rather than accepted from the host.

WATCH-ONLY FIRST. Both entry points need the account's public keys to decide
what to display — which change is ours, which address is ours. Those come from
an account xpub recorded at provisioning, never from the seed, so the device
can prepare and display a whole transaction while the seed is still encrypted.
The seed is unwrapped for the milliseconds between the gate passing and the
signature existing, and not one moment earlier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import bip32
import bip39
import eth
import ops
import psbt as psbtmod
import seedstore
import signer
from bip32 import ExtendedKey
from policy import Policy, Tier
from se import SecureElement

# BIP-44 purpose numbers, and what each one means for the script we build.
PURPOSE = {"p2pkh": 44, "p2sh-p2wpkh": 49, "p2wpkh": 84, "p2tr": 86}
COIN = {"mainnet": 0, "testnet": 1, "regtest": 1}

# BIP-48 multisig accounts. The last hardened element names the script type:
# 1' for p2sh-p2wsh, 2' for native p2wsh. Every coordinator worth using
# follows this, and using our own scheme would mean an xpub nobody else could
# pair with.
MULTISIG_SCRIPT = {"multisig-p2sh-p2wsh": 1, "multisig-p2wsh": 2}

# Ethereum's registered coin type. The account level is hardened, and the
# address index lives at m/44'/60'/account'/0/index like every other wallet,
# so the same words restore in MetaMask.
ETH_COIN = 60


class WalletError(Exception):
    """Something the wallet refuses to do, phrased for the owner."""


def account_path(script_type: str, account: int = 0,
                 network: str = "mainnet") -> str:
    if script_type not in PURPOSE:
        raise WalletError(f"unknown script type {script_type!r}")
    return f"m/{PURPOSE[script_type]}h/{COIN[network]}h/{account}h"


def multisig_account_path(script_type: str, account: int = 0,
                          network: str = "mainnet") -> str:
    """BIP-48: m/48'/coin'/account'/script'."""
    if script_type not in MULTISIG_SCRIPT:
        raise WalletError(f"unknown multisig script type {script_type!r}")
    return (f"m/48h/{COIN[network]}h/{account}h/"
            f"{MULTISIG_SCRIPT[script_type]}h")


def eth_path(account: int = 0, index: int = 0) -> str:
    return f"m/44h/{ETH_COIN}h/{account}h/0/{index}"


@dataclass
class Account:
    """A watch-only account. Everything the device shows comes from here."""

    script_type: str
    path: str
    xpub: str
    network: str = "mainnet"

    def key(self) -> ExtendedKey:
        node = ExtendedKey.deserialize(self.xpub)
        if node.seckey is not None:
            raise WalletError("an account record must hold a public key only")
        return node


@dataclass
class CoSigner:
    """One party to a multisig, as recorded on this device.

    The label is what appears on the confirmation screen. It is for the owner's
    benefit and carries no authority — the fingerprint and xpub are what the
    device actually checks against.
    """

    label: str
    fingerprint: str                    # hex, 8 chars
    path: str                           # the account path this xpub sits at
    xpub: str

    def key(self) -> ExtendedKey:
        node = ExtendedKey.deserialize(self.xpub)
        if node.seckey is None:
            return node
        raise WalletError("a co-signer record must hold a public key only")


@dataclass
class Multisig:
    """A registered quorum. See psbt.MultisigDescriptor for why this exists."""

    label: str
    threshold: int
    cosigners: list[CoSigner]
    sorted_keys: bool = True
    wrapped: bool = False
    network: str = "mainnet"

    def descriptor(self) -> psbtmod.MultisigDescriptor:
        return psbtmod.MultisigDescriptor(
            threshold=self.threshold,
            keys=[(bytes.fromhex(c.fingerprint), bip32.parse_path(c.path), c.key())
                  for c in self.cosigners],
            sorted_keys=self.sorted_keys, wrapped=self.wrapped, label=self.label)

    def check(self) -> None:
        n = len(self.cosigners)
        if not 1 <= self.threshold <= n <= 16:
            raise WalletError(
                f"{self.threshold}-of-{n} is not a usable quorum")
        fps = [c.fingerprint for c in self.cosigners]
        if len(set(fps)) != len(fps):
            raise WalletError(
                "two co-signers share a master fingerprint. The device matches "
                "PSBT key origins on that fingerprint, so it could not tell "
                "them apart.")
        for c in self.cosigners:
            got = c.key().fingerprint().hex()
            # The recorded fingerprint is the MASTER's, and an account xpub
            # cannot prove what its master was. What we can check is that the
            # record is self-consistent and the xpub parses as public-only.
            del got


@dataclass
class Provisioning:
    """What the device knows about itself between power cycles.

    None of it is secret. The seed blob is encrypted, and the accounts are
    watch-only — this record can be backed up in the clear.
    """

    seed_blob: bytes
    accounts: list[Account] = field(default_factory=list)
    master_fingerprint: bytes = b"\x00\x00\x00\x00"
    multisig: list[Multisig] = field(default_factory=list)
    # EVM chains the owner registered, {chain_id: (name, ticker)}. Applied to
    # eth.CHAINS when the record is loaded; see tools/provision.py chain.
    chains: dict[int, tuple[str, str]] = field(default_factory=dict)

    def descriptors(self, network: str = "mainnet") -> list:
        return [m.descriptor() for m in self.multisig if m.network == network]

    def register_multisig(self, ms: Multisig) -> None:
        """Add a quorum, refusing one this device is not a member of.

        A device that will register a quorum it has no key in is a device that
        will call somebody else's address its own change.
        """
        ms.check()
        mine = self.master_fingerprint.hex()
        ours = [c for c in ms.cosigners if c.fingerprint == mine]
        if not ours:
            raise WalletError(
                f"this device's fingerprint ({mine}) is not among the "
                f"co-signers. Registering a quorum you are not in would let it "
                f"be treated as your own change.")
        # And the xpub filed under our fingerprint has to be one this seed
        # actually produced. Otherwise a coordinator could register a quorum
        # that merely claims to include us.
        want = {a.xpub for a in self.accounts if a.network == ms.network}
        for c in ours:
            if c.xpub not in want:
                raise WalletError(
                    f"the co-signer entry for this device quotes an xpub this "
                    f"seed does not derive at {c.path}. Take your xpub from "
                    f"`provision.py show`, not from the coordinator.")
        if any(m.label == ms.label for m in self.multisig):
            raise WalletError(f"a quorum labelled {ms.label!r} is already registered")
        self.multisig.append(ms)

    def account_for(self, script_type: str, network: str = "mainnet") -> Account:
        for a in self.accounts:
            if a.script_type == script_type and a.network == network:
                return a
        raise WalletError(
            f"this device has no {script_type} account on {network}. "
            f"Provision one before asking it to sign for that script type.")


def provision(mnemonic: str, se: SecureElement, pin: str,
              script_types: tuple[str, ...] = ("p2wpkh", "p2tr", "p2sh-p2wpkh"),
              network: str = "mainnet") -> Provisioning:
    """Wrap a seed and record the watch-only accounts that go with it.

    Called once, by tools/provision.py, with the device open. The mnemonic is
    validated first: a phrase that fails its checksum would restore nowhere,
    and discovering that during a recovery is discovering it too late.
    """
    if not bip39.validate(mnemonic):
        raise WalletError(
            "that mnemonic fails its BIP-39 checksum. A word is wrong or out "
            "of order — fix it now, because a backup that does not restore is "
            "not a backup.")
    root = bip32.from_mnemonic(mnemonic)
    # The secure element hands out a wrapping key only after a successful PIN,
    # and only once per PIN. Provisioning is no exception: a path that could
    # reach the KDF without the counter being spent would be a path around the
    # counter, which is the whole reason the part is in the design.
    if not se.verify_pin(pin):
        raise WalletError("that PIN was not accepted by the secure element")
    key = se.kdf(signer.unwrap_context(pin))
    blob = seedstore.wrap(mnemonic, key)

    accounts = []
    for st in MULTISIG_SCRIPT:
        # Derived at provisioning whether or not a quorum is ever registered.
        # The xpub is what a co-signer needs from you to build the descriptor,
        # and asking the owner to re-open a sealed device to get it would be a
        # design that punishes doing multisig properly.
        path = multisig_account_path(st, 0, network)
        accounts.append(Account(script_type=st, path=path,
                                xpub=root.derive(path).neutered().serialize("xpub"),
                                network=network))
    for st in script_types:
        path = account_path(st, 0, network)
        node = root.derive(path)
        accounts.append(Account(script_type=st, path=path,
                                xpub=node.neutered().serialize("xpub"),
                                network=network))
    accounts.append(Account(script_type="eth", path=f"m/44h/{ETH_COIN}h/0h",
                            xpub=root.derive(f"m/44h/{ETH_COIN}h/0h")
                            .neutered().serialize("xpub"),
                            network="ethereum"))
    return Provisioning(seed_blob=blob.pack(), accounts=accounts,
                        master_fingerprint=root.fingerprint())


# --------------------------------------------------------------------------
# Seed handling
# --------------------------------------------------------------------------


def _root_from(seed_words: bytearray) -> ExtendedKey:
    """Expand the unwrapped mnemonic into a root key.

    signer.py owns the lifetime of `seed_words` and zeroises it on every path
    out, including the ones that raise. What this function creates in between —
    the 64-byte BIP-39 seed and the derived private keys — are immutable
    `bytes`, which Python gives no way to overwrite. signer.zeroise documents
    the same limitation. The mitigation is the same one the rest of the design
    uses: the window is short, the device is airgapped, and the case is sealed.
    """
    return ExtendedKey.from_seed(bip39.to_seed(bytes(seed_words).decode("utf-8")))


# --------------------------------------------------------------------------
# Bitcoin
# --------------------------------------------------------------------------


@dataclass
class SignedPSBT:
    psbt: bytes
    attestation: bytes
    tier: Tier
    display: list[str]
    signatures: int


def sign_psbt(blob: bytes, prov: Provisioning, se: SecureElement,
              pol: Policy, fw_hash: bytes, cal_hash: bytes,
              confirm, run_gate, pin: str,
              network: str = "mainnet",
              requested_tier: Tier | None = None,
              attach_attestation: bool = True) -> SignedPSBT:
    """Run the full unlock chain over a PSBT and return it signed."""
    p = psbtmod.PSBT.parse(blob)
    # The registered quorums travel with the PSBT object, because every
    # "is this ours?" question in psbt.py is answered against them.
    p.descriptors = prov.descriptors(network)

    # Analyse against the watch-only keys. This is what makes it possible to
    # display the transaction — including which output is really our change —
    # without the seed being anywhere in memory yet.
    watch = _watch_root(prov, network)
    infos = [p._input_info(i, watch) for i in range(len(p.tx.vin))]
    summary = p.summarize(watch, network)
    if summary.signable == 0:
        raise WalletError(
            "this PSBT contains no input this device holds a key for. Nothing "
            "would be signed, so nothing is asked of you.")

    digest = p.signing_digest(infos)

    signed_count = {"n": 0}

    # signer.py hands us the unwrapped seed buffer and the digest it bound the
    # attestation to. The real signing happens here, over the PSBT itself.
    def sign_digest(seed: bytearray, bound: bytes) -> bytes:
        if bound != digest:
            raise WalletError("the digest changed between display and signing")
        root = _root_from(seed)
        if root.fingerprint() != prov.master_fingerprint:
            raise WalletError(
                "the unwrapped seed does not match this device's recorded "
                "master fingerprint; refusing to sign with an unexpected key")
        fresh = [p._input_info(i, root) for i in range(len(p.tx.vin))]
        n = p.sign(root, fresh)
        if n == 0:
            raise WalletError("no input could be signed after unlocking")
        signed_count["n"] = n
        return b"".join(
            v for m in p.inputs for k, v in sorted(m.items())
            if k[:1] in (bytes([psbtmod.IN_PARTIAL_SIG]),
                         bytes([psbtmod.IN_TAP_KEY_SIG])))

    def unwrap_seed(key: bytes) -> bytearray:
        return seedstore.unwrap(prov.seed_blob, key)

    s = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                      confirm=confirm, run_gate=run_gate,
                      unwrap_seed=unwrap_seed, sign_digest=sign_digest)
    result = s.authorize_and_sign(
        signer.SignRequest(operation=summary.spend, sighash=digest,
                           requested_tier=requested_tier), pin)

    if attach_attestation:
        identifier, subtype, value = result.psbt_proprietary()
        p.set_proprietary(identifier, subtype, value)

    return SignedPSBT(psbt=p.serialize(),
                      attestation=result.attestation.pack(),
                      tier=result.tier, display=result.display,
                      signatures=signed_count["n"])


def _watch_root(prov: Provisioning, network: str) -> ExtendedKey:
    """A synthetic root that answers owns() for our accounts.

    An account xpub sits at depth 3, so paths inside a PSBT — which are quoted
    from the master — cannot be walked from it directly. This wrapper walks the
    account's own suffix instead, and refuses anything outside it.
    """
    accounts = [a for a in prov.accounts if a.network == network]
    if not accounts:
        raise WalletError(f"no accounts provisioned for {network}")
    return _AccountRoot(accounts, prov.master_fingerprint)


class _AccountRoot(ExtendedKey):
    """Presents several account xpubs behind one master-rooted interface."""

    def __init__(self, accounts: list[Account], fingerprint: bytes):
        self._accounts = [(bip32.parse_path(a.path), a.key()) for a in accounts]
        self._fp = fingerprint
        first = self._accounts[0][1]
        super().__init__(chain_code=first.chain_code, pubkey=first.pubkey,
                         seckey=None, depth=first.depth,
                         parent_fp=first.parent_fp, index=first.index)

    def fingerprint(self) -> bytes:
        return self._fp

    def derive(self, path):
        want = bip32.parse_path(path) if isinstance(path, str) else list(path)
        for prefix, node in self._accounts:
            if want[:len(prefix)] == prefix:
                return node.derive(want[len(prefix):])
        raise bip32.BadPath(
            f"path {bip32.format_path(want)} is outside every account this "
            f"device was provisioned with")


# --------------------------------------------------------------------------
# Ethereum
# --------------------------------------------------------------------------


@dataclass
class SignedEth:
    raw: bytes
    txid: str
    sender: str
    attestation: bytes
    tier: Tier
    display: list[str]


def sign_eth(tx: eth.EthTransaction, prov: Provisioning, se: SecureElement,
             pol: Policy, fw_hash: bytes, cal_hash: bytes,
             confirm, run_gate, pin: str, index: int = 0,
             requested_tier: Tier | None = None) -> SignedEth:
    """Run the unlock chain over an EIP-1559 transaction."""
    account = prov.account_for("eth", "ethereum")
    watch = account.key().derive([0, index])
    from addresses import eth_address
    from_addr = eth_address(watch.pubkey)

    op = ops.EthereumSpend(amount_wei=tx.value, destination=tx.to,
                           chain_id=tx.chain_id, chain_name=tx.chain_name(),
                           ticker=tx.ticker(),
                           nonce=tx.nonce, max_fee_wei=tx.max_fee_wei())
    digest = tx.sighash()
    out: dict = {}

    def sign_digest(seed: bytearray, bound: bytes) -> bytes:
        if bound != digest:
            raise WalletError("the digest changed between display and signing")
        root = _root_from(seed)
        node = root.derive(eth_path(0, index))
        if node.pubkey != watch.pubkey:
            raise WalletError(
                "the unwrapped seed derives a different sending address than "
                "the one displayed; refusing to sign")
        assert node.seckey is not None
        r, s_, y = eth.sign(tx, node.seckey)
        out["raw"] = tx.encode_signed(r, s_, y)
        out["txid"] = tx.txid(r, s_, y)
        out["sender"] = eth.sender(tx, r, s_, y)
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([y])

    def unwrap_seed(key: bytes) -> bytearray:
        return seedstore.unwrap(prov.seed_blob, key)

    s = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                      confirm=confirm, run_gate=run_gate,
                      unwrap_seed=unwrap_seed, sign_digest=sign_digest)
    result = s.authorize_and_sign(
        signer.SignRequest(operation=op, sighash=digest,
                           requested_tier=requested_tier), pin)

    if out["sender"] != from_addr:
        raise WalletError("signed transaction recovers to an unexpected sender")
    return SignedEth(raw=out["raw"], txid=out["txid"], sender=out["sender"],
                     attestation=result.attestation.pack(), tier=result.tier,
                     display=result.display)
