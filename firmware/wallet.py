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

import hmac
from dataclasses import dataclass, field

import bip32
import beacon
import bip39
import duress
import eip712
import eth
import ops
import psbt as psbtmod
import secp256k1 as ec
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

    None of it is secret. The seed store is encrypted, and the accounts are
    watch-only — this record can be backed up in the clear.
    """

    # Both wrapped seeds, always. Which one a PIN opens is decided by which
    # key it derives, and nothing here knows or needs to know which is the
    # decoy — see duress.py. A device with no duress PIN configured still
    # carries a second blob, under a key nobody can produce.
    seed_pair: "duress.SeedPair"
    accounts: list[Account] = field(default_factory=list)
    master_fingerprint: bytes = b"\x00\x00\x00\x00"
    # The chain this device was provisioned for. Recorded because every
    # account is recorded against it and NOTHING else can recover it at boot:
    # a device provisioned for testnet whose loop defaults to mainnet finds no
    # accounts, cannot show a receive address, and cannot sign -- it is simply
    # a brick with a confusing error. app.load_device reads it from here.
    network: str = "mainnet"
    # The second wallet's watch-only half. Present whether or not a duress PIN
    # was configured, for the same reason the second blob is: a record that
    # appears only on devices with a decoy is a record that announces them.
    # Which of the two a spend is for is read off the PSBT, not off the PIN —
    # see _watch_root(). Nothing here is secret; both halves are xpubs.
    decoy_accounts: list[Account] = field(default_factory=list)
    decoy_fingerprint: bytes = b"\x00\x00\x00\x00"
    multisig: list[Multisig] = field(default_factory=list)
    # EVM chains the owner registered, {chain_id: (name, ticker)}. Applied to
    # eth.CHAINS when the record is loaded; see tools/provision.py chain.
    chains: dict[int, tuple[str, str]] = field(default_factory=dict)
    # Smart accounts the owner registered, and the implementations they run.
    # Applied to eip712.ACCOUNTS when the record is loaded; see
    # tools/provision.py smart-account. Recorded rather than accepted from a
    # payload because an EIP-712 signature is bound to a verifyingContract,
    # and an attacker who picks that address picks which account is spent from.
    smart_accounts: list["eip712.SmartAccount"] = field(default_factory=list)

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
        # Compared on the key material, not on the string. xpub, zpub and
        # tpub are three spellings of the same extended key, differing only in
        # four version bytes that say which script type and network a wallet
        # meant -- so a coordinator that hands back a different spelling of
        # OUR OWN key is not quoting a key we do not derive.
        def _material(x: str):
            n = ExtendedKey.deserialize(x)
            return (n.chain_code, n.pubkey)

        want = {_material(a.xpub)
                for a in self.accounts if a.network == ms.network}
        if not want:
            # The commonest way to land here is a forgotten --network, not a
            # bad xpub. Saying "this seed does not derive that xpub" sends
            # somebody hunting a key that was correct all along.
            raise WalletError(
                f"this device has no accounts on {ms.network}; it was "
                f"provisioned for "
                f"{', '.join(sorted({a.network for a in self.accounts})) or 'nothing'}. "
                f"Register the quorum on the network this device is on.")
        for c in ours:
            try:
                got = _material(c.xpub)
            except ValueError as e:
                raise WalletError(
                    f"the co-signer entry for this device does not carry a "
                    f"readable extended key ({e})") from None
            if got not in want:
                raise WalletError(
                    f"the co-signer entry for this device quotes an xpub this "
                    f"seed does not derive at {c.path} on {ms.network}. Take "
                    f"your xpub from `provision.py show`, not from the "
                    f"coordinator.")
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
              network: str = "mainnet",
              duress_pin: str | None = None,
              decoy: str | None = None,
              chamber: "bytes | None" = None) -> Provisioning:
    """Wrap a seed and record the watch-only accounts that go with it.

    Called once, by tools/provision.py, with the device open. The mnemonic is
    validated first: a phrase that fails its checksum would restore nowhere,
    and discovering that during a recovery is discovering it too late.

    TWO SEEDS ARE ALWAYS WRAPPED, whether or not a duress PIN was asked for.
    With one, the second seed is the decoy and `duress_pin` opens it. Without
    one, the second seed is a real 24-word mnemonic wrapped under a key derived
    from a PIN nobody can enter, and it is unreachable forever. The device is
    byte-for-byte the same shape either way, which is the entire mechanism —
    see duress.py. A build that wrote one blob when duress was off would
    announce, to anyone holding the card, exactly which devices have something
    to hide.

    `chamber` is the optical PUF key, on devices that enrolled one. It goes
    into BOTH wrapping keys, so a decoy wallet is bound to the instrument on
    the same terms as the real one -- a duress blob that survived opening the
    case would be a tell about which blob is which.
    """
    if not bip39.validate(mnemonic):
        raise WalletError(
            "that mnemonic fails its BIP-39 checksum. A word is wrong or out "
            "of order — fix it now, because a backup that does not restore is "
            "not a backup.")
    if duress_pin is not None and duress_pin == pin:
        raise WalletError("the duress PIN must differ from the normal one")
    root = bip32.from_mnemonic(mnemonic)
    # The secure element hands out a wrapping key only after a successful PIN,
    # and only once per PIN. Provisioning is no exception: a path that could
    # reach the KDF without the counter being spent would be a path around the
    # counter, which is the whole reason the part is in the design.
    if not se.verify_pin(pin):
        raise WalletError("that PIN was not accepted by the secure element")
    key = se.kdf(signer.unwrap_context(pin, chamber))

    if duress_pin is not None:
        if not se.verify_pin(duress_pin):
            raise WalletError(
                "that duress PIN was not accepted by the secure element. It "
                "has to be set on the chip before provisioning — see "
                "se_atecc.set_pin.")
        duress_key = se.kdf(signer.unwrap_context(duress_pin, chamber))
    else:
        # No PIN derives this. The second blob is real, well-formed and
        # permanently unopenable, which is what makes its presence say nothing.
        import os
        duress_key = os.urandom(32)
    decoy = decoy or duress.decoy_mnemonic()
    pair = duress.wrap_pair(mnemonic, decoy, key, duress_key)

    # A device provisioned for testnet must not hand out mainnet-flavoured
    # keys. A coordinator reads the version bytes, returns the tpub it built
    # the descriptor from, and register_multisig's string comparison then said
    # "this seed does not derive that xpub" about a key that was correct all
    # along.
    pfx = "tpub" if COIN[network] == 1 else "xpub"
    accounts = []
    for st in MULTISIG_SCRIPT:
        # Derived at provisioning whether or not a quorum is ever registered.
        # The xpub is what a co-signer needs from you to build the descriptor,
        # and asking the owner to re-open a sealed device to get it would be a
        # design that punishes doing multisig properly.
        path = multisig_account_path(st, 0, network)
        accounts.append(Account(script_type=st, path=path,
                                xpub=root.derive(path).neutered().serialize(pfx),
                                network=network))
    for st in script_types:
        path = account_path(st, 0, network)
        node = root.derive(path)
        accounts.append(Account(script_type=st, path=path,
                                xpub=node.neutered().serialize(pfx),
                                network=network))
    accounts.append(Account(script_type="eth", path=f"m/44h/{ETH_COIN}h/0h",
                            xpub=root.derive(f"m/44h/{ETH_COIN}h/0h")
                            .neutered().serialize("xpub"),
                            network="ethereum"))
    # The decoy's watch-only half, derived the same way. Without it the device
    # can unwrap the decoy seed and then refuse to sign with it, because
    # sign_digest checks the unwrapped seed against a recorded fingerprint —
    # which is exactly what happened the first time duress was wired through.
    decoy_root = bip32.from_mnemonic(decoy)
    decoy_accounts = [
        Account(script_type=a.script_type, path=a.path,
                xpub=decoy_root.derive(a.path).neutered().serialize(
                    pfx if a.network != "ethereum" else "xpub"),
                network=a.network)
        for a in accounts]
    return Provisioning(seed_pair=pair, accounts=accounts,
                        master_fingerprint=root.fingerprint(),
                        decoy_accounts=decoy_accounts,
                        decoy_fingerprint=decoy_root.fingerprint(),
                        network=network)


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
              attach_attestation: bool = True,
              read_chamber=None) -> SignedPSBT:
    """Run the full unlock chain over a PSBT and return it signed."""
    p = psbtmod.PSBT.parse(blob)
    # The registered quorums travel with the PSBT object, because every
    # "is this ours?" question in psbt.py is answered against them.
    p.descriptors = prov.descriptors(network)

    # Analyse against the watch-only keys. This is what makes it possible to
    # display the transaction — including which output is really our change —
    # without the seed being anywhere in memory yet.
    quoted = p.quoted_fingerprints()
    watch = _watch_root(prov, network, quoted)
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
        # The seed that opened has to be the one this PSBT is for. Both of the
        # device's wallets are legitimate; a seed matching NEITHER means the
        # blob and the record disagree, and signing then would sign with a key
        # nobody provisioned.
        if root.fingerprint() != watch.fingerprint():
            raise WalletError(
                "the unwrapped seed does not match this device's recorded "
                "master fingerprint; refusing to sign with an unexpected key")
        fresh = [p._input_info(i, root) for i in range(len(p.tx.vin))]
        # And the inputs it signs have to be the inputs it showed. Everything
        # above ran against `watch`, an _AccountRoot that refuses any path
        # outside a provisioned account on this network; `root` is the real
        # master and derives ANYTHING. So the unwrap can find inputs the
        # summary counted as foreign -- including one at the Ethereum account
        # path -- and sign them under a digest the attestation does not cover.
        # `bound != digest` above cannot see it: both sides of that comparison
        # were computed before the seed opened.
        if p.signing_digest(fresh) != digest:
            raise WalletError(
                "the unwrapped seed signs a different set of inputs than the "
                "summary the owner approved and the attestation is bound to; "
                "refusing to sign")
        n = p.sign(root, fresh)
        if n == 0:
            raise WalletError("no input could be signed after unlocking")
        signed_count["n"] = n
        return b"".join(
            v for m in p.inputs for k, v in sorted(m.items())
            if k[:1] in (bytes([psbtmod.IN_PARTIAL_SIG]),
                         bytes([psbtmod.IN_TAP_KEY_SIG])))

    def unwrap_seed(key: bytes) -> bytearray:
        try:
            return duress.unwrap_any(prov.seed_pair, key)
        except (duress.NoBlobOpened, seedstore.SeedStoreError) as e:
            # Neither derives from ValueError, so both used to travel all the
            # way up to app.main's catch-all and paint a Python class name at
            # somebody holding a lancet. The owner needs to know it is not
            # their words.
            raise WalletError(
                f"the seed store did not open with the key this PIN derives "
                f"({e}). Nothing is wrong with your recovery words; the store "
                f"on this card and the chip in this device disagree.") from None

    s = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                      confirm=confirm, run_gate=run_gate,
                      unwrap_seed=unwrap_seed, sign_digest=sign_digest,
                      read_chamber=read_chamber)
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


def _wallet_for(prov: Provisioning, quoted=None):
    """Which of this device's two wallets a request is for.

    A CELL holds two: the one the normal PIN opens and the one the duress PIN
    opens. Which one a spend concerns cannot be decided by the PIN, because the
    transaction is rendered before the PIN is asked for and that ordering is
    the whole unlock chain. So it is decided by the PSBT, which already says:
    a coordinator spending the decoy's coins quotes the decoy's fingerprint.

    Ambiguity resolves to the primary wallet. A PSBT quoting both, or neither,
    is one the device will fail to find a signable input in anyway.
    """
    if (quoted and prov.decoy_accounts
            and prov.decoy_fingerprint in quoted
            and prov.master_fingerprint not in quoted):
        return prov.decoy_accounts, prov.decoy_fingerprint
    return prov.accounts, prov.master_fingerprint


def _account_in(accounts: list[Account], script_type: str,
                network: str) -> "Account | None":
    for a in accounts:
        if a.script_type == script_type and a.network == network:
            return a
    return None


def _wallet_of_seed(prov: Provisioning, root: ExtendedKey):
    """Which of this device's two recorded wallets an unwrapped seed IS.

    A CELL carries two. For Bitcoin the PSBT says which one a spend concerns,
    because a coordinator quotes the origin fingerprint of the wallet whose
    coins it is spending -- see _wallet_for. An Ethereum request carries no key
    origin at all: there is one account path and nothing in the transaction
    names a wallet, so the same question has no answer before the seed opens.

    It does not need one. Unlike a PSBT, nothing about the sender reaches the
    screen -- ops.EthereumSpend renders the chain, the destination, the amount,
    the fee cap and the nonce, and never the account it spends from -- so
    deciding here costs no ordering property. The seed that opened is the
    answer, and asking it is what makes a duress unlock sign the decoy's
    Ethereum instead of failing with "the unwrapped seed derives a different
    sending address", which is a sentence no coerced owner wants on screen.

    Returns (accounts, fingerprint), or (None, None) when the seed matches
    neither record -- the blob and the record disagreeing, which means signing
    would use a key nobody provisioned.
    """
    fp = root.fingerprint()
    match = None
    for accounts, recorded in ((prov.accounts, prov.master_fingerprint),
                               (prov.decoy_accounts, prov.decoy_fingerprint)):
        # BOTH are always compared and neither short-circuits, for the same
        # reason se.verify_pin checks both PIN slots: a duress unlock must not
        # be distinguishable from a normal one by how long it takes.
        hit = bool(accounts) and hmac.compare_digest(fp, recorded)
        if hit and match is None:
            match = (accounts, recorded)
    return match if match is not None else (None, None)


def _watch_root(prov: Provisioning, network: str, quoted=None) -> ExtendedKey:
    """A synthetic root that answers owns() for our accounts.

    An account xpub sits at depth 3, so paths inside a PSBT — which are quoted
    from the master — cannot be walked from it directly. This wrapper walks the
    account's own suffix instead, and refuses anything outside it.
    """
    all_accounts, fingerprint = _wallet_for(prov, quoted)
    accounts = [a for a in all_accounts if a.network == network]
    if not accounts:
        raise WalletError(f"no accounts provisioned for {network}")
    return _AccountRoot(accounts, fingerprint)


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


@dataclass
class SignedTypedData:
    """One EIP-712 or EIP-7702 signature, and what it was made over.

    There is no raw transaction here, because the device did not build one.
    What the coordinator gets is a 65-byte signature and the digest it covers,
    and whoever relays it pays for the gas.
    """

    signature: bytes                # r || s || v, v = 27 + y_parity
    signer_address: str
    digest: str                     # 0x-hex, so a coordinator can check it
    attestation: bytes
    tier: Tier
    display: list[str]


def _sign_typed(op, digest: bytes, prov: Provisioning, se: SecureElement,
                pol: Policy, fw_hash: bytes, cal_hash: bytes,
                confirm, run_gate, pin: str, index: int = 0,
                requested_tier: Tier | None = None,
                read_chamber=None) -> SignedTypedData:
    """The unlock chain over a 32-byte digest this device built itself.

    Shared by the smart-account spend and the delegation, because from here
    down they are the same operation: one digest, one key, one recovery check.
    What differs is upstream, in what was rendered and what policy priced it
    at, and that has already happened by the time this runs.
    """
    from addresses import eth_address
    if len(digest) != 32:
        raise WalletError("a typed-data digest is 32 bytes")
    if not any(_account_in(a, "eth", "ethereum")
               for a in (prov.accounts, prov.decoy_accounts)):
        raise WalletError(
            "this device has no eth account on ethereum. Provision one before "
            "asking it to sign for that chain.")
    out: dict = {}

    def sign_digest(seed: bytearray, bound: bytes) -> bytes:
        if bound != digest:
            raise WalletError("the digest changed between display and signing")
        root = _root_from(seed)
        accounts, _fp = _wallet_of_seed(prov, root)
        if accounts is None:
            raise WalletError(
                "the unwrapped seed matches neither wallet recorded on this "
                "device; refusing to sign with an unexpected key")
        account = _account_in(accounts, "eth", "ethereum")
        if account is None:
            raise WalletError(
                "the wallet that opened has no eth account recorded on this "
                "device; refusing to sign for an account it cannot check")
        node = root.derive(eth_path(0, index))
        if node.pubkey != account.key().derive([0, index]).pubkey:
            raise WalletError(
                "the unwrapped seed derives a different signing address than "
                "the account recorded for it; refusing to sign")
        assert node.seckey is not None
        r, s_, rec = ec.ecdsa_sign(digest, node.seckey, grind_low_r=False)
        y = rec & 1
        # Same check sign_eth makes, for the same reason: the EVM verifies by
        # recovery, so a wrong parity byte yields a signature that recovers to
        # an address nobody controls. Here it would be an owner the account
        # does not have, and the account would simply refuse -- after the
        # owner had already bled.
        if ec.ecdsa_recover(digest, r, s_, y) != node.pubkey:
            raise WalletError("signature does not recover to the signing key")
        out["expect"] = eth_address(node.pubkey)
        # v is 27 + y_parity. The account contract reads v < 27 as one of its
        # other approval types, so an offset of zero here does not fail as a
        # bad signature; it is read as a different kind of approval entirely.
        out["sig"] = (r.to_bytes(32, "big") + s_.to_bytes(32, "big")
                      + bytes([27 + y]))
        out["recovered"] = eth_address(ec.ecdsa_recover(digest, r, s_, y))
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([y])

    def unwrap_seed(key: bytes) -> bytearray:
        try:
            return duress.unwrap_any(prov.seed_pair, key)
        except (duress.NoBlobOpened, seedstore.SeedStoreError) as e:
            # Neither derives from ValueError, so both used to travel all the
            # way up to app.main's catch-all and paint a Python class name at
            # somebody holding a lancet. The owner needs to know it is not
            # their words.
            raise WalletError(
                f"the seed store did not open with the key this PIN derives "
                f"({e}). Nothing is wrong with your recovery words; the store "
                f"on this card and the chip in this device disagree.") from None

    sg = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                       confirm=confirm, run_gate=run_gate,
                       unwrap_seed=unwrap_seed, sign_digest=sign_digest,
                       read_chamber=read_chamber)
    result = sg.authorize_and_sign(
        signer.SignRequest(operation=op, sighash=digest,
                           requested_tier=requested_tier), pin)
    if out["recovered"] != out["expect"]:
        raise WalletError("signature recovers to an unexpected address")
    return SignedTypedData(signature=out["sig"], signer_address=out["expect"],
                           digest="0x" + digest.hex(),
                           attestation=result.attestation.pack(),
                           tier=result.tier, display=result.display)


@dataclass
class SignedBeacon:
    """One proof of life. There is no spend signature here, by construction."""

    attestation: bytes
    digest: str                     # 0x-hex, what CellRegistry.heartbeat wants
    epoch: int
    period: str                     # the dates the owner was shown
    tier: Tier
    display: list[str]


def sign_beacon(registry: str, claimant: str, chain_id: int, epoch: int,
                prov: Provisioning, se: SecureElement, pol: Policy,
                fw_hash: bytes, cal_hash: bytes, confirm, run_gate, pin: str,
                requested_tier: Tier | None = None,
                read_chamber=None) -> SignedBeacon:
    """Attest that a living human was here, in this period.

    Nothing is spent and nothing is signed with the seed. The claim is made by
    the attestation key in the secure element, over a digest built here from
    the fields the owner reads, so `needs_seed=False` and the seed never leaves
    its blob. Everything before the unwrap is the ordinary chain: render,
    policy, confirm, PIN, gate.
    """
    if chain_id not in eth.CHAINS:
        raise WalletError(
            f"chain {chain_id} is not registered on this device, so the "
            f"confirmation screen could not name the network. Register it "
            f"before asking for a beacon on it.")
    # The period is not a parameter. It is CellRegistry.EPOCH_SECONDS, which
    # the digest does not commit to -- see beacon.Beacon.check.
    b = beacon.Beacon(registry=registry, claimant=claimant, chain_id=chain_id,
                      chain_name=eth.CHAINS[chain_id][0], epoch=epoch)
    try:
        digest = b.digest()
    except beacon.BadBeacon as e:
        raise WalletError(str(e)) from None
    start, end = b.window()
    op = ops.ProofOfLife(registry=b.registry, claimant=b.claimant,
                         chain_id=b.chain_id, chain_name=b.chain_name,
                         period_start=start.isoformat(),
                         period_end=end.isoformat())

    def never(_seed, _bound):                           # pragma: no cover
        raise WalletError(
            "a beacon must not reach the signing key. Reaching here means the "
            "chain unwrapped a seed for an operation that spends nothing.")

    sg = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                       confirm=confirm, run_gate=run_gate,
                       unwrap_seed=never, sign_digest=never,
                       read_chamber=read_chamber)
    result = sg.authorize_and_sign(
        signer.SignRequest(operation=op, sighash=digest,
                           requested_tier=requested_tier, needs_seed=False), pin)
    return SignedBeacon(attestation=result.attestation.pack(),
                        digest="0x" + digest.hex(), epoch=epoch,
                        period=f"{start.isoformat()} to {end.isoformat()}",
                        tier=result.tier, display=result.display)


def sign_account_execute(label: str, destination: str, amount_wei: int,
                         nonce: int, prov: Provisioning, se: SecureElement,
                         pol: Policy, fw_hash: bytes, cal_hash: bytes,
                         confirm, run_gate, pin: str, index: int = 0,
                         requested_tier: Tier | None = None,
                         read_chamber=None) -> SignedTypedData:
    """Authorise a value transfer out of a registered smart account.

    The account is looked up by label, so the address the domain separator
    commits to is one this device was told about out of band. A payload that
    carries its own `verifyingContract` is a payload that chooses which account
    the owner is spending from.
    """
    acct = eip712.account(label)
    op = ops.SmartAccountExecute(
        amount_wei=amount_wei, destination=destination,
        account_label=acct.label, account_address=acct.address,
        chain_id=acct.chain_id, chain_name=eth.CHAINS[acct.chain_id][0],
        ticker=eth.CHAINS[acct.chain_id][1], nonce=nonce)
    digest = acct.spend_digest(destination, amount_wei, nonce)
    return _sign_typed(op, digest, prov, se, pol, fw_hash, cal_hash,
                       confirm, run_gate, pin, index, requested_tier,
                       read_chamber)


def sign_delegation(label: str, account_address: str, nonce: int,
                    prov: Provisioning, se: SecureElement, pol: Policy,
                    fw_hash: bytes, cal_hash: bytes, confirm, run_gate,
                    pin: str, index: int = 0,
                    requested_tier: Tier | None = None,
                    read_chamber=None) -> SignedTypedData:
    """Authorise an EIP-7702 delegation to a registered implementation.

    Blood-locked through `account.delegate`, unconditionally. The
    implementation is looked up by label for the same reason the account is:
    the authorisation commits to an address and to nothing whatever about what
    that address contains, so the only check available is one made in advance.

    THE AUTHORITY COMES FROM THE REGISTRATION, NOT FROM THE PAYLOAD. An
    EIP-7702 digest is `keccak(0x05 || rlp([chain_id, implementation, nonce]))`
    and cannot commit to the address being delegated -- the authority is
    whoever signs. So a caller that could name any `account_address` would be
    naming a screen, not a fact: the owner would read an address they do not
    recognise, approve it at blood tier, and delegate their OWN address to that
    code. It is checked against the registered account for the same reason
    eip712.py records `verifyingContract` rather than accepting it.
    """
    acct = eip712.account(label)
    if account_address.lower() != acct.address.lower():
        raise WalletError(
            f"account {label!r} is registered at {acct.address}, and the "
            f"request asked to delegate {account_address}. A 7702 signature "
            f"does not commit to the address it delegates, so this device "
            f"only delegates one it was told about in advance.")
    op = ops.Delegation(
        account_address=acct.address, implementation=acct.implementation,
        implementation_label=acct.implementation_label,
        chain_id=acct.chain_id,
        chain_name=eth.CHAINS[acct.chain_id][0], nonce=nonce)
    digest = eip712.delegation_digest(acct.chain_id, acct.implementation, nonce)
    return _sign_typed(op, digest, prov, se, pol, fw_hash, cal_hash,
                       confirm, run_gate, pin, index, requested_tier,
                       read_chamber)


def sign_eth(tx: eth.EthTransaction, prov: Provisioning, se: SecureElement,
             pol: Policy, fw_hash: bytes, cal_hash: bytes,
             confirm, run_gate, pin: str, index: int = 0,
             requested_tier: Tier | None = None,
             read_chamber=None) -> SignedEth:
    """Run the unlock chain over an EIP-1559 transaction."""
    from addresses import eth_address
    # Fail before the owner spends a PIN attempt or a gate on it if this device
    # cannot sign Ethereum at all. WHICH of the two wallets answers is decided
    # after the unwrap, by the seed -- see _wallet_of_seed. This only asks
    # whether either can, so it settles nothing an observer could read.
    if not any(_account_in(a, "eth", "ethereum")
               for a in (prov.accounts, prov.decoy_accounts)):
        raise WalletError(
            "this device has no eth account on ethereum. Provision one before "
            "asking it to sign for that chain.")

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
        # The seed that opened says which wallet this is. Both of the device's
        # wallets are legitimate; a seed matching NEITHER means the blob and
        # the record disagree, and signing then would sign with a key nobody
        # provisioned -- the same rule sign_psbt enforces one layer up.
        accounts, _fp = _wallet_of_seed(prov, root)
        if accounts is None:
            raise WalletError(
                "the unwrapped seed matches neither wallet recorded on this "
                "device; refusing to sign with an unexpected key")
        account = _account_in(accounts, "eth", "ethereum")
        if account is None:
            raise WalletError(
                "the wallet that opened has no eth account recorded on this "
                "device; refusing to sign for an account it cannot check")
        node = root.derive(eth_path(0, index))
        if node.pubkey != account.key().derive([0, index]).pubkey:
            raise WalletError(
                "the unwrapped seed derives a different sending address than "
                "the account recorded for it; refusing to sign")
        assert node.seckey is not None
        r, s_, y = eth.sign(tx, node.seckey)
        out["raw"] = tx.encode_signed(r, s_, y)
        out["txid"] = tx.txid(r, s_, y)
        out["sender"] = eth.sender(tx, r, s_, y)
        out["expect"] = eth_address(node.pubkey)
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([y])

    def unwrap_seed(key: bytes) -> bytearray:
        try:
            return duress.unwrap_any(prov.seed_pair, key)
        except (duress.NoBlobOpened, seedstore.SeedStoreError) as e:
            # Neither derives from ValueError, so both used to travel all the
            # way up to app.main's catch-all and paint a Python class name at
            # somebody holding a lancet. The owner needs to know it is not
            # their words.
            raise WalletError(
                f"the seed store did not open with the key this PIN derives "
                f"({e}). Nothing is wrong with your recovery words; the store "
                f"on this card and the chip in this device disagree.") from None

    s = signer.Signer(se=se, pol=pol, fw_hash=fw_hash, cal_hash=cal_hash,
                      confirm=confirm, run_gate=run_gate,
                      unwrap_seed=unwrap_seed, sign_digest=sign_digest,
                      read_chamber=read_chamber)
    result = s.authorize_and_sign(
        signer.SignRequest(operation=op, sighash=digest,
                           requested_tier=requested_tier), pin)

    # Recovered from the signature, against the address the wallet that opened
    # actually derives. Ethereum verifies by recovery, so a wrong parity byte
    # produces a valid-looking transaction credited to an address nobody
    # controls; this is the check that catches it.
    if out["sender"] != out["expect"]:
        raise WalletError("signed transaction recovers to an unexpected sender")
    return SignedEth(raw=out["raw"], txid=out["txid"], sender=out["sender"],
                     attestation=result.attestation.pack(), tier=result.tier,
                     display=result.display)
