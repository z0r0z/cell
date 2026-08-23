"""PSBT — parse, verify, summarise for the display, and sign.

This is where the host's claims meet the device's arithmetic. A PSBT is a
document written by software the device does not trust, and every number in it
is an assertion until the device rederives it. What this module refuses to
take on trust:

  THE INPUT AMOUNTS.  A segwit v0 signature commits to the amount of its own
      input but not the others, so a host can understate one input and the
      difference silently becomes fee. Every non-taproot input must therefore
      carry its full parent transaction, and its txid is recomputed and
      compared to the outpoint. Taproot commits to every amount at once, so
      there a witness_utxo alone is sufficient — and only there.

  WHICH OUTPUT IS CHANGE.  The host labels an output as change by attaching a
      derivation path. The device rederives the key at that path from its own
      seed, rebuilds the scriptPubKey, and compares it byte for byte to the
      output. An output that fails is shown to the owner as an unverified
      destination, in full, never folded into "change".

  THE SCRIPT TYPE.  Read from the scriptPubKey itself, never from a field the
      host supplies, because the script type selects the sighash algorithm.

  THE SIGHASH FLAG.  SIGHASH_ALL only, and an explicit PSBT_IN_SIGHASH_TYPE
      requesting anything else is a refusal rather than a downgrade.

SCOPE, deliberately: exactly one non-change output. The operation set in
ops.py is closed and BitcoinSpend renders one destination, so a batched
payment is refused rather than summarised into a total the owner cannot check
line by line. See BUILD.md section 5.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import addresses
import ops
import secp256k1 as ec
import tx as txmod
from bip32 import ExtendedKey
from tx import Reader, Transaction, ser_compact

PSBT_MAGIC = b"psbt\xff"

# Global
GLOBAL_UNSIGNED_TX = 0x00
GLOBAL_XPUB = 0x01
GLOBAL_TX_VERSION = 0x02
GLOBAL_FALLBACK_LOCKTIME = 0x03
GLOBAL_INPUT_COUNT = 0x04
GLOBAL_OUTPUT_COUNT = 0x05
GLOBAL_TX_MODIFIABLE = 0x06
GLOBAL_VERSION = 0xFB
PROPRIETARY = 0xFC

# Per-input
IN_NON_WITNESS_UTXO = 0x00
IN_WITNESS_UTXO = 0x01
IN_PARTIAL_SIG = 0x02
IN_SIGHASH_TYPE = 0x03
IN_REDEEM_SCRIPT = 0x04
IN_WITNESS_SCRIPT = 0x05
IN_BIP32_DERIVATION = 0x06
IN_FINAL_SCRIPTSIG = 0x07
IN_FINAL_SCRIPTWITNESS = 0x08
IN_PREVIOUS_TXID = 0x0E
IN_OUTPUT_INDEX = 0x0F
IN_SEQUENCE = 0x10
IN_REQUIRED_TIME_LOCKTIME = 0x11
IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
IN_TAP_KEY_SIG = 0x13
IN_TAP_BIP32_DERIVATION = 0x16
IN_TAP_INTERNAL_KEY = 0x17

# Per-output
OUT_REDEEM_SCRIPT = 0x00
OUT_WITNESS_SCRIPT = 0x01
OUT_BIP32_DERIVATION = 0x02
OUT_AMOUNT = 0x03
OUT_SCRIPT = 0x04
OUT_TAP_INTERNAL_KEY = 0x05
OUT_TAP_BIP32_DERIVATION = 0x07

# A fee this large is almost certainly a lie about an input amount rather than
# a generous tip, so it is surfaced as a refusal the owner has to look at.
ABSURD_FEE_SATS = 10_000_000


class BadPSBT(ValueError):
    """A PSBT this device will not sign, and why."""


# --------------------------------------------------------------------------
# Key-value maps
# --------------------------------------------------------------------------

KVMap = dict[bytes, bytes]


def _parse_map(r: Reader) -> KVMap:
    out: KVMap = {}
    while True:
        klen = r.compact()
        if klen == 0:
            return out
        key = r.read(klen)
        val = r.bytes_with_len()
        if key in out:
            # Duplicate keys are explicitly invalid in BIP-174. Accepting them
            # means the device and the host may disagree about which value
            # applies, which is a disagreement about what is being signed.
            raise BadPSBT(f"duplicate key {key.hex()} in a PSBT map")
        out[key] = val


def _ser_map(m: KVMap) -> bytes:
    out = b""
    for k in sorted(m):
        out += ser_compact(len(k)) + k + ser_compact(len(m[k])) + m[k]
    return out + b"\x00"


def _get(m: KVMap, keytype: int) -> bytes | None:
    return m.get(bytes([keytype]))


def _get_all(m: KVMap, keytype: int) -> dict[bytes, bytes]:
    """Every entry of this type, mapped by the key's data suffix."""
    return {k[1:]: v for k, v in m.items() if k and k[0] == keytype and len(k) > 1}


def proprietary_key(identifier: bytes, subtype: int = 0,
                    keydata: bytes = b"") -> bytes:
    """A BIP-174 proprietary key.

        0xFC <compact len(identifier)> <identifier> <compact subtype> <keydata>

    The length prefix is the whole point and is easy to leave out, because
    `0xFC` followed by a vendor string looks complete. It is not: a parser
    reads the byte after 0xFC as the identifier's length, so `0xFC "CELL" 01`
    tells it the identifier is 0x43 = 67 bytes long, and it runs off the end
    of the map. Bitcoin Core rejects such a PSBT outright with a decode error
    — it does not skip the field it cannot read — so an attestation written
    this way makes the whole transaction unreadable to the coordinator that
    has to finalise it.

    This was found by handing a signed PSBT to a real node. No amount of
    round-tripping through our own parser would have shown it, because our own
    parser treats the key as an opaque blob and never looks inside.
    """
    return (bytes([PROPRIETARY]) + ser_compact(len(identifier)) + identifier
            + ser_compact(subtype) + keydata)


def _parse_derivation(val: bytes) -> tuple[bytes, list[int]]:
    if len(val) < 4 or (len(val) - 4) % 4:
        raise BadPSBT("malformed BIP32 derivation field")
    fp = val[:4]
    path = [int.from_bytes(val[i:i + 4], "little") for i in range(4, len(val), 4)]
    return fp, path


def _ser_derivation(fp: bytes, path: list[int]) -> bytes:
    return fp + b"".join(i.to_bytes(4, "little") for i in path)


# --------------------------------------------------------------------------
# BIP-370 (version 2) reconstruction
#
# Version 2 removes the global unsigned transaction and scatters its fields
# across the input and output maps instead. Nothing about what the device
# checks changes: we rebuild the transaction those fields describe and then
# run exactly the same verification over it. Doing it this way rather than
# threading a second representation through psbt.py means there is one set of
# rules about amounts, change and sighashes, not two that could drift.
# --------------------------------------------------------------------------


def _count(g: KVMap, keytype: int, what: str) -> int:
    raw = _get(g, keytype)
    if raw is None:
        raise BadPSBT(f"a version 2 PSBT must declare its {what} count")
    r = Reader(raw)
    n = r.compact()
    if not r.done:
        raise BadPSBT(f"trailing bytes in the {what} count")
    if not 0 < n <= 4096:
        raise BadPSBT(f"{what} count of {n} is out of range")
    return n


def _rebuild_v2(g: KVMap, in_maps: list[KVMap], out_maps: list[KVMap]) -> Transaction:
    ver_raw = _get(g, GLOBAL_TX_VERSION)
    if ver_raw is None or len(ver_raw) != 4:
        raise BadPSBT("a version 2 PSBT must declare a 4-byte transaction version")
    tx = Transaction(version=int.from_bytes(ver_raw, "little"))

    for i, m in enumerate(in_maps):
        txid = _get(m, IN_PREVIOUS_TXID)
        index = _get(m, IN_OUTPUT_INDEX)
        if txid is None or len(txid) != 32:
            raise BadPSBT(f"input {i} has no 32-byte previous txid")
        if index is None or len(index) != 4:
            raise BadPSBT(f"input {i} has no 4-byte output index")
        seq = _get(m, IN_SEQUENCE)
        if seq is not None and len(seq) != 4:
            raise BadPSBT(f"input {i} has a malformed sequence")
        tx.vin.append(txmod.TxIn(
            txid=txid, vout=int.from_bytes(index, "little"),
            sequence=int.from_bytes(seq, "little") if seq else 0xFFFFFFFF))

    for i, m in enumerate(out_maps):
        amount = _get(m, OUT_AMOUNT)
        script = _get(m, OUT_SCRIPT)
        if amount is None or len(amount) != 8:
            raise BadPSBT(f"output {i} has no 8-byte amount")
        if script is None:
            raise BadPSBT(f"output {i} has no script")
        value = int.from_bytes(amount, "little", signed=True)
        if value < 0:
            raise BadPSBT(f"output {i} has a negative amount")
        tx.vout.append(txmod.TxOut(value=value, script_pubkey=script))

    tx.locktime = _v2_locktime(g, in_maps)
    return tx


def _v2_locktime(g: KVMap, in_maps: list[KVMap]) -> int:
    """The locktime BIP-370 says this transaction ends up with.

    An input may REQUIRE a height or a time locktime. If any does, the
    transaction takes the largest requirement of that kind and the fallback is
    ignored. Requiring both kinds at once is not satisfiable, and a device that
    picked one would be signing a transaction different from the one the
    coordinator meant — so that is a refusal.
    """
    heights, times = [], []
    for i, m in enumerate(in_maps):
        h, t = _get(m, IN_REQUIRED_HEIGHT_LOCKTIME), _get(m, IN_REQUIRED_TIME_LOCKTIME)
        if h is not None:
            if len(h) != 4:
                raise BadPSBT(f"input {i} has a malformed height locktime")
            heights.append(int.from_bytes(h, "little"))
        if t is not None:
            if len(t) != 4:
                raise BadPSBT(f"input {i} has a malformed time locktime")
            times.append(int.from_bytes(t, "little"))
    if heights and times:
        raise BadPSBT(
            "this PSBT requires both a height locktime and a time locktime, "
            "which no single transaction can satisfy")
    if heights:
        return max(heights)
    if times:
        return max(times)
    fallback = _get(g, GLOBAL_FALLBACK_LOCKTIME)
    if fallback is None:
        return 0
    if len(fallback) != 4:
        raise BadPSBT("malformed fallback locktime")
    return int.from_bytes(fallback, "little")


# --------------------------------------------------------------------------
# Multisig descriptors — the registered co-signers
# --------------------------------------------------------------------------


@dataclass
class MultisigDescriptor:
    """An m-of-n the device has been told about, and can therefore rebuild.

    THIS IS WHY REGISTRATION EXISTS. Without it, "is this output ours?" can
    only be answered as "does it contain a key of mine?" — and an attacker who
    controls the coordinator can build a script holding exactly one key of
    yours and n-1 of theirs. It hashes correctly, the wallet calls it change,
    and the balance moves to a script you cannot spend without them.

    With the co-signers registered the question becomes "does this output
    equal the script my registered quorum produces at the path it claims?",
    which is arithmetic and cannot be talked around.

    `keys` are (master fingerprint, account path, account xpub), one per
    co-signer, in the order the descriptor declares. `sorted_keys` is BIP-67
    lexicographic ordering, which most coordinators default to; getting it
    wrong produces a different address rather than an error, so it is recorded
    rather than guessed.
    """

    threshold: int
    keys: list[tuple[bytes, list[int], ExtendedKey]]
    sorted_keys: bool = True
    wrapped: bool = False               # p2sh-p2wsh rather than bare p2wsh
    label: str = ""

    @property
    def n(self) -> int:
        return len(self.keys)

    def witness_script_for(self, derivations: dict[bytes, bytes]) -> bytes | None:
        """Rebuild the witness script these derivations claim, or None.

        Every registered co-signer must appear exactly once, at the same
        change/index suffix as the others. A PSBT that quotes a different
        suffix for one co-signer is not describing a standard multisig
        address, and guessing which one it meant is how a wallet ends up
        confident about the wrong script.
        """
        found: list[bytes] = []
        suffix: list[int] | None = None
        for fp, prefix, xpub in self.keys:
            match = None
            for keybytes, val in derivations.items():
                try:
                    origin_fp, path = _parse_derivation(val)
                except BadPSBT:
                    return None
                if origin_fp != fp or path[:len(prefix)] != prefix:
                    continue
                if match is not None:
                    return None                 # ambiguous; refuse to guess
                match = (keybytes, path[len(prefix):])
            if match is None:
                return None
            keybytes, tail = match
            if suffix is None:
                suffix = tail
            elif tail != suffix:
                return None
            try:
                if xpub.derive(tail).pubkey != keybytes:
                    return None
            except ValueError:
                return None
            found.append(keybytes)

        if len(found) != self.n or not 1 <= self.threshold <= self.n:
            return None
        ordered = sorted(found) if self.sorted_keys else found
        try:
            return addresses.multisig_script(self.threshold, ordered)
        except addresses.BadAddress:
            return None

    def script_pubkey_for(self, derivations: dict[bytes, bytes]) -> bytes | None:
        ws = self.witness_script_for(derivations)
        if ws is None:
            return None
        p2wsh = addresses.p2wsh_script(ws)
        return addresses.p2sh_script(p2wsh) if self.wrapped else p2wsh


# --------------------------------------------------------------------------
# Per-input analysis
# --------------------------------------------------------------------------


@dataclass
class InputInfo:
    """Everything the device worked out for itself about one input."""

    index: int
    amount: int
    script_pubkey: bytes
    kind: str                       # p2pkh / p2sh / p2wpkh / p2wsh / p2sh-p2wpkh / p2tr
    script_code: bytes = b""        # what a v0 or legacy sighash covers
    witness_script: bytes = b""
    amount_verified: bool = False   # by the parent transaction, or by BIP-341
    ours: list[tuple[bytes, list[int]]] = field(default_factory=list)
    quorum_needed: int = 0
    quorum_size: int = 0
    sigs_present: int = 0
    descriptor: "MultisigDescriptor | None" = None


def _classify(spk: bytes) -> str:
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh"
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22:] == b"\x87":
        return "p2sh"
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh"
    if len(spk) == 34 and spk[:2] == b"\x00\x20":
        return "p2wsh"
    if len(spk) == 34 and spk[:2] == b"\x51\x20":
        return "p2tr"
    raise BadPSBT(f"input has an unsupported script type ({spk[:4].hex()}…). "
                  f"This device signs p2pkh, p2sh, p2wpkh, p2wsh and p2tr.")


def parse_multisig(script: bytes) -> tuple[int, list[bytes]]:
    """(m, keys) from a bare CHECKMULTISIG script, or (0, []).

    Strict on purpose. The loose version of this — read the first and last
    opcodes, trust the middle — will happily report "2 of 3" for a script
    whose middle is something else entirely, and that number goes on the
    screen the owner approves. So every push is walked, every key must be a
    33-byte compressed point on the curve, and the declared n must equal the
    number of keys actually present.
    """
    if len(script) < 3 + 34 or script[-1] != 0xAE:
        return 0, []
    m, n = script[0] - 0x50, script[-2] - 0x50
    if not (1 <= m <= n <= 16):
        return 0, []
    keys, i = [], 1
    while i < len(script) - 2:
        if script[i] != 33 or i + 34 > len(script) - 2:
            return 0, []
        key = script[i + 1:i + 34]
        try:
            ec.parse_pubkey(key)
        except ec.BadKey:
            return 0, []
        keys.append(key)
        i += 34
    if i != len(script) - 2 or len(keys) != n:
        return 0, []
    return m, keys


def _parse_multisig(script: bytes) -> tuple[int, int]:
    """(m, n), or (0, 0). Convenience over parse_multisig."""
    m, keys = parse_multisig(script)
    return (m, len(keys)) if m else (0, 0)


# --------------------------------------------------------------------------


@dataclass
class Summary:
    """What the device concluded, and what it will show the owner."""

    spend: ops.BitcoinSpend
    inputs: list[InputInfo]
    total_in: int
    fee: int
    signable: int                   # inputs this device holds a key for
    warnings: list[str] = field(default_factory=list)


class PSBT:
    """A BIP-174 partially signed Bitcoin transaction."""

    def __init__(self, unsigned: Transaction):
        self.tx = unsigned
        self.globals: KVMap = {}
        self.inputs: list[KVMap] = [{} for _ in unsigned.vin]
        self.outputs: list[KVMap] = [{} for _ in unsigned.vout]
        # Multisig quorums this device has been told about. Empty means the
        # device knows of none, and every multisig script it meets is
        # therefore unrecognised — which is a refusal, not a shrug.
        self.descriptors: list[MultisigDescriptor] = []
        # 0 for BIP-174, 2 for BIP-370. Kept because serialize() must hand the
        # coordinator back the dialect it sent: a v2 PSBT that comes back as
        # v0 is a PSBT the coordinator may not be able to finalise.
        self.psbt_version = 0

    # ---- serialisation ----

    @staticmethod
    def parse(data: bytes) -> "PSBT":
        if not data.startswith(PSBT_MAGIC):
            raise BadPSBT("not a PSBT: magic bytes missing")
        r = Reader(data)
        r.read(5)
        g = _parse_map(r)
        version = int.from_bytes(_get(g, GLOBAL_VERSION) or b"\x00", "little")
        raw = _get(g, GLOBAL_UNSIGNED_TX)

        if raw is not None:
            if version not in (0, 1):
                raise BadPSBT(
                    f"PSBT declares version {version} but carries a version 0 "
                    f"unsigned transaction. One of the two is wrong.")
            unsigned = Transaction.parse(raw)
            n_in, n_out = len(unsigned.vin), len(unsigned.vout)
            in_maps = [_parse_map(r) for _ in range(n_in)]
            out_maps = [_parse_map(r) for _ in range(n_out)]
        elif version == 2:
            n_in = _count(g, GLOBAL_INPUT_COUNT, "input")
            n_out = _count(g, GLOBAL_OUTPUT_COUNT, "output")
            in_maps = [_parse_map(r) for _ in range(n_in)]
            out_maps = [_parse_map(r) for _ in range(n_out)]
            unsigned = _rebuild_v2(g, in_maps, out_maps)
        else:
            raise BadPSBT(
                f"PSBT version {version} has no unsigned transaction and is "
                f"not version 2. This device reads BIP-174 version 0 and "
                f"BIP-370 version 2.")

        for i, vin in enumerate(unsigned.vin):
            if vin.script_sig or vin.witness:
                raise BadPSBT(f"input {i} of the unsigned transaction is already "
                              f"signed; a PSBT's transaction must be bare")
        p = PSBT(unsigned)
        p.psbt_version = version
        p.globals = g
        p.inputs = in_maps
        p.outputs = out_maps
        if not r.done:
            raise BadPSBT(f"{len(data) - r.pos} trailing bytes after the PSBT")
        return p

    def serialize(self) -> bytes:
        return (PSBT_MAGIC + _ser_map(self.globals)
                + b"".join(_ser_map(m) for m in self.inputs)
                + b"".join(_ser_map(m) for m in self.outputs))

    # ---- proprietary fields, used to carry the attestation ----

    def set_proprietary(self, identifier: bytes, subtype: int,
                        value: bytes, keydata: bytes = b"") -> None:
        self.globals[proprietary_key(identifier, subtype, keydata)] = value

    def get_proprietary(self, identifier: bytes, subtype: int = 0,
                        keydata: bytes = b"") -> bytes | None:
        return self.globals.get(proprietary_key(identifier, subtype, keydata))

    def strip_proprietary(self, identifier: bytes | None = None) -> None:
        """Remove proprietary fields before broadcast.

        The attestation must not reach the chain by default: it fingerprints
        the address as a CELL device and discloses how the spend was
        authorised.
        """
        want = None if identifier is None else \
            bytes([PROPRIETARY]) + ser_compact(len(identifier)) + identifier
        for k in [k for k in self.globals
                  if k and k[0] == PROPRIETARY
                  and (want is None or k.startswith(want))]:
            del self.globals[k]

    # ---- analysis ----

    def _input_info(self, i: int, root: ExtendedKey | None) -> InputInfo:
        m = self.inputs[i]
        vin = self.tx.vin[i]

        non_witness = _get(m, IN_NON_WITNESS_UTXO)
        witness_utxo = _get(m, IN_WITNESS_UTXO)

        amount: int | None = None
        spk: bytes | None = None
        verified = False

        if non_witness is not None:
            parent = Transaction.parse(non_witness)
            if parent.txid() != vin.txid:
                raise BadPSBT(
                    f"input {i}: the supplied parent transaction hashes to "
                    f"{parent.txid_hex()}, but the input spends "
                    f"{vin.txid_hex()}. The host is lying about this input.")
            if vin.vout >= len(parent.vout):
                raise BadPSBT(f"input {i}: parent transaction has no output {vin.vout}")
            out = parent.vout[vin.vout]
            amount, spk, verified = out.value, out.script_pubkey, True

        if witness_utxo is not None:
            r = Reader(witness_utxo)
            w_amount, w_spk = r.u64(), r.bytes_with_len()
            if not r.done:
                raise BadPSBT(f"input {i}: trailing bytes in witness_utxo")
            if amount is not None and (w_amount, w_spk) != (amount, spk):
                raise BadPSBT(
                    f"input {i}: witness_utxo and the parent transaction "
                    f"disagree about the amount or script. One of them is a lie.")
            amount, spk = w_amount, w_spk

        if amount is None or spk is None:
            raise BadPSBT(f"input {i} has neither a witness UTXO nor its parent "
                          f"transaction; its value cannot be established")

        kind = _classify(spk)
        info = InputInfo(index=i, amount=amount, script_pubkey=spk, kind=kind,
                         amount_verified=verified)

        redeem = _get(m, IN_REDEEM_SCRIPT) or b""
        witness_script = _get(m, IN_WITNESS_SCRIPT) or b""

        if kind == "p2sh":
            if not redeem:
                raise BadPSBT(f"input {i}: p2sh input with no redeem script")
            if addresses.p2sh_script(redeem) != spk:
                raise BadPSBT(f"input {i}: redeem script does not hash to the "
                              f"input's scriptPubKey")
            inner = _classify(redeem) if len(redeem) in (22, 34) and redeem[0] == 0 \
                else "legacy"
            if inner == "p2wpkh":
                info.kind = "p2sh-p2wpkh"
                info.script_code = b"\x76\xa9\x14" + redeem[2:] + b"\x88\xac"
            elif inner == "p2wsh":
                info.kind = "p2sh-p2wsh"
                if hashlib.sha256(witness_script).digest() != redeem[2:]:
                    raise BadPSBT(f"input {i}: witness script does not match the "
                                  f"redeem script's commitment")
                info.script_code = witness_script
            else:
                info.script_code = redeem
        elif kind == "p2wsh":
            if hashlib.sha256(witness_script).digest() != spk[2:]:
                raise BadPSBT(f"input {i}: witness script does not hash to the "
                              f"input's scriptPubKey")
            info.script_code = witness_script
        elif kind == "p2wpkh":
            info.script_code = b"\x76\xa9\x14" + spk[2:] + b"\x88\xac"
        elif kind == "p2pkh":
            info.script_code = spk

        info.witness_script = witness_script
        if witness_script:
            info.quorum_needed, info.quorum_size = _parse_multisig(witness_script)
            if not info.quorum_needed:
                raise BadPSBT(
                    f"input {i}: the witness script is not a bare m-of-n "
                    f"multisig. This device signs multisig it can describe to "
                    f"you, and it cannot describe this one.")
            # The quorum on the confirmation screen has to be a fact, not a
            # reading of a script the host wrote. Rebuild it from the
            # registered co-signers, or refuse.
            derivs = _get_all(m, IN_BIP32_DERIVATION)
            for d in self.descriptors:
                if d.witness_script_for(derivs) == witness_script:
                    info.descriptor = d
                    break
            if info.descriptor is None:
                raise BadPSBT(
                    f"input {i} spends a {info.quorum_needed}-of-"
                    f"{info.quorum_size} multisig this device has not been "
                    f"told about. Register the co-signers "
                    f"(tools/provision.py multisig) before signing, so the "
                    f"device can tell your quorum from someone else's.")
        info.sigs_present = len(_get_all(m, IN_PARTIAL_SIG))

        # Taproot's sighash covers every input's amount, so a witness_utxo is
        # enough there. Everywhere else the parent transaction is mandatory.
        if info.kind == "p2tr":
            info.amount_verified = True
        elif not verified:
            raise BadPSBT(
                f"input {i} supplies only a witness UTXO. A segwit v0 signature "
                f"does not commit to the other inputs' amounts, so a host that "
                f"understates one turns the difference into fee. Include the "
                f"full parent transaction (PSBT_IN_NON_WITNESS_UTXO).")

        # Which keys here are ours — rederived, not asserted.
        if root is not None:
            info.ours = self._our_keys(m, root, taproot=info.kind == "p2tr")
        return info

    def _our_keys(self, m: KVMap, root: ExtendedKey,
                  taproot: bool) -> list[tuple[bytes, list[int]]]:
        """Keys in this map that our seed really does derive."""
        found = []
        fp = root.fingerprint()
        if taproot:
            entries = {}
            for xonly, val in _get_all(m, IN_TAP_BIP32_DERIVATION).items():
                r = Reader(val)
                for _ in range(r.compact()):        # leaf hashes; key path has none
                    r.read(32)
                entries[xonly] = r.data[r.pos:]
        else:
            entries = _get_all(m, IN_BIP32_DERIVATION)

        for keybytes, val in entries.items():
            origin_fp, path = _parse_derivation(val)
            if origin_fp != fp:
                # A foreign fingerprint is a co-signer's key, not an error. We
                # still try the path when the fingerprint is absent-by-accident
                # only if it matches ours; otherwise deriving every co-signer's
                # path would be wasted work.
                continue
            try:
                node = root.derive(path)
            except ValueError:
                continue
            if taproot:
                if node.pubkey[1:] == keybytes:
                    found.append((keybytes, path))
            elif node.pubkey == keybytes:
                found.append((keybytes, path))
        return found

    def quoted_fingerprints(self) -> set:
        """Every master fingerprint the inputs claim a key origin under.

        A device that holds two wallets — see duress.py — has to know which of
        them a PSBT is for BEFORE it can render it, because rendering happens
        before the PIN and the PIN is the only other thing that could say. The
        PSBT already answers: a coordinator building a spend quotes the origin
        fingerprint of the wallet whose coins it is spending.

        Read-only, and it commits to nothing: the answer only selects which
        account xpubs to check ownership against, and every derivation is
        rebuilt and compared afterwards regardless.
        """
        out = set()
        for m in self.inputs:
            entries = dict(_get_all(m, IN_BIP32_DERIVATION))
            for _xonly, val in _get_all(m, IN_TAP_BIP32_DERIVATION).items():
                r = Reader(val)
                for _ in range(r.compact()):
                    r.read(32)
                entries[_xonly] = r.data[r.pos:]
            for val in entries.values():
                try:
                    origin_fp, _path = _parse_derivation(val)
                except Exception:                               # noqa: BLE001
                    continue                    # malformed origins are caught later
                out.add(origin_fp)
        return out

    def _output_is_ours(self, i: int, root: ExtendedKey) -> bool:
        """Rederive and rebuild. The host's label is not evidence."""
        m = self.outputs[i]
        spk = self.tx.vout[i].script_pubkey
        fp = root.fingerprint()

        internal = _get(m, OUT_TAP_INTERNAL_KEY)
        if internal is not None:
            for xonly, val in _get_all(m, OUT_TAP_BIP32_DERIVATION).items():
                r = Reader(val)
                for _ in range(r.compact()):
                    r.read(32)
                origin_fp, path = _parse_derivation(r.data[r.pos:])
                if origin_fp != fp or xonly != internal:
                    continue
                try:
                    node = root.derive(path)
                except ValueError:
                    continue
                if node.pubkey[1:] != internal:
                    continue
                out_key, _ = ec.taproot_tweak_pubkey(internal)
                if addresses.p2tr_script(out_key) == spk:
                    return True
            return False

        witness_script = _get(m, OUT_WITNESS_SCRIPT)
        redeem = _get(m, OUT_REDEEM_SCRIPT)
        derivations = _get_all(m, OUT_BIP32_DERIVATION)
        if not derivations:
            return False

        # Multisig change is only ours if the WHOLE quorum rebuilds. Checking
        # that one of the keys is ours is not enough: a script holding one key
        # of yours and n-1 of an attacker's hashes correctly, looks like
        # change, and moves the balance somewhere you cannot spend alone.
        if witness_script is not None:
            if not _parse_multisig(witness_script)[0]:
                return False
            for d in self.descriptors:
                rebuilt = d.witness_script_for(derivations)
                if rebuilt is None or rebuilt != witness_script:
                    continue
                if d.script_pubkey_for(derivations) != spk:
                    continue
                if redeem is not None and addresses.p2wsh_script(witness_script) != redeem:
                    continue
                # ...and one of the quorum has to actually be us, or this is a
                # perfectly valid address belonging to somebody else.
                for keybytes, val in derivations.items():
                    origin_fp, path = _parse_derivation(val)
                    if origin_fp == fp and root.owns(keybytes, path):
                        return True
            return False

        for keybytes, val in derivations.items():
            origin_fp, path = _parse_derivation(val)
            if origin_fp != fp or not root.owns(keybytes, path):
                continue
            candidates = [addresses.p2wpkh_script(keybytes),
                          addresses.p2pkh_script(keybytes)]
            if redeem is not None:
                candidates.append(addresses.p2sh_script(redeem))
            if spk in candidates:
                if spk == candidates[-1] and redeem is not None:
                    # A p2sh wrapper only counts if the redeem script is our key.
                    if redeem != addresses.p2wpkh_script(keybytes):
                        continue
                return True
        return False

    def summarize(self, root: ExtendedKey, network: str = "mainnet") -> Summary:
        """Everything the owner needs, computed from the seed and the bytes."""
        infos = [self._input_info(i, root) for i in range(len(self.tx.vin))]
        total_in = sum(i.amount for i in infos)
        total_out = sum(o.value for o in self.tx.vout)
        fee = total_in - total_out
        if fee < 0:
            raise BadPSBT(f"outputs exceed inputs by {-fee} sat; this "
                          f"transaction cannot be valid")

        warnings: list[str] = []
        recipients, change_sats, change_addr, change_ours = [], 0, "", True
        # Addresses that were LABELLED change and could not be derived. Kept as
        # a list rather than a single slot: BitcoinSpend has one change line, so
        # a second unverified output used to overwrite the first one's address
        # while still adding its value to the total -- the owner saw the right
        # number and only one of the two addresses it went to.
        unverified: list[str] = []
        for i, out in enumerate(self.tx.vout):
            try:
                addr = addresses.script_to_address(out.script_pubkey, network)
            except addresses.BadAddress as e:
                raise BadPSBT(f"output {i} cannot be displayed as an address: {e}. "
                              f"This device does not sign what it cannot show.")
            claimed_ours = bool(_get_all(self.outputs[i], OUT_BIP32_DERIVATION)
                                or _get(self.outputs[i], OUT_TAP_INTERNAL_KEY))
            if self._output_is_ours(i, root):
                change_sats += out.value
                change_addr = change_addr or addr
            elif claimed_ours:
                # The host labelled this output as ours and the device cannot
                # derive it. It stays in the change slot rather than becoming a
                # second recipient, because BitcoinSpend renders an unverified
                # change output as a WARNING with the address in full — which is
                # exactly the screen the owner needs to catch this. Folding it
                # in with the real destinations would bury it.
                change_sats += out.value
                change_addr = addr
                change_ours = False
                unverified.append(addr)
                warnings.append(
                    f"output {i} is labelled as change but this wallet cannot "
                    f"derive it")
            else:
                recipients.append((addr, out.value))

        if len(unverified) > 1:
            # One unverified change output gets a WARNING with its address in
            # full, which is the screen that catches it. Two cannot both be
            # shown on a 20-row display, and showing one while summing both is
            # worse than refusing: the total looks right and an address the
            # money went to is simply absent.
            raise BadPSBT(
                f"this transaction sends to {len(unverified)} outputs labelled "
                f"as change that this wallet cannot derive. The device shows "
                f"one such address in full and will not summarise several into "
                f"a total; ask the coordinator for the derivation paths, or "
                f"split the transaction.")

        if len(recipients) != 1:
            raise BadPSBT(
                f"this transaction pays {len(recipients)} destinations. The "
                f"device renders one destination per signature so the owner can "
                f"check it in full; split the payment or use a coordinator that "
                f"batches at a higher layer.")

        if fee > ABSURD_FEE_SATS:
            warnings.append(f"fee is {fee} sat, which is unusually large")

        quorum = next((i for i in infos if i.quorum_size), None)
        spend = ops.BitcoinSpend(
            amount_sats=recipients[0][1],
            destination=recipients[0][0],
            fee_sats=fee,
            change_sats=change_sats,
            change_address=change_addr,
            change_is_ours=change_ours if change_sats else True,
            quorum_needed=quorum.quorum_needed if quorum else 0,
            quorum_size=quorum.quorum_size if quorum else 0,
            signatures_present=quorum.sigs_present if quorum else 0)

        return Summary(spend=spend, inputs=infos, total_in=total_in, fee=fee,
                       signable=sum(1 for i in infos if i.ours), warnings=warnings)

    # ---- signing ----

    def sighash(self, i: int, infos: list[InputInfo]) -> bytes:
        """The digest for input i, chosen by that input's own script type."""
        info = infos[i]
        declared = _get(self.inputs[i], IN_SIGHASH_TYPE)
        if declared is not None:
            want = int.from_bytes(declared, "little")
            allowed = (txmod.SIGHASH_DEFAULT, txmod.SIGHASH_ALL) \
                if info.kind == "p2tr" else (txmod.SIGHASH_ALL,)
            if want not in allowed:
                raise BadPSBT(
                    f"input {i} asks for sighash flag {want:#x}. This device "
                    f"signs SIGHASH_ALL only — every other flag lets someone "
                    f"change part of the transaction after you approved it.")
        if info.kind == "p2tr":
            return self.tx.sighash_taproot(
                i, [x.amount for x in infos], [x.script_pubkey for x in infos])
        if info.kind in ("p2wpkh", "p2wsh", "p2sh-p2wpkh", "p2sh-p2wsh"):
            return self.tx.sighash_segwit_v0(i, info.script_code, info.amount)
        return self.tx.sighash_legacy(i, info.script_code)

    def signing_digest(self, infos: list[InputInfo]) -> bytes:
        """One 32-byte value binding every digest this signing will produce.

        The attestation binds to a single sighash, but a transaction has one
        per input. Hashing them in order gives a single stable value that
        changes if any input, output, amount or ordering changes.
        """
        h = hashlib.sha256(b"CELL/psbt/v1")
        for i, info in enumerate(infos):
            h.update(self.sighash(i, infos) if info.ours else b"\x00" * 32)
        return h.digest()

    def sign(self, root: ExtendedKey, infos: list[InputInfo] | None = None) -> int:
        """Add a partial signature for every input we hold a key for.

        Returns the number of signatures added. Zero is not an error at this
        layer — a co-signer may legitimately have nothing to contribute — but
        signer.py treats it as a refusal, because the owner bled for a
        signature and must not be told it worked when nothing was produced.
        """
        if root.seckey is None:
            raise BadPSBT("cannot sign from a watch-only key")
        if infos is None:
            infos = [self._input_info(i, root) for i in range(len(self.tx.vin))]

        added = 0
        for i, info in enumerate(infos):
            if not info.ours:
                continue
            digest = self.sighash(i, infos)
            for keybytes, path in info.ours:
                node = root.derive(path)
                assert node.seckey is not None
                if info.kind == "p2tr":
                    sk = ec.taproot_tweak_seckey(node.seckey)
                    sig = ec.schnorr_sign(digest, sk)
                    out_key, _ = ec.taproot_tweak_pubkey(node.pubkey[1:])
                    if addresses.p2tr_script(out_key) != info.script_pubkey:
                        raise BadPSBT(
                            f"input {i}: our key tweaks to a different taproot "
                            f"output than the one being spent; refusing to sign "
                            f"a script-path spend this device cannot render")
                    if not ec.schnorr_verify(digest, out_key, sig):
                        raise BadPSBT(f"input {i}: produced a signature that "
                                      f"does not verify")
                    self.inputs[i][bytes([IN_TAP_KEY_SIG])] = sig
                else:
                    r, s, _ = ec.ecdsa_sign(digest, node.seckey)
                    if not ec.ecdsa_verify(digest, node.pubkey, r, s):
                        raise BadPSBT(f"input {i}: produced a signature that "
                                      f"does not verify")
                    self.inputs[i][bytes([IN_PARTIAL_SIG]) + keybytes] = \
                        ec.der_encode(r, s) + bytes([txmod.SIGHASH_ALL])
                added += 1
        return added


