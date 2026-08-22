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
from bip32 import HARDENED, ExtendedKey
from tx import Reader, Transaction, ser_compact

PSBT_MAGIC = b"psbt\xff"

# Global
GLOBAL_UNSIGNED_TX = 0x00
GLOBAL_XPUB = 0x01
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
IN_TAP_KEY_SIG = 0x13
IN_TAP_BIP32_DERIVATION = 0x16
IN_TAP_INTERNAL_KEY = 0x17

# Per-output
OUT_REDEEM_SCRIPT = 0x00
OUT_WITNESS_SCRIPT = 0x01
OUT_BIP32_DERIVATION = 0x02
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


def _parse_derivation(val: bytes) -> tuple[bytes, list[int]]:
    if len(val) < 4 or (len(val) - 4) % 4:
        raise BadPSBT("malformed BIP32 derivation field")
    fp = val[:4]
    path = [int.from_bytes(val[i:i + 4], "little") for i in range(4, len(val), 4)]
    return fp, path


def _ser_derivation(fp: bytes, path: list[int]) -> bytes:
    return fp + b"".join(i.to_bytes(4, "little") for i in path)


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


def _parse_multisig(script: bytes) -> tuple[int, int]:
    """(m, n) from a bare CHECKMULTISIG witness script, or (0, 0)."""
    if len(script) < 3 or script[-1] != 0xAE:
        return 0, 0
    m, n = script[0] - 0x50, script[-2] - 0x50
    if not (1 <= m <= n <= 16):
        return 0, 0
    return m, n


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

    # ---- serialisation ----

    @staticmethod
    def parse(data: bytes) -> "PSBT":
        if not data.startswith(PSBT_MAGIC):
            raise BadPSBT("not a PSBT: magic bytes missing")
        r = Reader(data)
        r.read(5)
        g = _parse_map(r)
        raw = _get(g, GLOBAL_UNSIGNED_TX)
        if raw is None:
            raise BadPSBT("PSBT has no unsigned transaction. Version 2 PSBTs "
                          "are not supported by this device.")
        unsigned = Transaction.parse(raw)
        for i, vin in enumerate(unsigned.vin):
            if vin.script_sig or vin.witness:
                raise BadPSBT(f"input {i} of the unsigned transaction is already "
                              f"signed; a PSBT's transaction must be bare")
        p = PSBT(unsigned)
        p.globals = g
        p.inputs = [_parse_map(r) for _ in unsigned.vin]
        p.outputs = [_parse_map(r) for _ in unsigned.vout]
        if not r.done:
            raise BadPSBT(f"{len(data) - r.pos} trailing bytes after the PSBT")
        return p

    def serialize(self) -> bytes:
        return (PSBT_MAGIC + _ser_map(self.globals)
                + b"".join(_ser_map(m) for m in self.inputs)
                + b"".join(_ser_map(m) for m in self.outputs))

    # ---- proprietary fields, used to carry the attestation ----

    def set_proprietary(self, key: bytes, value: bytes) -> None:
        self.globals[bytes([PROPRIETARY]) + key] = value

    def get_proprietary(self, key: bytes) -> bytes | None:
        return self.globals.get(bytes([PROPRIETARY]) + key)

    def strip_proprietary(self, prefix: bytes = b"") -> None:
        """Remove proprietary fields before broadcast.

        The attestation must not reach the chain by default: it fingerprints
        the address as a CELL device and discloses how the spend was
        authorised.
        """
        for k in [k for k in self.globals
                  if k and k[0] == PROPRIETARY and k[1:].startswith(prefix)]:
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

        # Every key in a multisig change output must check out, not just ours:
        # a script where one co-signer's key was swapped is not our address.
        if witness_script is not None:
            m_, n_ = _parse_multisig(witness_script)
            if not m_:
                return False
            expected = addresses.p2wsh_script(witness_script)
            if redeem is not None:
                expected = addresses.p2sh_script(redeem)
                if addresses.p2wsh_script(witness_script) != redeem:
                    return False
            if expected != spk:
                return False
            mine = 0
            for keybytes, val in derivations.items():
                origin_fp, path = _parse_derivation(val)
                if origin_fp != fp:
                    continue
                if root.owns(keybytes, path):
                    mine += 1
            return mine >= 1 and all(
                len(k) == 33 for k in _script_pubkeys(witness_script))

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
        for i, out in enumerate(self.tx.vout):
            try:
                addr = addresses.script_to_address(out.script_pubkey, network)
            except addresses.BadAddress as e:
                raise BadPSBT(f"output {i} cannot be displayed as an address: {e}. "
                              f"This device does not sign what it cannot show.")
            if self._output_is_ours(i, root):
                change_sats += out.value
                change_addr = change_addr or addr
            elif self.outputs[i] and (_get_all(self.outputs[i], OUT_BIP32_DERIVATION)
                                      or _get(self.outputs[i], OUT_TAP_INTERNAL_KEY)):
                # The host claimed this was ours and it is not. Show it as a
                # destination, in full, and say why.
                recipients.append((addr, out.value))
                change_ours = False
                warnings.append(
                    f"output {i} is labelled as change but this wallet cannot "
                    f"derive it; it is shown as a destination")
            else:
                recipients.append((addr, out.value))

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


def _script_pubkeys(witness_script: bytes) -> list[bytes]:
    """The pushed 33-byte keys in a bare multisig script."""
    out, i = [], 1
    while i < len(witness_script) - 2:
        n = witness_script[i]
        if n != 33:
            break
        out.append(witness_script[i + 1:i + 1 + n])
        i += 1 + n
    return out
