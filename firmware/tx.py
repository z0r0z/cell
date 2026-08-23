"""Bitcoin transactions and the three sighash algorithms.

A signature does not commit to "a transaction". It commits to a digest, and
which digest depends on the script type and the sighash flag. Getting that
wrong does not produce an error — it produces a signature that is simply
invalid, or worse, one that is valid over something other than what the owner
approved. So all three algorithms live here, side by side, and psbt.py picks
between them from the input's own script rather than from anything the host
asserts.

  Legacy (pre-segwit)   Serialises a modified copy of the transaction. It does
                        NOT commit to input amounts, which is why a legacy
                        input's value can only be learned from the full parent
                        transaction.
  BIP-143 (segwit v0)   Commits to the amount of the input being signed, but
                        not to the amounts of the others. That gap is the
                        fee-inflation attack: a host that lies about one
                        input's value can make the owner pay the difference as
                        fee. psbt.py closes it by requiring the parent
                        transaction for every v0 input and checking its txid.
  BIP-341 (taproot)     Commits to every input's amount and scriptPubKey at
                        once, which is what makes witness_utxo alone safe
                        there and nowhere else.

SIGHASH_ALL only. Every other flag lets someone else change part of the
transaction after the owner approved it, and this device signs what it
displayed or it signs nothing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from hashes import sha256d, tagged

SIGHASH_ALL = 0x01
SIGHASH_DEFAULT = 0x00           # taproot's implicit ALL


class BadTransaction(ValueError):
    """A transaction that does not parse, or that we refuse to sign."""


# --------------------------------------------------------------------------
# Serialisation primitives
# --------------------------------------------------------------------------


def ser_compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class Reader:
    """A cursor that refuses to read past the end.

    Every parse failure in this file is a refusal, never a partial result. A
    truncated transaction that half-parses is a transaction the owner is shown
    incorrectly.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise BadTransaction(
                f"truncated: wanted {n} bytes at offset {self.pos}, "
                f"{len(self.data) - self.pos} remain")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def compact(self) -> int:
        first = self.read(1)[0]
        if first < 0xFD:
            return first
        width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        v = int.from_bytes(self.read(width), "little")
        # Non-minimal encodings are a malleability vector and are not valid.
        if (width == 2 and v < 0xFD) or (width == 4 and v <= 0xFFFF) \
                or (width == 8 and v <= 0xFFFFFFFF):
            raise BadTransaction("non-minimal compact size")
        return v

    def bytes_with_len(self) -> bytes:
        return self.read(self.compact())

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    @property
    def done(self) -> bool:
        return self.pos >= len(self.data)


# --------------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------------


@dataclass
class TxIn:
    txid: bytes                     # 32, internal byte order
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFD      # opt in to RBF by default
    witness: list[bytes] = field(default_factory=list)

    def outpoint(self) -> bytes:
        return self.txid + self.vout.to_bytes(4, "little")

    def txid_hex(self) -> str:
        """Display order, which is the reverse of the wire order."""
        return self.txid[::-1].hex()


@dataclass
class TxOut:
    value: int                      # satoshis
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return (self.value.to_bytes(8, "little")
                + ser_compact(len(self.script_pubkey)) + self.script_pubkey)


@dataclass
class Transaction:
    version: int = 2
    vin: list[TxIn] = field(default_factory=list)
    vout: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    # ---- parse ----

    @staticmethod
    def parse(data: bytes) -> "Transaction":
        r = Reader(data)
        tx = Transaction(version=r.u32())
        n_in = r.compact()
        segwit = False
        if n_in == 0:
            flag = r.read(1)[0]
            if flag != 0x01:
                raise BadTransaction(f"unknown segwit flag {flag:#04x}")
            segwit = True
            n_in = r.compact()
            if n_in == 0:
                raise BadTransaction("segwit transaction with no inputs")
        for _ in range(n_in):
            tx.vin.append(TxIn(txid=r.read(32), vout=r.u32(),
                               script_sig=r.bytes_with_len(), sequence=r.u32()))
        for _ in range(r.compact()):
            tx.vout.append(TxOut(value=r.u64(), script_pubkey=r.bytes_with_len()))
        if segwit:
            for vin in tx.vin:
                vin.witness = [r.bytes_with_len() for _ in range(r.compact())]
        tx.locktime = r.u32()
        if not r.done:
            raise BadTransaction(f"{len(data) - r.pos} trailing bytes")
        return tx

    # ---- serialise ----

    def serialize(self, witness: bool = True) -> bytes:
        has_wit = witness and any(i.witness for i in self.vin)
        out = self.version.to_bytes(4, "little")
        if has_wit:
            out += b"\x00\x01"
        out += ser_compact(len(self.vin))
        for i in self.vin:
            out += (i.outpoint() + ser_compact(len(i.script_sig)) + i.script_sig
                    + i.sequence.to_bytes(4, "little"))
        out += ser_compact(len(self.vout))
        for o in self.vout:
            out += o.serialize()
        if has_wit:
            for i in self.vin:
                out += ser_compact(len(i.witness))
                for item in i.witness:
                    out += ser_compact(len(item)) + item
        return out + self.locktime.to_bytes(4, "little")

    def txid(self) -> bytes:
        """Witness-stripped hash, internal order. This is what an outpoint names."""
        return sha256d(self.serialize(witness=False))

    def txid_hex(self) -> str:
        return self.txid()[::-1].hex()

    # ---- sighash ----

    def _prevouts_hash(self) -> bytes:
        return sha256d(b"".join(i.outpoint() for i in self.vin))

    def _sequences_hash(self) -> bytes:
        return sha256d(b"".join(i.sequence.to_bytes(4, "little") for i in self.vin))

    def _outputs_hash(self) -> bytes:
        return sha256d(b"".join(o.serialize() for o in self.vout))

    def sighash_legacy(self, index: int, script_code: bytes,
                       hashtype: int = SIGHASH_ALL) -> bytes:
        """Pre-segwit. Only SIGHASH_ALL is implemented, deliberately."""
        if hashtype != SIGHASH_ALL:
            raise BadTransaction("this device signs SIGHASH_ALL only")
        copy = Transaction(self.version, [], list(self.vout), self.locktime)
        for n, i in enumerate(self.vin):
            copy.vin.append(TxIn(i.txid, i.vout,
                                 script_code if n == index else b"", i.sequence))
        return sha256d(copy.serialize(witness=False)
                       + hashtype.to_bytes(4, "little"))

    def sighash_segwit_v0(self, index: int, script_code: bytes, amount: int,
                          hashtype: int = SIGHASH_ALL) -> bytes:
        """BIP-143."""
        if hashtype != SIGHASH_ALL:
            raise BadTransaction("this device signs SIGHASH_ALL only")
        i = self.vin[index]
        pre = (self.version.to_bytes(4, "little")
               + self._prevouts_hash()
               + self._sequences_hash()
               + i.outpoint()
               + ser_compact(len(script_code)) + script_code
               + amount.to_bytes(8, "little")
               + i.sequence.to_bytes(4, "little")
               + self._outputs_hash()
               + self.locktime.to_bytes(4, "little")
               + hashtype.to_bytes(4, "little"))
        return sha256d(pre)

    def sighash_taproot(self, index: int, amounts: list[int],
                        scripts: list[bytes],
                        hashtype: int = SIGHASH_DEFAULT,
                        annex: bytes | None = None) -> bytes:
        """BIP-341 key-path spend.

        Note the arguments: EVERY input's amount and script, not just this
        one's. That is the property that makes taproot immune to the
        fee-inflation attack, and it is why they are required here rather than
        optional.
        """
        if hashtype not in (SIGHASH_DEFAULT, SIGHASH_ALL):
            raise BadTransaction("this device signs SIGHASH_ALL only")
        if len(amounts) != len(self.vin) or len(scripts) != len(self.vin):
            raise BadTransaction("taproot sighash needs every input's amount and script")

        sha_amounts = hashlib.sha256(
            b"".join(a.to_bytes(8, "little") for a in amounts)).digest()
        sha_scripts = hashlib.sha256(
            b"".join(ser_compact(len(s)) + s for s in scripts)).digest()
        sha_prevouts = hashlib.sha256(
            b"".join(i.outpoint() for i in self.vin)).digest()
        sha_sequences = hashlib.sha256(
            b"".join(i.sequence.to_bytes(4, "little") for i in self.vin)).digest()
        sha_outputs = hashlib.sha256(
            b"".join(o.serialize() for o in self.vout)).digest()

        # BIP-341: spend_type = (ext_flag * 2) + annex_present. ext_flag is 0
        # for a key-path spend, so an annex makes this 1, not 2. A 2 claims
        # ext_flag=1 -- a tapscript spend, which also has to append a
        # tapleaf_hash -- so it produces a digest for a different spend shape
        # entirely and therefore a signature that does not verify.
        spend_type = 0x01 if annex is not None else 0x00
        msg = (b"\x00"                                  # sighash epoch
               + bytes([hashtype])
               + self.version.to_bytes(4, "little")
               + self.locktime.to_bytes(4, "little")
               + sha_prevouts + sha_amounts + sha_scripts + sha_sequences
               + sha_outputs
               + bytes([spend_type])
               + index.to_bytes(4, "little"))
        if annex is not None:
            msg += hashlib.sha256(ser_compact(len(annex)) + annex).digest()
        return tagged("TapSighash", msg)


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Transactions — parse, serialise, BIP-143 and BIP-341 sighash\n")
    checks = []

    # A real mainnet transaction: the first one that ever paid a person,
    # block 170, Satoshi to Hal Finney. Legacy, one input, two outputs.
    raw = bytes.fromhex(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857f"
        "cd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9"
        "d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbb"
        "ac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5"
        "f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7"
        "df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043"
        "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
        "b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00"
        "000000")
    tx = Transaction.parse(raw)
    checks.append(("parses the block-170 transaction", len(tx.vin) == 1
                   and len(tx.vout) == 2))
    checks.append(("round trips byte for byte", tx.serialize() == raw))
    checks.append(("txid matches the known value", tx.txid_hex() ==
                   "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"))
    checks.append(("output values read correctly",
                   [o.value for o in tx.vout] == [1000000000, 4000000000]))

    # BIP-143's own test vector: the native P2WPKH example.
    unsigned = bytes.fromhex(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4"
        "ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe2"
        "87d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280"
        "b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde"
        "42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    t = Transaction.parse(unsigned)
    script_code = bytes.fromhex("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")[1:]
    got = t.sighash_segwit_v0(1, script_code, 600000000)
    checks.append(("BIP-143 P2WPKH sighash", got.hex() ==
                   "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"))

    # BIP-143 P2SH-P2WPKH vector.
    u2 = bytes.fromhex(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb"
        "1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a4"
        "6a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97"
        "fea7ad0402e8bd8ad6d77c88ac92040000")
    t2 = Transaction.parse(u2)
    sc2 = bytes.fromhex("1976a91479091972186c449eb1ded22b78e40d009bdf008988ac")[1:]
    checks.append(("BIP-143 P2SH-P2WPKH sighash",
                   t2.sighash_segwit_v0(0, sc2, 1000000000).hex() ==
                   "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"))

    # Compact size, including the non-minimal encodings a malleating host might
    # send.
    checks.append(("compact size round trip",
                   all(Reader(ser_compact(n)).compact() == n
                       for n in (0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF,
                                 0x100000000))))
    for label, blob in [("2-byte", b"\xfd\x01\x00"), ("4-byte", b"\xfe\x01\x00\x00\x00"),
                        ("8-byte", b"\xff" + (1).to_bytes(8, "little"))]:
        try:
            Reader(blob).compact()
            checks.append((f"refuses non-minimal {label} compact size", False))
        except BadTransaction:
            checks.append((f"refuses non-minimal {label} compact size", True))

    # Truncation and trailing bytes must both refuse.
    for label, blob in [("truncated", raw[:-4]), ("trailing bytes", raw + b"\x00")]:
        try:
            Transaction.parse(blob)
            checks.append((f"refuses a {label} transaction", False))
        except BadTransaction:
            checks.append((f"refuses a {label} transaction", True))

    # Segwit serialisation: the txid must not change when a witness is added,
    # which is the entire point of segwit and the thing a PSBT relies on.
    wt = Transaction.parse(raw)
    before = wt.txid()
    wt.vin[0].witness = [b"\x01" * 71, b"\x02" * 33]
    checks.append(("witness does not change the txid", wt.txid() == before))
    checks.append(("witness serialisation is longer",
                   len(wt.serialize()) > len(wt.serialize(witness=False))))
    checks.append(("witness round trips",
                   Transaction.parse(wt.serialize()).vin[0].witness == wt.vin[0].witness))

    # Anything other than SIGHASH_ALL must be refused rather than signed.
    for name, fn in [("legacy", lambda: t.sighash_legacy(0, b"", 0x81)),
                     ("segwit v0", lambda: t.sighash_segwit_v0(0, b"", 1, 0x83)),
                     ("taproot", lambda: t.sighash_taproot(0, [1, 1], [b"", b""], 0x81))]:
        try:
            fn()
            checks.append((f"{name} refuses a non-ALL sighash flag", False))
        except BadTransaction:
            checks.append((f"{name} refuses a non-ALL sighash flag", True))

    # BIP-341 requires every input's amount and script; a caller that supplies
    # only the one being signed must be refused, not quietly accommodated.
    try:
        t.sighash_taproot(0, [1], [b""])
        checks.append(("taproot demands all amounts", False))
    except BadTransaction:
        checks.append(("taproot demands all amounts", True))

    # BIP-341 spend_type = (ext_flag * 2) + annex_present. A key-path spend has
    # ext_flag 0, so an annex makes it 1. This was 2 -- the tapscript value,
    # which also requires a tapleaf_hash the message does not carry -- so the
    # digest described a different spend shape and the signature would not have
    # verified. Rebuilt here independently rather than compared to itself.
    ann = b"\x50\xde\xad\xbe\xef"
    amts, spks = [100, 200], [b"\x51\x20" + b"\x11" * 32] * 2
    want = tagged("TapSighash",
                  b"\x00" + bytes([SIGHASH_DEFAULT])
                  + t.version.to_bytes(4, "little")
                  + t.locktime.to_bytes(4, "little")
                  + hashlib.sha256(b"".join(i.outpoint() for i in t.vin)).digest()
                  + hashlib.sha256(b"".join(a.to_bytes(8, "little") for a in amts)).digest()
                  + hashlib.sha256(b"".join(ser_compact(len(x)) + x for x in spks)).digest()
                  + hashlib.sha256(b"".join(i.sequence.to_bytes(4, "little")
                                            for i in t.vin)).digest()
                  + hashlib.sha256(b"".join(o.serialize() for o in t.vout)).digest()
                  + bytes([0x01])                       # ext_flag 0, annex present
                  + (0).to_bytes(4, "little")
                  + hashlib.sha256(ser_compact(len(ann)) + ann).digest())
    checks.append(("BIP-341 annex sets spend_type 1, not 2",
                   t.sighash_taproot(0, amts, spks, annex=ann) == want))
    checks.append(("the annex changes the digest",
                   t.sighash_taproot(0, amts, spks, annex=ann)
                   != t.sighash_taproot(0, amts, spks)))

    # And the taproot digest must actually depend on the other input's amount.
    a = t.sighash_taproot(0, [100, 200], [b"\x51\x20" + b"\x11" * 32] * 2)
    b = t.sighash_taproot(0, [100, 999], [b"\x51\x20" + b"\x11" * 32] * 2)
    checks.append(("taproot commits to every amount", a != b))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
