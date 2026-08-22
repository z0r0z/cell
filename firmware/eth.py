"""Ethereum — RLP, EIP-1559 transactions, and the signing hash.

An Ethereum signature commits to the chain id, the nonce, both gas prices, the
gas limit, the recipient, the value and the calldata. All of it. A device that
signs "send 1 ETH to Alice" without committing to the rest is not signing what
the owner read: the same authorisation replays on another chain, or at a gas
limit that drains the account in fees, or with calldata that does something
else entirely.

So this module builds the whole transaction on the device, from fields the
device displays, and hashes what it built. It never accepts a digest to sign,
because a digest is exactly the thing the owner cannot read.

TYPE 2 (EIP-1559) ONLY. Legacy and EIP-2930 transactions are still valid on
chain, but supporting three encodings triples the surface for a device whose
whole argument is that it renders what it signs. Every chain CELL targets has
supported type 2 since 2021.

NO CALLDATA. `data` must be empty. Arbitrary EVM calldata cannot be rendered
as a sentence the owner can evaluate — that is a scope decision stated in
BUILD.md section 5, and this module enforces it rather than trusting the
caller to have checked.
"""

from __future__ import annotations

from dataclasses import dataclass

import secp256k1 as ec
from addresses import BadAddress, to_checksum_address, valid_checksum_address
from hashes import keccak256

TX_TYPE_1559 = 0x02

# Chain ids the device will sign for, by name, so the display can say
# "Ethereum" rather than "chain 1" — and so an unknown chain is a refusal
# rather than a number the owner cannot evaluate.
CHAINS = {
    1: "Ethereum",
    10: "Optimism",
    137: "Polygon",
    8453: "Base",
    42161: "Arbitrum One",
    11155111: "Sepolia (test)",
}


class BadEthTransaction(ValueError):
    """A transaction this device will not build or sign."""


# --------------------------------------------------------------------------
# RLP
# --------------------------------------------------------------------------


def _rlp_len(prefix: int, n: int) -> bytes:
    if n < 56:
        return bytes([prefix + n])
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([prefix + 55 + len(length)]) + length


def rlp_encode(item) -> bytes:
    """Bytes, ints (as minimal big-endian) and lists. RLP has nothing else."""
    if isinstance(item, bool):
        raise BadEthTransaction("RLP has no boolean type")
    if isinstance(item, int):
        if item < 0:
            raise BadEthTransaction("RLP cannot encode a negative integer")
        item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, (bytes, bytearray)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80:
            return b
        return _rlp_len(0x80, len(b)) + b
    if isinstance(item, (list, tuple)):
        body = b"".join(rlp_encode(i) for i in item)
        return _rlp_len(0xC0, len(body)) + body
    raise BadEthTransaction(f"cannot RLP-encode {type(item).__name__}")


def rlp_decode(data: bytes):
    """Only used by the tests, to prove the encoder round trips."""
    out, rest = _rlp_decode_one(data)
    if rest:
        raise BadEthTransaction(f"{len(rest)} trailing bytes after RLP item")
    return out


def _rlp_decode_one(d: bytes):
    if not d:
        raise BadEthTransaction("RLP input is empty")
    p = d[0]
    if p < 0x80:
        return d[:1], d[1:]
    if p < 0xB8:
        n = p - 0x80
        return d[1:1 + n], d[1 + n:]
    if p < 0xC0:
        ln = p - 0xB7
        n = int.from_bytes(d[1:1 + ln], "big")
        return d[1 + ln:1 + ln + n], d[1 + ln + n:]
    if p < 0xF8:
        n = p - 0xC0
        body, rest = d[1:1 + n], d[1 + n:]
    else:
        ln = p - 0xF7
        n = int.from_bytes(d[1:1 + ln], "big")
        body, rest = d[1 + ln:1 + ln + n], d[1 + ln + n:]
    items = []
    while body:
        item, body = _rlp_decode_one(body)
        items.append(item)
    return items, rest


# --------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EthTransaction:
    """An EIP-1559 transaction, built from displayed fields.

    `max_fee_per_gas * gas_limit` is the worst case the owner can be charged,
    and it is that number — not the tip, not the base fee — that the display
    shows, because it is the only one that bounds the loss.
    """

    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to: str
    value: int
    data: bytes = b""

    def __post_init__(self):
        if self.chain_id not in CHAINS:
            raise BadEthTransaction(
                f"chain id {self.chain_id} is not one this device recognises. "
                f"Signing for an unnamed chain means the owner cannot tell "
                f"which network the transfer lands on.")
        for name in ("nonce", "max_priority_fee_per_gas", "max_fee_per_gas",
                     "gas_limit", "value"):
            v = getattr(self, name)
            if not isinstance(v, int) or v < 0:
                raise BadEthTransaction(f"{name} must be a non-negative integer")
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise BadEthTransaction("priority fee exceeds the max fee per gas")
        if self.gas_limit < 21000:
            raise BadEthTransaction("gas limit below the 21000 minimum for a transfer")
        if self.data:
            raise BadEthTransaction(
                "this device refuses transactions carrying calldata. It signs "
                "value transfers, which it can render in full; it cannot render "
                "an EVM call as something an owner could evaluate.")
        if not valid_checksum_address(self.to):
            raise BadEthTransaction(
                f"recipient {self.to!r} is not a valid address, or its EIP-55 "
                f"checksum does not match its capitalisation")
        if int(self.to.removeprefix("0x"), 16) == 0:
            raise BadEthTransaction("refusing to send to the zero address")

    # ---- encoding ----

    def to_bytes(self) -> bytes:
        return int(self.to.removeprefix("0x"), 16).to_bytes(20, "big")

    def _fields(self) -> list:
        return [self.chain_id, self.nonce, self.max_priority_fee_per_gas,
                self.max_fee_per_gas, self.gas_limit, self.to_bytes(),
                self.value, self.data, []]        # empty access list

    def signing_payload(self) -> bytes:
        return bytes([TX_TYPE_1559]) + rlp_encode(self._fields())

    def sighash(self) -> bytes:
        """keccak256 of the typed payload. This is what gets signed."""
        return keccak256(self.signing_payload())

    def encode_signed(self, r: int, s: int, y_parity: int) -> bytes:
        """The raw transaction to broadcast, ready for eth_sendRawTransaction."""
        if y_parity not in (0, 1):
            raise BadEthTransaction("y_parity must be 0 or 1")
        return bytes([TX_TYPE_1559]) + rlp_encode(
            self._fields() + [y_parity, r, s])

    def txid(self, r: int, s: int, y_parity: int) -> str:
        return "0x" + keccak256(self.encode_signed(r, s, y_parity)).hex()

    # ---- display ----

    def max_fee_wei(self) -> int:
        return self.max_fee_per_gas * self.gas_limit

    def chain_name(self) -> str:
        return CHAINS[self.chain_id]


def sign(tx: EthTransaction, seckey: bytes) -> tuple[int, int, int]:
    """Returns (r, s, y_parity). Verifies before returning.

    Ethereum verifies by recovering the
    sender from the signature, so a wrong parity byte produces a transaction
    that is valid-looking and credited to an address nobody controls.
    """
    digest = tx.sighash()
    # No low-R grinding here: it is a Bitcoin size optimisation, and every
    # Ethereum library signs with plain RFC 6979. Matching them byte for byte
    # keeps the cross-check in the tests meaningful.
    r, s, rec = ec.ecdsa_sign(digest, seckey, grind_low_r=False)
    y_parity = rec & 1
    if ec.ecdsa_recover(digest, r, s, y_parity) != ec.pubkey_compressed(seckey):
        raise BadEthTransaction("signature does not recover to the signing key")
    return r, s, y_parity


def sender(tx: EthTransaction, r: int, s: int, y_parity: int) -> str:
    """Recover the sender address, as a node would."""
    from addresses import eth_address
    return eth_address(ec.ecdsa_recover(tx.sighash(), r, s, y_parity))


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Ethereum — RLP, EIP-1559 encoding, signature recovery\n")
    checks = []

    # RLP vectors from the Ethereum yellow paper and the standard test set.
    for item, want in [
        (b"dog", "83646f67"),
        (b"", "80"),
        (b"\x00", "00"),
        (b"\x0f", "0f"),
        (b"\x04\x00", "820400"),
        (0, "80"),
        (15, "0f"),
        (1024, "820400"),
        ([], "c0"),
        ([b"cat", b"dog"], "c88363617483646f67"),
        ([[], [[]], [[], [[]]]], "c7c0c1c0c3c0c1c0"),
        (b"a" * 56, "b838" + "61" * 56),
    ]:
        checks.append((f"RLP {str(item)[:24]}", rlp_encode(item).hex() == want))

    checks.append(("RLP round trips a nested list",
                   rlp_decode(rlp_encode([b"cat", [b"dog", b""], b"x" * 100]))
                   == [b"cat", [b"dog", b""], b"x" * 100]))
    for bad in (-1, True, 3.5, None):
        try:
            rlp_encode(bad)
            checks.append((f"RLP refuses {bad!r}", False))
        except BadEthTransaction:
            checks.append((f"RLP refuses {bad!r}", True))

    # A transaction signed with the well-known EIP-155 example key.
    sk = bytes.fromhex(
        "4646464646464646464646464646464646464646464646464646464646464646")
    from addresses import eth_address
    me = eth_address(ec.pubkey_compressed(sk))
    checks.append(("key derives the known address",
                   me == "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"))

    t = EthTransaction(chain_id=1, nonce=9,
                       max_priority_fee_per_gas=2_000_000_000,
                       max_fee_per_gas=30_000_000_000,
                       gas_limit=21000,
                       to="0x3535353535353535353535353535353535353535",
                       value=10**18)
    r, s, yp = sign(t, sk)
    checks.append(("signs and recovers to the sender", sender(t, r, s, yp) == me))
    checks.append(("signing is deterministic", sign(t, sk) == (r, s, yp)))
    checks.append(("typed envelope starts with 0x02",
                   t.signing_payload()[0] == TX_TYPE_1559))
    checks.append(("signed encoding starts with 0x02",
                   t.encode_signed(r, s, yp)[0] == TX_TYPE_1559))
    checks.append(("signed encoding round trips through RLP",
                   len(rlp_decode(t.encode_signed(r, s, yp)[1:])) == 12))
    checks.append(("txid is 32 bytes of hex", len(t.txid(r, s, yp)) == 66))

    # Every signed field must change the digest. This is the test that would
    # catch a field accidentally left out of _fields().
    base = t.sighash()
    variants = {
        "chain_id": {"chain_id": 137},
        "nonce": {"nonce": 10},
        "priority fee": {"max_priority_fee_per_gas": 3_000_000_000},
        "max fee": {"max_fee_per_gas": 31_000_000_000},
        "gas limit": {"gas_limit": 22000},
        "recipient": {"to": "0x3535353535353535353535353535353535353536"},
        "value": {"value": 10**18 + 1},
    }
    for name, change in variants.items():
        fields = {**t.__dict__, **change}
        checks.append((f"digest commits to the {name}",
                       EthTransaction(**fields).sighash() != base))

    # The refusals.
    def refuses(label, **kw):
        fields = {**t.__dict__, **kw}
        try:
            EthTransaction(**fields)
            checks.append((label, False))
        except (BadEthTransaction, BadAddress):
            checks.append((label, True))

    refuses("refuses calldata", data=b"\xa9\x05\x9c\xbb")
    refuses("refuses an unknown chain id", chain_id=999999)
    refuses("refuses a gas limit below 21000", gas_limit=20999)
    refuses("refuses a negative value", value=-1)
    refuses("refuses a priority fee above the max fee",
            max_priority_fee_per_gas=40_000_000_000)
    refuses("refuses the zero address",
            to="0x0000000000000000000000000000000000000000")
    refuses("refuses a bad EIP-55 checksum",
            to="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed")
    refuses("refuses a short address", to="0x353535")

    # An address given in lowercase claims no checksum and is accepted; the
    # display then shows it checksummed so the owner sees the canonical form.
    ok_lower = EthTransaction(**{**t.__dict__,
                                 "to": "0x3535353535353535353535353535353535353535"})
    checks.append(("lowercase address accepted",
                   ok_lower.to_bytes().hex() == "35" * 20))
    checks.append(("display form is checksummed",
                   to_checksum_address(ok_lower.to)
                   == "0x3535353535353535353535353535353535353535"))

    # Worst-case fee, which is the number the owner is shown.
    checks.append(("max fee is price times limit",
                   t.max_fee_wei() == 30_000_000_000 * 21000))
    checks.append(("chain is named", t.chain_name() == "Ethereum"))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
