#!/usr/bin/env python3
"""EIP-712 typed data, and the EIP-7702 delegation authorisation.

WHY THIS EXISTS. BUILD.md section 5 says the device never builds a transaction:
it signs an authorisation and the companion submits it. `eth.py` does not
actually work that way. It builds a whole EIP-1559 transaction, holds the
account's nonce, and prices `gas_limit * max_fee_per_gas`, because an EOA has
no other way to move value.

A smart account does. The authorisation is an EIP-712 `Execute` message, the
account's own contract holds the nonce, and whoever relays it pays the gas. So
the device signs three fields and a domain, holds no gas, and never has to
reason about a fee it cannot bound. That is the shape section 5 describes.

WHAT IT WILL SIGN. One thing: a value transfer out of a registered smart
account, with empty calldata. `Execute(address target, uint256 value, bytes
data, uint32 nonce)` with `data` empty renders as a sentence:

    SEND 1.5 ETH from treasury, to 0xCD2a..., account nonce 7, on Ethereum

Calldata stays refused, for the reason in BUILD.md section 5. That includes the
account's own governance calls, which are `execute(target=self, data=...)`:
changing owners, changing the threshold, cancelling a queued transaction. Those
are renderable in principle, from a fixed table of selectors decoded on the
device, and they are deliberately not here yet. A self-call is refused.

THE DOMAIN IS THE REPLAY DEFENCE. `chainId` and `verifyingContract` are inside
the domain separator, so an Execute signature is bound to one chain and one
deployment. That is strictly more than the EOA path pins, which is why the
registration below records the account address rather than accepting it from
the payload: an attacker who can choose `verifyingContract` can ask for a
signature that authorises a spend from an account the owner has never seen.

EIP-7702, AND WHY IT IS BLOOD-LOCKED. A delegation authorisation is
`keccak(0x05 || rlp([chain_id, address, nonce]))`. Three fields, all
displayable. It also hands the account's entire behaviour to a contract, at
which point every later signature means whatever that contract says it means.
It is reprovisioning under another name, so `ops.Delegation` reports
`account.delegate` and `policy.ALWAYS_BLOOD` holds it.

Two rules the device enforces on it, both of which have cost people accounts:

  chain_id 0 is refused. It is legal, and it means the authorisation is valid
  on every chain that exists and every chain that ever will.

  The implementation must be registered first. The signature commits to the
  address it delegates to; it does not commit to what that address contains.

WHAT THIS DOES NOT SOLVE. A 7702 authorisation does not commit to the
initialisation call that has to run in the same transaction, so a relayer can
delegate to the implementation the owner approved and initialise it with their
own owners. That is security consideration 2 of the EIP itself. It cannot be
closed by signing the authorisation alone, so `provision.py` records the
expected post-delegation state and `VALIDATION.md` carries the gap open.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import eth
from addresses import to_checksum_address, valid_checksum_address
from hashes import keccak256


class BadTypedData(ValueError):
    """A typed-data message this device will not build or sign."""


# EIP-712 section "Definition of domainSeparator". Only these four fields, in
# this order: a domain with a salt or a different field order is a different
# separator, and this device only signs for accounts it registered itself.
DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)")

# Transcribed from the account contract. If a deployment uses a different
# struct, every signature this device makes for it is a signature over a
# message that deployment will not recognise -- which fails closed, but it
# fails after the owner has already bled.
EXECUTE_TYPEHASH = keccak256(
    b"Execute(address target,uint256 value,bytes data,uint32 nonce)")

MAGIC_7702 = 0x05
UINT32_MAX = 2**32 - 1
UINT256_MAX = 2**256 - 1
ZERO_ADDRESS = "0x" + "0" * 40


def _word(value: int) -> bytes:
    """One ABI word. Rejects anything that does not fit, instead of masking."""
    if not 0 <= value <= UINT256_MAX:
        raise BadTypedData(f"{value} does not fit a uint256")
    return value.to_bytes(32, "big")


def _address_word(addr: str) -> bytes:
    """An address as a left-padded ABI word, checksum checked on the way."""
    return b"\x00" * 12 + _address_bytes(addr)


def _address_bytes(addr: str) -> bytes:
    if not isinstance(addr, str):
        raise BadTypedData(f"address must be a string, got {type(addr).__name__}")
    a = addr.removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdefABCDEF" for c in a):
        raise BadTypedData(f"{addr!r} is not a 20-byte hex address")
    if not valid_checksum_address(addr):
        # A mixed-case address that fails EIP-55 is a typo or a substitution.
        # Refusing costs a re-scan; accepting costs the transfer.
        raise BadTypedData(f"{addr} fails its EIP-55 checksum")
    return bytes.fromhex(a)


def domain_separator(name: str, version: str, chain_id: int,
                     verifying_contract: str) -> bytes:
    """hashStruct of the EIP712Domain, built here and never accepted ready-made."""
    if not name or not version:
        raise BadTypedData("a domain needs both a name and a version")
    return keccak256(DOMAIN_TYPEHASH
                     + keccak256(name.encode())
                     + keccak256(version.encode())
                     + _word(chain_id)
                     + _address_word(verifying_contract))


def digest(separator: bytes, struct_hash: bytes) -> bytes:
    r"""The signing digest: keccak(0x19 0x01 || domainSeparator || hashStruct).

    Kept separate from the struct hashing so the published Ether Mail vector in
    the EIP can be run through the same code the device uses, rather than
    through a test-only reimplementation of it.
    """
    if len(separator) != 32 or len(struct_hash) != 32:
        raise BadTypedData("domain separator and struct hash are 32 bytes each")
    return keccak256(b"\x19\x01" + separator + struct_hash)


def execute_struct_hash(target: str, value: int, data: bytes, nonce: int) -> bytes:
    """hashStruct of one Execute message.

    `data` is hashed rather than inlined because it is a dynamic type, and it
    is required to be empty because this device does not sign calldata.
    """
    if data:
        raise BadTypedData(
            "this device refuses an Execute carrying calldata. It signs value "
            "transfers out of a smart account and nothing else. See BUILD.md "
            "section 5.")
    if not 0 <= nonce <= UINT32_MAX:
        raise BadTypedData(f"nonce {nonce} does not fit the account's uint32")
    return keccak256(EXECUTE_TYPEHASH
                     + _address_word(target)
                     + _word(value)
                     + keccak256(b"")
                     + _word(nonce))


# --------------------------------------------------------------------------
# Registered accounts
#
# Same argument as eth.register_chain and wallet.register_multisig. The device
# cannot tell whose account an address is, so it is told once, out of band, and
# refuses everything it was not told about. Without this, "sign an Execute for
# verifyingContract X" is a request the owner has no way to evaluate.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SmartAccount:
    """One account this device is willing to authorise spends from."""

    label: str
    address: str                    # the account itself, EIP-55
    chain_id: int
    implementation: str             # the code the account runs, EIP-55
    threshold: int = 1
    owners: tuple[str, ...] = ()
    domain_name: str = "Multisig"
    domain_version: str = "1"
    # True when the account is an EOA that delegated to `implementation` under
    # EIP-7702. Recorded because it changes what the account is worth: the key
    # behind that address stays a superuser, so a timelock on this account
    # bounds a relayer and does not bound the key holder.
    delegated_eoa: bool = False

    def check(self) -> None:
        if not self.label or len(self.label) > 16:
            raise BadTypedData("an account label is 1 to 16 characters")
        if any(c < " " or c == "\x7f" or not c.isprintable() for c in self.label):
            raise BadTypedData(
                f"account label {self.label!r} carries a character the display "
                f"cannot render as one column")
        if self.chain_id <= 0:
            raise BadTypedData(
                "chain id 0 is every chain at once. Register the one you mean.")
        if self.chain_id not in eth.CHAINS:
            raise BadTypedData(
                f"chain {self.chain_id} is not registered on this device, so "
                f"the confirmation screen could not name the network. Register "
                f"the chain first.")
        for role, addr in (("account", self.address),
                           ("implementation", self.implementation)):
            _address_bytes(addr)
            if addr.lower() == ZERO_ADDRESS:
                raise BadTypedData(f"the {role} address is the zero address")
        if self.address.lower() == self.implementation.lower():
            raise BadTypedData(
                "the account and its implementation are the same address")
        if not 1 <= self.threshold <= max(1, len(self.owners) or 1):
            raise BadTypedData(
                f"{self.threshold} of {len(self.owners)} is not a usable quorum")
        for owner in self.owners:
            _address_bytes(owner)
        if len(set(o.lower() for o in self.owners)) != len(self.owners):
            raise BadTypedData("two owners are the same address")

    def separator(self) -> bytes:
        return domain_separator(self.domain_name, self.domain_version,
                                self.chain_id, self.address)

    def spend_digest(self, target: str, value: int, nonce: int) -> bytes:
        """What the owner's signature will commit to, built from what it shows."""
        if target.lower() == self.address.lower():
            # execute(target=self, ...) is how owners, threshold, delay and
            # queued transactions are changed. All of it is calldata, so none
            # of it can be rendered yet, so none of it is signed yet.
            raise BadTypedData(
                "refusing a call from the account to itself. That is how the "
                "account's own configuration is changed, and it travels as "
                "calldata this device cannot render.")
        return digest(self.separator(),
                      execute_struct_hash(target, value, b"", nonce))


ACCOUNTS: dict[str, SmartAccount] = {}


def register_account(account: SmartAccount) -> None:
    """Record an account, refusing a relabel of one already registered."""
    account.check()
    existing = ACCOUNTS.get(account.label)
    if existing is not None and existing != account:
        raise BadTypedData(
            f"account {account.label!r} is already registered at "
            f"{existing.address} on chain {existing.chain_id}. Registering a "
            f"second account under one label means the confirmation screen "
            f"names the wrong one.")
    for other in ACCOUNTS.values():
        if (other.address.lower() == account.address.lower()
                and other.chain_id == account.chain_id
                and other.label != account.label):
            raise BadTypedData(
                f"{account.address} on chain {account.chain_id} is already "
                f"registered as {other.label!r}")
    ACCOUNTS[account.label] = account


def account(label: str) -> SmartAccount:
    try:
        return ACCOUNTS[label]
    except KeyError:
        raise BadTypedData(
            f"no smart account registered as {label!r}. This device signs for "
            f"{', '.join(sorted(ACCOUNTS)) or 'no accounts yet'}.") from None


# --------------------------------------------------------------------------
# EIP-7702
# --------------------------------------------------------------------------


def delegation_digest(chain_id: int, address: str, nonce: int) -> bytes:
    """keccak(0x05 || rlp([chain_id, address, nonce])), per EIP-7702.

    The nonce here is the EOA's own transaction nonce, not an account nonce.
    """
    if chain_id == 0:
        raise BadTypedData(
            "refusing a delegation with chain id 0. That is valid on every "
            "chain at once, including chains that do not exist yet, and it "
            "cannot be revoked on a chain the owner never uses.")
    if chain_id < 0:
        raise BadTypedData("negative chain id")
    if not 0 <= nonce <= UINT256_MAX:
        raise BadTypedData(f"nonce {nonce} does not fit a uint256")
    payload = eth.rlp_encode([chain_id, _address_bytes(address), nonce])
    return keccak256(bytes([MAGIC_7702]) + payload)


def _selftest() -> int:                                     # pragma: no cover
    import test_eip712
    return test_eip712.main()


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(_selftest())
