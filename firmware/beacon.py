#!/usr/bin/env python3
"""Proof of life: the attestation with no transaction attached.

WHAT THIS IS FOR. Every dead-man switch in self-custody keys off SIGNING
ACTIVITY, which conflates two different facts. "This key moved" is not "this
person is alive": a stolen key resets the clock, and a careful owner who simply
does not spend for a year looks dead. CELL is the only device that can separate
them, because the touch gate measures a body rather than a decision.

So the beacon is the existing attestation record with no transaction under it.
Fifteen seconds, no consumable, and `CellRegistry.heartbeat` writes down when a
living human was last proven to be here. What reads that number is somebody
else's business: an inheritance path, a recovery quorum, an insurer, a
multisig that wants a co-signer's pulse before it treats them as present.

NOTHING NEW IS SIGNED. `CellRegistry.actionDigest` already commits to the
chain, the contract and the claimant, and takes a `purpose` word. The beacon is
that function with a purpose that carries a period index:

    purpose = keccak(abi.encode(BEACON_TAG, epoch))
    digest  = keccak(abi.encode(chainid, registry, claimant, purpose))

which is the digest `attest.py` was already going to sign. No new record
format, no new curve, no second key.

THE DEVICE HAS NO CLOCK, AND DOES NOT NEED ONE. It has no battery and no
network, so it cannot honestly attest to time -- `attest.py` says so and it is
still true. The epoch is supplied by the companion and DISPLAYED AS A DATE, so
the owner is the clock. A companion that asks for a period that is not the
current one is asking the owner to approve a date they can read.

The chain does have a clock, and that is where the real bound lives.
`heartbeat` accepts a beacon only while its epoch IS the current epoch. A
record harvested for a future period cannot be submitted early, and cannot be
submitted late.

WHAT REMAINS, AND IT IS WORTH SAYING PLAINLY. A companion that tricks the owner
into approving N future periods can keep a dead owner alive for exactly those N
periods. Each one costs a separate gate and shows a separate wrong date. The
defence is the date on the screen, and the cost is linear in the lie.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

import eip712
from hashes import keccak256

# keccak256("CELL/beacon-v1"). Domain separation from every other purpose word
# a registry might use: a beacon must not be redeemable as an allowlist entry
# and an allowlist entry must not read as proof of life.
BEACON_TAG = keccak256(b"CELL/beacon-v1")

SECONDS_PER_DAY = 86_400
DEFAULT_PERIOD_DAYS = 30
UNIX_EPOCH = date(1970, 1, 1)


class BadBeacon(ValueError):
    """A beacon this device will not build or sign."""


def epoch_of(day: date, period_days: int = DEFAULT_PERIOD_DAYS) -> int:
    """The period index containing `day`. Integer division, from the Unix epoch."""
    if period_days <= 0:
        raise BadBeacon("a period is at least one day")
    return (day - UNIX_EPOCH).days // period_days


def epoch_dates(epoch: int, period_days: int = DEFAULT_PERIOD_DAYS) -> tuple[date, date]:
    """(first day, last day) of a period, for the confirmation screen.

    The screen shows a date range because that is the only part of this the
    owner can check. An epoch index is a number nobody can evaluate, and a
    number nobody can evaluate is the thing this device refuses to sign.
    """
    if epoch < 0:
        raise BadBeacon("negative period")
    if period_days <= 0:
        raise BadBeacon("a period is at least one day")
    start = UNIX_EPOCH + timedelta(days=epoch * period_days)
    return start, start + timedelta(days=period_days - 1)


# keccak256("CELL/redeem-v1"). The other half of the separation above.
# `CellRegistry.redeem` takes an ARBITRARY purpose word from its caller, so
# without a tag of its own the caller can simply spell a beacon purpose and
# redeem a proof of life as an allowlist entry. The tag makes the two
# namespaces disjoint by construction rather than by convention.
REDEEM_TAG = keccak256(b"CELL/redeem-v1")


def redeem_purpose(word: bytes) -> bytes:
    """keccak(abi.encode(bytes32 tag, bytes32 word)), as CellRegistry does."""
    if len(word) != 32:
        raise BadBeacon("a purpose word is 32 bytes")
    return keccak256(REDEEM_TAG + word)


def purpose(epoch: int) -> bytes:
    """keccak(abi.encode(bytes32 tag, uint256 epoch)), as the registry computes it."""
    if not 0 <= epoch <= eip712.UINT256_MAX:
        raise BadBeacon(f"period {epoch} does not fit a uint256")
    return keccak256(BEACON_TAG + eip712._word(epoch))


@dataclass(frozen=True)
class Beacon:
    """One proof-of-life claim, and the registry it is addressed to."""

    registry: str                   # the CellRegistry deployment, EIP-55
    claimant: str                   # the address whose life is being proven
    chain_id: int
    chain_name: str
    epoch: int
    period_days: int = DEFAULT_PERIOD_DAYS

    def check(self) -> None:
        if self.chain_id <= 0:
            raise BadBeacon(
                "chain id 0 is every chain at once. A proof of life addressed "
                "to every chain is redeemable on all of them.")
        if self.period_days != DEFAULT_PERIOD_DAYS:
            # The digest commits to the EPOCH and to nothing else, while the
            # screen shows dates computed from the period. So a non-default
            # period moves the date the owner reads without moving the number
            # the chain checks: fifteen seconds of a fingertip under today's
            # date, redeemable decades away. CellRegistry.EPOCH_SECONDS is a
            # constant precisely because both sides have to already know it.
            raise BadBeacon(
                f"a beacon period is {DEFAULT_PERIOD_DAYS} days, fixed by "
                f"CellRegistry.EPOCH_SECONDS. A {self.period_days}-day period "
                f"shows the owner dates the chain does not mean, and the "
                f"digest does not commit to it.")
        # eip712 raises its own type for a bad address. A caller holding a
        # Beacon should have one exception to catch, not two, so it is
        # re-raised rather than allowed to leak the other module's.
        for role, addr in (("registry", self.registry),
                           ("claimant", self.claimant)):
            try:
                eip712._address_bytes(addr)
            except eip712.BadTypedData as e:
                raise BadBeacon(f"{role}: {e}") from None
            if eip712._is_zero_address(addr):
                raise BadBeacon(f"the {role} address is the zero address")
        if self.registry.lower() == self.claimant.lower():
            raise BadBeacon("the registry and the claimant are the same address")
        epoch_dates(self.epoch, self.period_days)       # refuses a negative one

    def digest(self) -> bytes:
        """What the attestation key signs. `CellRegistry.actionDigest`, exactly."""
        self.check()
        return keccak256(eip712._word(self.chain_id)
                         + eip712._address_word(self.registry)
                         + eip712._address_word(self.claimant)
                         + purpose(self.epoch))

    def window(self) -> tuple[date, date]:
        return epoch_dates(self.epoch, self.period_days)


def _selftest() -> int:                                     # pragma: no cover
    import test_beacon
    return test_beacon.main()


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(_selftest())
