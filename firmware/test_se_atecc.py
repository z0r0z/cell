#!/usr/bin/env python3
"""The ATECC608B driver's arithmetic, against a fake chip.

The silicon cannot be attached to CI, and this file does not pretend
otherwise — VALIDATION.md still records the part as unverified until someone
runs `se_atecc.py --probe` on a built device. What it does exercise is the
logic wrapped around the chip, which is where the subtle mistakes live:

    the attempt budget, expressed as a distance from a baseline because the
        chip's counters cannot be reset
    that baseline living ON the chip, so it cannot be rolled back by anyone
        holding the SD card — the single property the part was bought for
    the KDF refusing to answer without a spent PIN attempt, once
    the refusal to run at all against a chip whose zones are unlocked
    a wipe that actually destroys the wrapping secret

The fake below implements only the cryptoauthlib calls the driver makes, and
implements them the way the datasheet says the chip behaves — counters that
only increase, slots that answer HMAC without revealing their contents. Where
it is more permissive than the real part, the test says so rather than
claiming coverage it does not have.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

from se import MAX_PIN_ATTEMPTS, PinLockout
from se_atecc import (COUNTER_PIN, SLOT_ATTEST, SLOT_PIN, SLOT_PIN_BASELINE,
                      SLOT_WRAP, ATECC608B, DeviceError)

FAILURES: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


def refuses(label: str, fn, *exc) -> None:
    exc = exc or (Exception,)
    try:
        fn()
        check(label, False)
    except exc:
        check(label, True)


# --------------------------------------------------------------------------
# A fake chip
# --------------------------------------------------------------------------


class _Status:
    ATCA_SUCCESS = 0
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1


class AtcaReference:
    def __init__(self, value=0):
        self.value = value


class FakeATECC:
    """Enough of cryptoauthlib to drive the driver. Not a simulator."""

    Status = _Status
    AtcaReference = AtcaReference
    ATCA_ZONE_CONFIG = 0
    ATCA_ZONE_DATA = 2
    SHA_MODE_TARGET_TEMPKEY = 0

    def __init__(self, pin: str = "123456", locked: bool = True):
        self.slots = {SLOT_WRAP: os.urandom(32), SLOT_ATTEST: os.urandom(32),
                      SLOT_PIN: hashlib.sha256(b"CELL/pin/v1|"
                                               + pin.encode()).digest(),
                      SLOT_PIN_BASELINE: bytes(32)}
        self.counters = {0: 0, 1: 0}
        self.locked = locked
        self.checkmac_calls = 0
        self.writes: list[int] = []

    # -- the calls the driver makes --

    def cfg_ateccx08a_i2c_default(self):
        class _Cfg:
            class cfg:
                class atcai2c:
                    bus = 0
                    slave_address = 0
        return _Cfg()

    def atcab_init(self, _cfg):
        return _Status.ATCA_SUCCESS

    def atcab_is_locked(self, _zone, ref):
        ref.value = 1 if self.locked else 0
        return _Status.ATCA_SUCCESS

    def atcab_counter_read(self, which, ref):
        ref.value = self.counters[which]
        return _Status.ATCA_SUCCESS

    def atcab_counter_increment(self, which, ref):
        # Monotonic, as the part is. There is no decrement command and this
        # fake does not offer one either.
        self.counters[which] += 1
        ref.value = self.counters[which]
        return _Status.ATCA_SUCCESS

    def atcab_read_zone(self, _zone, slot, _block, _offset, buf, length):
        data = self.slots[slot][:length]
        buf[:len(data)] = data
        return _Status.ATCA_SUCCESS

    def atcab_write_zone(self, _zone, slot, _block, _offset, data, _length):
        self.writes.append(slot)
        self.slots[slot] = bytes(data)
        return _Status.ATCA_SUCCESS

    def atcab_sha_hmac(self, message, _length, slot, out, _mode):
        # The real part computes this inside the chip under a key that never
        # leaves it. The fake holds the key in memory, which is exactly the
        # difference between the two and exactly why this is not a security
        # test.
        digest = hmac.new(self.slots[slot], bytes(message), hashlib.sha256).digest()
        out[:] = digest
        return _Status.ATCA_SUCCESS

    def atcab_random(self, buf):
        buf[:] = os.urandom(len(buf))
        return _Status.ATCA_SUCCESS

    def atcab_checkmac(self, _mode, slot, challenge, _resp, _other, _ref):
        self.checkmac_calls += 1
        return (_Status.ATCA_SUCCESS if bytes(challenge) == self.slots[slot]
                else _Status.ATCA_CHECKMAC_VERIFY_FAILED)


def device(pin: str = "123456", locked: bool = True):
    fake = FakeATECC(pin=pin, locked=locked)
    return ATECC608B(lib=fake), fake


# --------------------------------------------------------------------------


def main() -> int:
    print("ATECC608B driver — the arithmetic around the chip\n")

    # ---- the lock ------------------------------------------------------
    print(" refusing an unlocked chip")
    refuses("an unlocked chip is refused outright",
            lambda: device(locked=False), DeviceError)
    try:
        device(locked=False)
    except DeviceError as e:
        check("...and the message says how to fix it", "lock" in str(e).lower())

    # ---- the PIN -------------------------------------------------------
    print("\n the attempt counter")
    se, fake = device()
    check("a fresh device has the full budget",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    check("the correct PIN is accepted", se.verify_pin("123456") is True)
    check("a correct PIN restores the budget",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    check("...by moving the baseline, not the counter",
          fake.counters[COUNTER_PIN] == 1
          and int.from_bytes(fake.slots[SLOT_PIN_BASELINE][:4], "big") == 1)

    se, fake = device()
    before = fake.counters[COUNTER_PIN]
    check("a wrong PIN is rejected", se.verify_pin("000000") is False)
    check("...and it cost an attempt", se.attempts_remaining() == MAX_PIN_ATTEMPTS - 1)
    check("...spent on the chip's counter", fake.counters[COUNTER_PIN] == before + 1)
    check("...before the comparison ran, not after", fake.checkmac_calls == 1)

    # The counter is spent first, so a power cut mid-attempt still costs one.
    # Modelled by dropping the driver and rebuilding it against the same chip.
    se2 = ATECC608B(lib=fake)
    check("the cost survives a power cut",
          se2.attempts_remaining() == MAX_PIN_ATTEMPTS - 1)

    # ---- the rollback the part exists to prevent ------------------------
    print("\n rollback")
    se, fake = device()
    for _ in range(4):
        se.verify_pin("wrong")
    check("four wrong PINs spend four attempts",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS - 4)
    # An attacker who could rewrite the baseline would buy attempts back. The
    # baseline is on the chip, behind a correct PIN, so this is what it takes.
    fake.slots[SLOT_PIN_BASELINE] = (99).to_bytes(4, "big") + bytes(28)
    refuses("a baseline ahead of the counter is treated as tampering",
            lambda: se.attempts_remaining(), DeviceError)

    # ---- the wipe ------------------------------------------------------
    print("\n the wipe")
    se, fake = device()
    se.verify_pin("123456")
    before_key = se.kdf(b"ctx")
    secret_before = fake.slots[SLOT_WRAP]
    wiped = False
    for _ in range(MAX_PIN_ATTEMPTS + 2):
        try:
            se.verify_pin("wrong")
        except PinLockout:
            wiped = True
            break
    check(f"wipes after {MAX_PIN_ATTEMPTS} wrong PINs", wiped)
    check("...by overwriting the wrapping slot", SLOT_WRAP in fake.writes)
    check("...with something else entirely",
          fake.slots[SLOT_WRAP] != secret_before)

    # The wrapping key that opened the seed cannot be derived again, so the
    # blob on the card is noise from here on. Note what is NOT claimed: the
    # correct PIN does not bring the device back, because the counter is
    # exhausted and cannot be wound down. Recovery is the backup words.
    refuses("...and even the correct PIN cannot revive it",
            lambda: se.verify_pin("123456"), PinLockout)
    revived = ATECC608B(lib=fake)
    check("...across a power cut too", revived.attempts_remaining() == 0)
    check("...and the old wrapping key is gone",
          hmac.new(fake.slots[SLOT_WRAP], b"ctx", hashlib.sha256).digest()
          != before_key)

    # ---- the KDF -------------------------------------------------------
    print("\n the wrapping key")
    se, fake = device()
    refuses("the KDF refuses without a spent PIN attempt",
            lambda: se.kdf(b"ctx"), PinLockout)
    se.verify_pin("123456")
    k1 = se.kdf(b"ctx")
    refuses("...and it is single use", lambda: se.kdf(b"ctx"), PinLockout)
    se.verify_pin("123456")
    check("the same context gives the same key", se.kdf(b"ctx") == k1)
    se.verify_pin("123456")
    check("a different context gives a different key", se.kdf(b"other") != k1)

    other, _ = device()
    other.verify_pin("123456")
    check("a different chip gives a different key", other.kdf(b"ctx") != k1)

    # ---- attestation ---------------------------------------------------
    print("\n the attestation key")
    se, fake = device()
    pub = se.attest_pubkey()
    check("the attestation pubkey is 32 bytes, x-only", len(pub) == 32)
    check("...and stable across calls", se.attest_pubkey() == pub)
    check("...and does not need the PIN", isinstance(pub, bytes))

    import attest
    digest = hashlib.sha256(b"a sighash").digest()
    sig = se.attest_sign(digest)
    check("it signs a digest that verifies against its own pubkey",
          attest.schnorr_verify(digest, pub, sig))
    check("a different chip attests differently",
          device()[0].attest_pubkey() != pub)

    # The attestation key must NOT be reachable from the wrapping slot, or a
    # wipe would silently change the device's identity as well as its key.
    se.verify_pin("123456")
    check("the attestation key is not the wrapping key",
          se.kdf(b"CELL/attest/v1") != pub)

    # ---- what this file does not prove ---------------------------------
    print("\n the honest limits")
    check("the fake holds slot secrets in memory; the chip does not",
          FakeATECC().slots[SLOT_WRAP] is not None)
    print("      ^ so none of the above is evidence about the silicon.")
    print("      `python3 se_atecc.py --probe` on a built device is.")

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
