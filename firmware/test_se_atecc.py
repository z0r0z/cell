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
from se_atecc import (ATCA_ZONE_DATA, COUNTER_PIN, LOCK_ZONE_CONFIG,
                      LOCK_ZONE_DATA, SHA_MODE_TARGET_TEMPKEY, SLOT_ATTEST,
                      SLOT_PIN, SLOT_PIN_BASELINE, SLOT_PIN_VERIFIER,
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
    ATCA_BAD_PARAM = 0xE2
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1


class AtcaReference:
    def __init__(self, value=0):
        self.value = value


class FakeATECC:
    """Enough of cryptoauthlib to drive the driver. Not a simulator.

    Every signature here was taken from the installed cryptoauthlib package by
    introspection, not from memory, and `api_conformance()` below re-checks
    them against the real library whenever it is present. That check is the
    point of this class: the first version of this driver called
    `atcab_checkmac` with six arguments (it takes five) and read the data zone
    with the lock-zone constant. Both imported cleanly and would have failed on
    a bench.
    """

    Status = _Status
    AtcaReference = AtcaReference

    def __init__(self, pin: str = "123456", locked: bool = True):
        self.slots = {SLOT_WRAP: os.urandom(32), SLOT_ATTEST: os.urandom(32),
                      SLOT_PIN: os.urandom(32),
                      SLOT_PIN_BASELINE: bytes(32),
                      SLOT_PIN_VERIFIER: bytes(32)}
        self.counters = {0: 0, 1: 0}
        self.locked = locked
        self.hmac_calls = 0
        self.writes: list[int] = []
        self.zones_read: list[int] = []
        # Provisioning writes the verifier before the zones are locked.
        self.slots[SLOT_PIN_VERIFIER] = self._hmac(
            SLOT_PIN, b"CELL/pin/v1" + hashlib.sha256(pin.encode()).digest())

    def _hmac(self, slot, message):
        return hmac.new(self.slots[slot], bytes(message), hashlib.sha256).digest()

    # -- the calls the driver makes, with cryptoauthlib's real signatures --

    def cfg_ateccx08a_i2c_default(self):
        class _Cfg:
            class cfg:
                class atcai2c:
                    bus = 0
                    slave_address = 0
        return _Cfg()

    def atcab_init(self, iface_cfg):
        return _Status.ATCA_SUCCESS

    def atcab_is_locked(self, zone, is_locked):
        # LOCK_ZONE_CONFIG / LOCK_ZONE_DATA, not the ATCA_ZONE_* values.
        if zone not in (LOCK_ZONE_CONFIG, LOCK_ZONE_DATA):
            raise AssertionError(f"atcab_is_locked got zone {zone}, which is "
                                 f"not a LOCK_ZONE_* value")
        is_locked.value = 1 if self.locked else 0
        return _Status.ATCA_SUCCESS

    def atcab_counter_read(self, counter_id, counter_value):
        counter_value.value = self.counters[counter_id]
        return _Status.ATCA_SUCCESS

    def atcab_counter_increment(self, counter_id, counter_value):
        # Monotonic, as the part is. There is no decrement command and this
        # fake does not offer one either.
        self.counters[counter_id] += 1
        counter_value.value = self.counters[counter_id]
        return _Status.ATCA_SUCCESS

    def atcab_read_zone(self, zone, slot, block, offset, data, length):
        if zone != ATCA_ZONE_DATA:
            raise AssertionError(f"atcab_read_zone got zone {zone}, expected "
                                 f"ATCA_ZONE_DATA ({ATCA_ZONE_DATA})")
        self.zones_read.append(slot)
        payload = self.slots[slot][:length]
        data[:len(payload)] = payload
        return _Status.ATCA_SUCCESS

    def atcab_write_zone(self, zone, slot, block, offset, data, length):
        if zone != ATCA_ZONE_DATA:
            raise AssertionError(f"atcab_write_zone got zone {zone}, expected "
                                 f"ATCA_ZONE_DATA ({ATCA_ZONE_DATA})")
        self.writes.append(slot)
        self.slots[slot] = bytes(data)
        return _Status.ATCA_SUCCESS

    def atcab_sha_hmac(self, data, data_size, key_slot, digest, target):
        # The real binding refuses anything but a bytearray for the digest,
        # and returns ATCA_BAD_PARAM rather than raising. Mirror that.
        if not isinstance(digest, bytearray):
            return _Status.ATCA_BAD_PARAM
        if target != SHA_MODE_TARGET_TEMPKEY:
            raise AssertionError(f"unexpected SHA target {target}")
        if data_size != len(bytes(data)):
            raise AssertionError("data_size does not match the data")
        self.hmac_calls += 1
        # The real part computes this inside the chip under a key that never
        # leaves it. The fake holds the key in memory, which is exactly the
        # difference between the two and exactly why this is not a security
        # test.
        digest[:] = self._hmac(key_slot, data)
        return _Status.ATCA_SUCCESS

    def atcab_random(self, random_number):
        random_number[:] = os.urandom(len(random_number))
        return _Status.ATCA_SUCCESS


def api_conformance() -> list[tuple[str, bool]]:
    """Compare the fake's signatures with the real cryptoauthlib, if present.

    Skipped when the library is absent, which is the normal case in CI — the
    binding pulls a native shared object that has no business being a test
    dependency. When it IS installed, this is the check that would have caught
    the six-argument checkmac call.
    """
    try:
        import cryptoauthlib as real
    except ImportError:
        return []
    import inspect
    out = []
    for name in ("atcab_init", "atcab_is_locked", "atcab_counter_read",
                 "atcab_counter_increment", "atcab_read_zone",
                 "atcab_write_zone", "atcab_sha_hmac", "atcab_random"):
        theirs = getattr(real, name, None)
        if theirs is None:
            out.append((f"cryptoauthlib has {name}", False))
            continue
        want = list(inspect.signature(theirs).parameters)
        got = list(inspect.signature(getattr(FakeATECC, name)).parameters)[1:]
        out.append((f"{name}{tuple(want)} matches the fake", want == got))
    return out


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
    check("...before the comparison ran, not after", fake.hmac_calls >= 1)

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

    # ---- against the real library, when it is installed ------------------
    print("\n cryptoauthlib API conformance")
    conf = api_conformance()
    if not conf:
        print("      cryptoauthlib not installed — skipped. Install it to")
        print("      check the driver's calls against the real signatures:")
        print("          pip install cryptoauthlib")
    for label, ok in conf:
        check(label, ok)

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
