#!/usr/bin/env python3
"""The ATECC608B driver's arithmetic, against a fake chip.

The silicon cannot be attached to CI, and this file does not pretend
otherwise — VALIDATION.md still records the part as unverified until someone
runs `se_atecc.py --probe` and `tools/atecc_config.py verify --behaviour` on a
built device. What it does exercise is the logic wrapped around the chip, which
is where the subtle mistakes live:

    the attempt budget, expressed as a distance from a baseline because the
        chip's counters cannot be reset
    that baseline living ON the chip and behind an encrypted write, so it
        cannot be rolled back by anyone holding the SD card — the single
        property the part was bought for
    the KDF refusing to answer without a spent PIN attempt, once
    the refusal to run at all against a chip whose zones are unlocked
    a wipe that actually destroys both wrapping secrets
    a duress PIN that reaches a different wrapping slot and is not otherwise
        distinguishable from the normal one

THE FAKE ENFORCES THE CONFIG ZONE. This is the change that matters. The
previous version of this file modelled a chip that answered every command,
which meant the driver's tests passed against a chip nobody could actually
build: apply the ReqAuth binding BUILD.md 12 asks for and the real part would
have refused every derive, because the driver never performed a CheckMac. The
fake below refuses the same things `tools/atecc_config.py`'s policy tells the
chip to refuse — reads of secret slots, derives without a prior CheckMac,
clear writes to a baseline — so a driver that only works on an unconfigured
chip fails here.

Where it is more permissive than the real part, the test says so rather than
claiming coverage it does not have.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

from se import MAX_PIN_ATTEMPTS, PinLockout, PinResult
from se_atecc import (ATCA_ZONE_DATA, COUNTER_PIN, LOCK_ZONE_CONFIG,
                      LOCK_ZONE_DATA, SHA_MODE_TARGET_TEMPKEY, SLOT_ATTEST,
                      SLOT_BASELINE, SLOT_BASELINE_DURESS, SLOT_PIN,
                      SLOT_PIN_DURESS, SLOT_WRAP, SLOT_WRAP_DURESS,
                      ATECC608B, ConfigError, DeviceError, checkmac_response,
                      pin_key)

PIN, DPIN = "12345678", "87654321"

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
    ATCA_EXECUTION_ERROR = 0xC1
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1


class AtcaReference:
    def __init__(self, value=0):
        self.value = value


# What the config zone tells the chip to enforce, restated as the fake's rules.
# tools/atecc_config.py writes these bits; here they are the behaviour those
# bits are supposed to buy, so the driver is tested against the chip it will
# actually meet rather than against an unconfigured one.
SECRET_SLOTS = {SLOT_WRAP, SLOT_ATTEST, SLOT_PIN, SLOT_PIN_DURESS,
                SLOT_WRAP_DURESS}
REQ_AUTH = {SLOT_WRAP: SLOT_PIN, SLOT_WRAP_DURESS: SLOT_PIN_DURESS}
ENCRYPTED_WRITE = {SLOT_BASELINE: SLOT_PIN, SLOT_BASELINE_DURESS: SLOT_PIN_DURESS}
METERED = {SLOT_WRAP}


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

    def __init__(self, pin: str = PIN, duress_pin: str | None = DPIN,
                 locked: bool = True):
        self.serial = b"\x01\x23" + bytes([0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]) + b"\xEE"
        # An un-provisioned data zone, which is the state a real chip is in
        # when set_pin runs. Pre-loading the wrapping, attestation and
        # baseline slots with plausible values baked in the favourable
        # assumption and hid the fact that nothing ever wrote them: three of
        # these are now written by set_pin, and the baselines with them.
        self.slots: dict[int, bytes] = {}
        self.counters = {0: 0, 1: 0}
        self.locked = locked
        # Tracked separately, because the one window in which the slots are
        # writable is config-locked and data-unlocked. Modelling both zones
        # with one flag is why the provisioning order in BUILD.md section 12
        # could not be rehearsed here at all.
        self.data_locked = locked
        self.hmac_calls = 0
        self.checkmac_calls: list[int] = []
        self.writes: list[int] = []
        self.enc_writes: list[int] = []
        # Which slot a successful CheckMac last authorised. Cleared by any
        # subsequent CheckMac, as the real part clears TempKey.
        self.authorised: int | None = None
        self.pin, self.duress_pin = pin, duress_pin

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
        is_locked.value = 1 if (self.locked if zone == LOCK_ZONE_CONFIG
                                else self.data_locked) else 0
        return _Status.ATCA_SUCCESS

    def atcab_read_serial_number(self, serial_number):
        serial_number[:] = self.serial
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
        if self.locked and slot in SECRET_SLOTS:
            # IsSecret with EncryptRead clear. The real part answers a read of
            # such a slot with an error, and a driver that reads a secret slot
            # is a driver that will not work on a configured chip.
            return _Status.ATCA_EXECUTION_ERROR
        payload = self.slots[slot][:length]
        data[:len(payload)] = payload
        return _Status.ATCA_SUCCESS

    def atcab_write_zone(self, zone, slot, block, offset, data, length):
        if zone != ATCA_ZONE_DATA:
            raise AssertionError(f"atcab_write_zone got zone {zone}, expected "
                                 f"ATCA_ZONE_DATA ({ATCA_ZONE_DATA})")
        # data_locked, not locked: WriteConfig = Encrypt only bites once the
        # DATA zone is locked, and the provisioning window is exactly the one
        # where it does not.
        if self.data_locked and slot in ENCRYPTED_WRITE:
            # WriteConfig = Encrypt. A clear write is exactly the rollback the
            # baseline slots exist to prevent.
            return _Status.ATCA_EXECUTION_ERROR
        self.writes.append(slot)
        self.slots[slot] = bytes(data)
        return _Status.ATCA_SUCCESS

    def atcab_write_enc(self, key_id, block, data, enc_key, enc_key_id,
                        num_in=None):
        if self.slots.get(enc_key_id) != bytes(enc_key):
            # The host has to already hold the write key's secret. It does,
            # because that secret is a function of the PIN.
            return _Status.ATCA_EXECUTION_ERROR
        if ENCRYPTED_WRITE.get(key_id) != enc_key_id:
            return _Status.ATCA_EXECUTION_ERROR
        self.enc_writes.append(key_id)
        self.slots[key_id] = bytes(data)
        return _Status.ATCA_SUCCESS

    def atcab_checkmac(self, mode, key_id, challenge, response, other_data):
        self.checkmac_calls.append(key_id)
        want = checkmac_response(self.slots[key_id], bytes(challenge),
                                 bytes(other_data), self.serial)
        # Any CheckMac clears the previous authorisation, matching the real
        # part's TempKey. This is why verify_pin re-runs the one that has to
        # stand, and why kdf runs its own immediately before the derive.
        self.authorised = None
        if not hmac.compare_digest(want, bytes(response)):
            return _Status.ATCA_CHECKMAC_VERIFY_FAILED
        self.authorised = key_id
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
        if self.locked and key_slot in REQ_AUTH:
            # KeyConfig.ReqAuth. This is the line BUILD.md 12 is about, and
            # modelling it here is what makes the driver's CheckMac necessary
            # rather than decorative.
            if self.authorised != REQ_AUTH[key_slot]:
                return _Status.ATCA_EXECUTION_ERROR
        if self.locked and key_slot in METERED:
            self.counters[0] += 1           # SlotConfig.LimitedUse, Counter0
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
    for name in ("atcab_init", "atcab_is_locked", "atcab_read_serial_number",
                 "atcab_counter_read", "atcab_counter_increment",
                 "atcab_read_zone", "atcab_write_zone", "atcab_write_enc",
                 "atcab_checkmac", "atcab_sha_hmac", "atcab_random"):
        theirs = getattr(real, name, None)
        if theirs is None:
            out.append((f"cryptoauthlib has {name}", False))
            continue
        want = list(inspect.signature(theirs).parameters)
        got = list(inspect.signature(getattr(FakeATECC, name)).parameters)[1:]
        out.append((f"{name}{tuple(want)} matches the fake", want == got))
    return out


def checkmac_conformance() -> list[tuple[str, bool]]:
    """Our CheckMac digest against Microchip's own reference implementation.

    `se_atecc.checkmac_response()` is transcribed from the datasheet's CheckMac
    description — an 88-byte message with nine fields in a particular order —
    and it is the single most fragile thing in the driver. One field boundary
    wrong and every PIN is rejected on a chip that is behaving perfectly.

    cryptoauthlib ships `atcah_check_mac()`, which is the C implementation of
    that same digest, written by the people who make the part. It is exported
    from the bundled shared object, so it can be called directly and compared.
    Two independent transcriptions agreeing is not proof the chip agrees, but
    it removes the failure mode where one person read the table wrong.

    Skipped when the library is absent. The ctypes struct below is itself a
    transcription (of `atca_host.h`) — but a WRONG one produces a garbage
    digest or a non-zero status, not a false match, so a pass here means
    something and a skip costs nothing.
    """
    try:
        import ctypes
        import cryptoauthlib
    except ImportError:
        return []

    import pathlib
    lib_dir = pathlib.Path(cryptoauthlib.__file__).parent
    for name in ("libcryptoauth.dylib", "libcryptoauth.so",
                 "libcryptoauth.SOVERSION.dylib"):
        if (lib_dir / name).exists():
            break
    else:
        return []

    try:
        lib = ctypes.CDLL(str(lib_dir / name))
        u8p = ctypes.POINTER(ctypes.c_uint8)

        class _TempKey(ctypes.Structure):
            _fields_ = [("value", ctypes.c_uint8 * 64),
                        ("bits", ctypes.c_uint32),      # five bitfields, one word
                        ("is_64", ctypes.c_uint8)]

        class _CheckMacInOut(ctypes.Structure):
            _fields_ = [("mode", ctypes.c_uint8), ("key_id", ctypes.c_uint16),
                        ("sn", u8p), ("client_chal", u8p), ("client_resp", u8p),
                        ("other_data", u8p), ("otp", u8p), ("slot_key", u8p),
                        ("target_key", u8p),
                        ("temp_key", ctypes.POINTER(_TempKey))]

        def _buf(b):
            a = (ctypes.c_uint8 * len(b))(*b)
            return a, ctypes.cast(a, u8p)

        serial = FakeATECC().serial
        out = []
        for i in range(4):
            slot = SLOT_PIN if i % 2 == 0 else SLOT_PIN_DURESS
            secret = bytes((i * 13 + j) & 0xFF for j in range(32))
            chal = bytes((i * 7 + j * 3) & 0xFF for j in range(32))
            other = __import__("se_atecc").other_data_for(slot, serial)

            keep = [_buf(secret), _buf(chal), _buf(other), _buf(serial)]
            resp = (ctypes.c_uint8 * 32)()
            tk = _TempKey()
            p = _CheckMacInOut()
            p.mode, p.key_id = 0, slot
            p.slot_key, p.client_chal = keep[0][1], keep[1][1]
            p.other_data, p.sn = keep[2][1], keep[3][1]
            p.client_resp = ctypes.cast(resp, u8p)
            p.otp = p.target_key = None
            p.temp_key = ctypes.pointer(tk)

            status = lib.atcah_check_mac(ctypes.byref(p))
            mine = checkmac_response(secret, chal, other, serial)
            out.append((f"our CheckMac digest matches atcah_check_mac (slot "
                        f"{slot}, case {i})",
                        status == 0 and bytes(resp) == mine))
        return out
    except Exception as e:                                  # noqa: BLE001
        return [(f"atcah_check_mac cross-check raised {type(e).__name__}",
                 False)]


def device(pin: str = PIN, duress_pin: str | None = DPIN, locked: bool = True):
    """A provisioned chip, provisioned the way the runbook provisions one.

    The slots are written by set_pin through the real driver, in the real
    window -- config locked, data not yet -- rather than reached into from
    here. That is what makes the suite able to notice a slot nothing writes:
    while the fake pre-loaded the wrapping and attestation secrets, a
    provisioning path that never wrote them looked identical to one that did.
    """
    fake = FakeATECC(pin=pin, duress_pin=duress_pin, locked=locked)
    if locked:
        fake.data_locked = False
        ATECC608B(lib=fake, require_data_lock=False).set_pin(pin, duress_pin)
        fake.data_locked = True
        fake.writes.clear()
        fake.counters = {0: 0, 1: 0}
    return ATECC608B(lib=fake), fake


def unlock(se, pin: str = PIN, ctx: bytes = b"ctx") -> bytes:
    """Verify then derive. The chain always does both; the tests must too."""
    se.verify_pin(pin)
    return se.kdf(ctx)


# --------------------------------------------------------------------------


def main() -> int:
    print("ATECC608B driver — the arithmetic around a chip that enforces "
          "its config\n")

    # ---- the lock ------------------------------------------------------
    print(" refusing an unlocked chip")
    refuses("an unlocked chip is refused outright",
            lambda: device(locked=False), ConfigError)
    try:
        device(locked=False)
    except DeviceError as e:
        check("...and the message names the tool that fixes it",
              "atecc_config" in str(e))

    # ---- the PIN -------------------------------------------------------
    print("\n the attempt counter")
    se, fake = device()
    check("a fresh device has the full budget",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    check("the correct PIN is accepted", se.verify_pin(PIN) is PinResult.NORMAL)
    check("a correct PIN restores the budget",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    check("...by moving the baseline, not the counter",
          fake.counters[COUNTER_PIN] == 1
          and int.from_bytes(fake.slots[SLOT_BASELINE][:4], "big") == 1)
    check("...and the baseline moved by an encrypted write",
          fake.enc_writes == [SLOT_BASELINE] and SLOT_BASELINE not in fake.writes)

    se, fake = device()
    before = fake.counters[COUNTER_PIN]
    check("a wrong PIN is rejected", se.verify_pin("00000000") is PinResult.NONE)
    check("...and it cost an attempt", se.attempts_remaining() == MAX_PIN_ATTEMPTS - 1)
    check("...spent on the chip's counter", fake.counters[COUNTER_PIN] == before + 1)
    # Order, not merely "a CheckMac happened". The old form was a truthiness
    # test on a list that verify_pin always fills, so a driver that spent the
    # counter AFTER the comparison -- the exact rollback this part is in the
    # bill of materials to prevent -- passed it.
    se_o, fake_o = device()
    order: list[str] = []
    _inc, _cm = fake_o.atcab_counter_increment, fake_o.atcab_checkmac
    fake_o.atcab_counter_increment = (
        lambda *a, _f=_inc: (order.append("count"), _f(*a))[1])
    fake_o.atcab_checkmac = (
        lambda *a, _f=_cm: (order.append("checkmac"), _f(*a))[1])
    se_o.verify_pin("00000000")
    check("...before the comparison ran, not after",
          order[:1] == ["count"] and "checkmac" in order)

    # The counter is spent first, so a power cut mid-attempt still costs one.
    # Modelled by dropping the driver and rebuilding it against the same chip.
    se2 = ATECC608B(lib=fake)
    check("the cost survives a power cut",
          se2.attempts_remaining() == MAX_PIN_ATTEMPTS - 1)

    # ---- the PIN check is the chip's, not ours -------------------------
    print("\n the PIN check happens in silicon")
    se, fake = device()
    se.verify_pin(PIN)
    check("a correct PIN leaves the chip authorised for the wrapping slot",
          fake.authorised == SLOT_PIN)
    se, fake = device()
    se.verify_pin("00000000")
    check("a wrong PIN leaves it authorising nothing",
          fake.authorised is None)

    # This is the check the whole config zone exists for. With the ReqAuth
    # binding in place, the derive is not gated by a flag in this firmware —
    # it is gated by the chip, and no amount of replacing the firmware helps.
    se, fake = device()
    fake.authorised = None
    out = bytearray(32)
    check("the chip itself refuses to derive with no CheckMac",
          fake.atcab_sha_hmac(b"ctx", 3, SLOT_WRAP, out,
                              SHA_MODE_TARGET_TEMPKEY)
          != _Status.ATCA_SUCCESS)
    fake.authorised = SLOT_PIN_DURESS
    check("...and refuses an authorisation against the wrong slot",
          fake.atcab_sha_hmac(b"ctx", 3, SLOT_WRAP, out,
                              SHA_MODE_TARGET_TEMPKEY)
          != _Status.ATCA_SUCCESS)

    # Both PIN slots are always tried, and the successful one is re-established
    # last. Same number of commands whichever PIN was entered, or a coercer
    # with a stopwatch can read the difference off the bus.
    se, fake = device()
    se.verify_pin(PIN)
    normal_calls = list(fake.checkmac_calls)
    se, fake = device()
    se.verify_pin(DPIN)
    duress_calls = list(fake.checkmac_calls)
    se, fake = device()
    se.verify_pin("00000000")
    wrong_calls = list(fake.checkmac_calls)
    check("every PIN costs the same three CheckMacs",
          len(normal_calls) == len(duress_calls) == len(wrong_calls) == 3)
    check("...and the first two are always the same two slots",
          normal_calls[:2] == duress_calls[:2] == wrong_calls[:2]
          == [SLOT_PIN, SLOT_PIN_DURESS])

    # ---- rollback ------------------------------------------------------
    print("\n rollback")
    se, fake = device()
    for _ in range(4):
        se.verify_pin("wrongpin")
    check("four wrong PINs spend four attempts",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS - 4)
    # An attacker who could rewrite a baseline would buy attempts back. The
    # config makes that an encrypted write under a PIN-derived key, so this is
    # what it takes — and it is caught anyway.
    check("a clear write to the baseline is refused by the chip",
          fake.atcab_write_zone(ATCA_ZONE_DATA, SLOT_BASELINE, 0, 0,
                                bytes(32), 32) != _Status.ATCA_SUCCESS)
    check("...and so is an encrypted one under the wrong key",
          fake.atcab_write_enc(SLOT_BASELINE, 0, bytes(32), os.urandom(32),
                               SLOT_PIN) != _Status.ATCA_SUCCESS)
    fake.slots[SLOT_BASELINE] = (99).to_bytes(4, "big") + bytes(28)
    refuses("a baseline ahead of the counter is treated as tampering",
            lambda: se.attempts_remaining(), DeviceError)
    se, fake = device()
    fake.slots[SLOT_BASELINE_DURESS] = (99).to_bytes(4, "big") + bytes(28)
    refuses("...including the duress one",
            lambda: se.attempts_remaining(), DeviceError)

    # ---- the wipe ------------------------------------------------------
    print("\n the wipe")
    se, fake = device()
    before_key = unlock(se)
    before_decoy = unlock(se, DPIN)
    secrets_before = (fake.slots[SLOT_WRAP], fake.slots[SLOT_WRAP_DURESS])
    wiped = False
    for _ in range(MAX_PIN_ATTEMPTS + 2):
        try:
            se.verify_pin("wrongpin")
        except PinLockout:
            wiped = True
            break
    check(f"wipes after {MAX_PIN_ATTEMPTS} wrong PINs", wiped)
    check("...by overwriting BOTH wrapping slots",
          SLOT_WRAP in fake.writes and SLOT_WRAP_DURESS in fake.writes)
    check("...with something else entirely",
          (fake.slots[SLOT_WRAP], fake.slots[SLOT_WRAP_DURESS])
          != secrets_before)

    # The wrapping key that opened the seed cannot be derived again, so the
    # blob on the card is noise from here on. Note what is NOT claimed: the
    # correct PIN does not bring the device back, because the counter is
    # exhausted and cannot be wound down. Recovery is the backup words.
    refuses("...and even the correct PIN cannot revive it",
            lambda: se.verify_pin(PIN), PinLockout)
    revived = ATECC608B(lib=fake)
    check("...across a power cut too", revived.attempts_remaining() == 0)
    check("...and neither old wrapping key is recoverable",
          hmac.new(fake.slots[SLOT_WRAP], b"ctx", hashlib.sha256).digest()
          != before_key
          and hmac.new(fake.slots[SLOT_WRAP_DURESS], b"ctx",
                       hashlib.sha256).digest() != before_decoy)

    # ---- the KDF -------------------------------------------------------
    print("\n the wrapping key")
    se, fake = device()
    refuses("the KDF refuses without a spent PIN attempt",
            lambda: se.kdf(b"ctx"), PinLockout)
    se.verify_pin("00000000")
    refuses("a failed PIN does not authorise a derive",
            lambda: se.kdf(b"ctx"), PinLockout)
    se.verify_pin(PIN)
    k1 = se.kdf(b"ctx")
    refuses("...and it is single use", lambda: se.kdf(b"ctx"), PinLockout)
    check("the same context gives the same key", unlock(se) == k1)
    check("a different context gives a different key",
          unlock(se, ctx=b"other") != k1)

    other, _ = device()
    check("a different chip gives a different key", unlock(other) != k1)

    # Every derive re-establishes the authorisation immediately before using
    # it, because the chip forgets on sleep and the blood gate runs ten
    # minutes. A driver that authorised once at PIN time would work on a bench
    # and fail on a real capture.
    se, fake = device()
    se.verify_pin(PIN)
    fake.authorised = None                  # the chip slept during the gate
    check("the derive re-authorises rather than relying on the PIN step",
          isinstance(se.kdf(b"ctx"), bytes))

    # ---- duress --------------------------------------------------------
    print("\n the duress PIN")
    se, fake = device()
    check("the duress PIN is accepted", se.verify_pin(DPIN) is PinResult.DURESS)
    check("...and restores the budget exactly as the normal one does",
          se.attempts_remaining() == MAX_PIN_ATTEMPTS)
    check("...and reaches a different wrapping slot",
          unlock(se, DPIN) != unlock(se, PIN))
    check("...via the duress baseline, under the duress PIN key",
          SLOT_BASELINE_DURESS in fake.enc_writes)

    # A device with no duress PIN configured must be indistinguishable from
    # one that has it. The slot is written either way, with a secret nobody
    # can produce.
    se, fake = device(duress_pin=None)
    check("a device with no duress PIN still has the slot populated",
          len(fake.slots[SLOT_PIN_DURESS]) == 32)
    check("...and still spends three CheckMacs on every attempt",
          (se.verify_pin(PIN), len(fake.checkmac_calls))[1] == 3)
    check("...and no PIN reaches its decoy wallet",
          se.verify_pin("00000000") is PinResult.NONE)

    refuses("the two PINs cannot be the same",
            lambda: device()[0].set_pin(PIN, PIN), DeviceError)

    # ---- attestation ---------------------------------------------------
    print("\n the attestation key")
    se, fake = device()
    pub = se.attest_pubkey()
    check("the attestation pubkey is 32 bytes, x-only", len(pub) == 32)
    check("...and stable across calls", se.attest_pubkey() == pub)
    check("...and needs no PIN, so the idle screen can show it",
          se.attest_pubkey() == pub and fake.checkmac_calls == [])

    import attest
    digest = hashlib.sha256(b"a sighash").digest()
    sig = se.attest_sign(digest)
    check("it signs a digest that verifies against its own pubkey",
          attest.schnorr_verify(digest, pub, sig))
    check("a different chip attests differently",
          device()[0].attest_pubkey() != pub)

    # The attestation key must NOT be reachable from either wrapping slot, or
    # a wipe would silently change the device's identity as well as its key.
    # Compared secret against SECRET. `pub` is the x-only public half, so
    # comparing a 32-byte HMAC to it could never be equal: setting the
    # attestation slot to the wrapping slot's own secret still passed.
    check("the attestation key is not the wrapping key",
          se._hmac(SLOT_ATTEST, b"CELL/attest/v1")
          != unlock(se, ctx=b"CELL/attest/v1"))

    # ---- the secrets stay in the chip -----------------------------------
    print("\n what cannot be read back")
    se, fake = device()
    buf = bytearray(32)
    for slot, name in ((SLOT_WRAP, "wrapping"), (SLOT_WRAP_DURESS, "decoy"),
                       (SLOT_ATTEST, "attestation"), (SLOT_PIN, "PIN"),
                       (SLOT_PIN_DURESS, "duress PIN")):
        check(f"the {name} secret cannot be read out",
              fake.atcab_read_zone(ATCA_ZONE_DATA, slot, 0, 0, buf, 32)
              != _Status.ATCA_SUCCESS)

    # ---- against the real library, when it is installed ------------------
    print("\n the CheckMac digest, against Microchip's own implementation")
    cm = checkmac_conformance()
    if not cm:
        print("      cryptoauthlib not installed — skipped. This is the check")
        print("      that confirms the most fragile transcription in the")
        print("      driver, so install it if you are building a device:")
        print("          pip install cryptoauthlib")
    for label, ok in cm:
        check(label, ok)

    print("\n cryptoauthlib API conformance")
    conf = api_conformance()
    if not conf:
        print("      cryptoauthlib not installed — skipped. Install it to")
        print("      check the driver's calls against the real signatures:")
        print("          pip install cryptoauthlib")
    for label, ok in conf:
        check(label, ok)

    # Every slot the device depends on is written BY the provisioning path,
    # not assumed to be there. The wrapping and attestation secrets used to be
    # pre-loaded by the fake, so a set_pin that wrote neither looked exactly
    # like one that wrote both -- and on a real chip slot 1 is
    # WriteConfig = Never, so whatever the erased zone held was permanent.
    print("\n provisioning writes every slot the device needs")
    fresh = FakeATECC()
    fresh.data_locked = False
    ATECC608B(lib=fresh, require_data_lock=False).set_pin(PIN, DPIN)
    for slot, what in ((SLOT_WRAP, "the wrapping key"),
                       (SLOT_ATTEST, "the attestation key"),
                       (SLOT_PIN, "the PIN slot"),
                       (SLOT_PIN_DURESS, "the duress PIN slot"),
                       (SLOT_WRAP_DURESS, "the duress wrapping key"),
                       (SLOT_BASELINE, "the attempt baseline"),
                       (SLOT_BASELINE_DURESS, "the duress attempt baseline")):
        check(f"set_pin writes {what}", slot in fresh.slots)
    check("...and the two device secrets are not the same value",
          fresh.slots[SLOT_WRAP] != fresh.slots[SLOT_ATTEST]
          != fresh.slots[SLOT_WRAP_DURESS])
    check("two devices do not share a wrapping key",
          fresh.slots[SLOT_WRAP] != device()[1].slots[SLOT_WRAP])
    check("the baselines start where the counters do",
          fresh.slots[SLOT_BASELINE] == bytes(32)
          == fresh.slots[SLOT_BASELINE_DURESS])

    # ---- what this file does not prove ---------------------------------
    print("\n the honest limits")
    check("the fake holds slot secrets in memory; the chip does not",
          device()[1].slots[SLOT_WRAP] is not None)
    print("      ^ so none of the above is evidence about the silicon.")
    print("      The CheckMac digest in particular is transcribed from the")
    print("      datasheet and is confirmed only by")
    print("      `tools/atecc_config.py verify --behaviour` on a built device.")

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
