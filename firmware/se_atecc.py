"""The real ATECC608B, on I2C at 0x60.

se.py defines the interface and ships a software stub for the laptop. This is
the part that talks to the chip. It cannot be exercised without hardware, so
`run_tests.py` runs its argument checks and skips the rest, and VALIDATION.md
records it as unverified until someone runs `python3 se_atecc.py --probe` on a
built device.

The chip's configuration is not written here. `tools/atecc_config.py` builds
the config zone, shows it byte by byte, writes it, reads it back, and locks it
— in that order and only with the operator's hand on each step. This file is
the driver that config makes possible. The two carry the slot map separately
and `atecc_config.selfcheck()` asserts they agree, so firmware does not import
from tools and the map still cannot drift.

ONE THING THIS CHIP CANNOT DO, stated plainly because the README's phrasing is
easy to over-read: the ATECC608B signs NIST P-256 ECDSA and nothing else. It
cannot produce a BIP-340 Schnorr signature on secp256k1, which is what
attest.py's record format uses. So the attestation key is not a key the chip
holds and signs with — it is derived from a secret the chip holds and never
exports, via the chip's own HMAC, and the resulting scalar exists in RAM for
the microseconds it takes to sign.

    What that still buys:   the attestation key is unreproducible without this
                            specific chip. Clone the SD card and you cannot
                            attest as this device.
    What it does not buy:   an attacker who has already broken the firmware,
                            with the case open, can observe the scalar. The
                            tamper seal is what that assumption rests on,
                            exactly as BUILD.md section 16 says of the
                            attestation as a whole.

If you want the stronger property, switch attest.py to the chip's native P-256
ECDSA — the record format is versioned for exactly this kind of change, and
the cost is that co-signers verify with a different curve than they sign on.

SLOT MAP. Written by tools/atecc_config.py, then locked.

    Slot 0   wrapping secret     secret, HMAC use only, ReqAuth -> slot 2,
                                 every use metered by Counter0
    Slot 1   attestation secret  secret, HMAC use only, no authorisation
    Slot 2   PIN key, normal     secret, the slot 0 CheckMac is against
    Slot 3   PIN baseline        clear read, encrypted write under slot 2
    Slot 4   PIN key, duress     secret, the slot 5 CheckMac is against
    Slot 5   wrapping secret     secret, HMAC use only, ReqAuth -> slot 4
             for the decoy
    Slot 6   PIN baseline        clear read, encrypted write under slot 4
             for the decoy
    Counter0 PIN attempts        monotonic, never decreases
    Counter1 operations          monotonic, for attestation anti-replay

HOW THE PIN IS CHECKED, and why this way. The chip's CheckMac command compares
a MAC the HOST computed against one the chip computes from a slot secret. That
looks like the wrong instrument, because it means the host has to know the
secret — but here that is exactly the mechanism. Slot 2 holds

    HMAC-free, deliberately:  SHA-256("CELL/pin/v1" || serial || PIN)

so a host that knows the PIN can compute it and a host that does not cannot.
The serial number is in there so one precomputed table does not cover every
CELL ever built; it is not a secret and does not need to be.

A wrong PIN produces a different MAC, the chip says no, and — this is the part
that matters — the chip ALSO withholds the authorisation that slot 0 requires
before it will derive. The PIN check is not a comparison this firmware makes.
It is a comparison the silicon makes, and the wrapping key is unreachable
without it.

An earlier version of this file did it the other way: the chip computed an
HMAC and this code compared it against a verifier on the card. That works
right up until the config zone is written the way BUILD.md 12 asks, at which
point slot 0's ReqAuth makes the derive fail and the device cannot open its
own seed. The config and the driver contradicted each other and only one of
them could ship.

WHAT THE SILICON ENFORCES, AND WHAT IT DOES NOT. Worth being exact, because
the difference is where somebody's money is.

    Enforced by the chip:  the wrapping secrets never leave it.
                           No derive without a fresh CheckMac against the PIN
                           slot, so a PIN guess cannot be tested offline.
                           Counter0 only ever increases; there is no reset
                           command and this firmware does not have one either.
                           The baseline cannot be moved without the PIN,
                           because moving it is an encrypted write under the
                           PIN key.
                           At most 2**21 derives in the life of the part,
                           which is what LimitedUse against Counter0 means.

    NOT enforced by the chip:  the ten-attempt limit. There is no silicon
                           retry counter on this part. `attempts_remaining()`
                           is arithmetic this firmware does over a counter and
                           a baseline, and firmware is what an attacker with
                           the case open replaces.

    What that leaves:      an attacker running their own firmware gets as many
                           PIN guesses as Counter0 has left, which is 2**21 =
                           2,097,151. That is why PIN_LENGTH is 8 and not 6.
                           A six-digit PIN is 10**6 guesses and fits inside
                           that budget with room to spare; an eight-digit PIN
                           is 10**8 and does not, so the chip stops answering
                           long before the keyspace is exhausted. The ten
                           attempts protect an owner against someone who
                           picks the device up. The counter ceiling is what
                           protects them against someone who opens it.

Both of those rest on the tamper seal in the end, exactly as BUILD.md 16 says
of the attestation. This file does not claim more.
"""

from __future__ import annotations

import hashlib

from se import MAX_PIN_ATTEMPTS, PinLockout, PinResult, SecureElement

SLOT_WRAP = 0
SLOT_ATTEST = 1
SLOT_PIN = 2
SLOT_BASELINE = 3
SLOT_PIN_DURESS = 4
SLOT_WRAP_DURESS = 5
SLOT_BASELINE_DURESS = 6
COUNTER_PIN = 0
COUNTER_OPS = 1

# Which wrapping slot and which baseline each PIN reaches. A duress unlock runs
# the same commands in the same order against different slot numbers, which is
# the whole of what makes it unreadable from outside.
FOR_ROLE = {
    PinResult.NORMAL: (SLOT_PIN, SLOT_WRAP, SLOT_BASELINE),
    PinResult.DURESS: (SLOT_PIN_DURESS, SLOT_WRAP_DURESS, SLOT_BASELINE_DURESS),
}

I2C_ADDRESS = 0x60

# The counter is 21 bits. See the module docstring: this is the real ceiling on
# how many PIN guesses any firmware can ever make against this chip, and it is
# the reason the PIN is eight digits.
COUNTER_MAX = (1 << 21) - 1

# cryptoauthlib's Python binding documents these by their C names but does not
# export them, so they are restated here with the values its own docstrings
# quote. Note that the two zone namespaces are NOT the same: atcab_is_locked
# takes LOCK_ZONE_*, while atcab_read_zone and atcab_write_zone take ATCA_ZONE_*.
# Using one where the other belongs reads the wrong region and succeeds.
LOCK_ZONE_CONFIG = 0x00
LOCK_ZONE_DATA = 0x01
ATCA_ZONE_CONFIG = 0x00
ATCA_ZONE_OTP = 0x01
ATCA_ZONE_DATA = 0x02
SHA_MODE_TARGET_TEMPKEY = 0x00

# CheckMac, mode 0: the challenge travels in the command and the slot key is
# the chip's. OP_MAC is what OtherData claims the client used.
CHECKMAC_MODE = 0x00
OP_MAC = 0x08

# Fixed bytes of every ATECC serial number, which the MAC digest folds in at
# positions the variable part does not cover.
SN_0_1 = b"\x01\x23"
SN_8 = b"\xEE"


class DeviceError(Exception):
    """The chip is missing, misconfigured, or answered an error."""


class ConfigError(DeviceError):
    """The chip works but is not configured the way CELL needs.

    Separate from DeviceError because the remedy is different and specific:
    a chip that answers but refuses to derive is a chip whose config zone was
    never written, and `tools/atecc_config.py` is the fix.
    """


def pin_key(pin: str, serial: bytes) -> bytes:
    """The secret slot 2 (or slot 4) holds for this PIN, on this chip.

    A pure function of the PIN and the chip's serial number, so the host can
    recompute it at every unlock and nothing about it has to be stored. The
    serial is public — it is there to stop one precomputed table covering
    every CELL ever built, not to add secrecy.
    """
    return hashlib.sha256(b"CELL/pin/v1" + serial + pin.encode()).digest()


def checkmac_response(slot_secret: bytes, challenge: bytes,
                      other_data: bytes, serial: bytes) -> bytes:
    """What the chip will compute, computed here, so CheckMac can compare.

    The 88-byte digest below is transcribed from the datasheet's CheckMac
    description. Transcription is the risk in this whole file: get one field
    boundary wrong and every PIN is rejected, on a chip that is behaving
    perfectly. So it is not trusted — `tools/atecc_config.py` runs a CheckMac
    against a slot whose secret it just wrote, while the data zone is still
    open, and confirms the chip agrees. That takes seconds and it happens
    before anything is permanent.

        32  the slot's secret
        32  the challenge sent with the command
         4  OtherData[0:4]   opcode, mode, param2 low, param2 high
         8  zeros            OTP[0:8], zero because mode bit 5 is clear
         3  OtherData[4:7]   OTP[8:11]
         1  SN[8]            fixed, 0xEE
         4  OtherData[7:11]  SN[4:8]
         2  SN[0:2]          fixed, 0x0123
         2  OtherData[11:13] SN[2:4]
    """
    if len(slot_secret) != 32 or len(challenge) != 32:
        raise DeviceError("CheckMac takes a 32-byte secret and challenge")
    if len(other_data) != 13:
        raise DeviceError("CheckMac OtherData is 13 bytes")
    msg = (slot_secret
           + challenge
           + other_data[0:4]
           + bytes(8)
           + other_data[4:7]
           + SN_8
           + other_data[7:11]
           + SN_0_1
           + other_data[11:13])
    if len(msg) != 88:
        raise DeviceError(f"CheckMac digest is {len(msg)} bytes, expected 88")
    return hashlib.sha256(msg).digest()


def other_data_for(slot: int, serial: bytes) -> bytes:
    """OtherData describing the MAC the client claims to have computed.

    SN[4:8] and SN[2:4] are quoted back from the chip's own serial number
    because the digest above folds them in; getting them from anywhere else
    would make the MAC device-independent, which is the opposite of the point.
    """
    return (bytes([OP_MAC, CHECKMAC_MODE, slot & 0xFF, (slot >> 8) & 0xFF])
            + bytes(3)                  # OTP[8:11], zero
            + serial[4:8]
            + serial[2:4])


def _lib():
    try:
        import cryptoauthlib as cal                             # noqa: F401
    except ImportError:                                         # pragma: no cover
        raise DeviceError(
            "cryptoauthlib is not installed. On Raspberry Pi OS:\n"
            "    pip install cryptoauthlib\n"
            "and enable I2C with raspi-config. Until then the firmware runs "
            "against se.SoftSE, which is NOT a security boundary.") from None
    return cal


class ATECC608B(SecureElement):
    """PIN counter, key wrapping and attestation, backed by the chip."""

    IS_SECURE = True

    def __init__(self, bus: int = 1, address: int = I2C_ADDRESS, lib=None,
                 require_data_lock: bool = True):
        """`lib` overrides cryptoauthlib, so the logic can be tested.

        `require_data_lock=False` is for PROVISIONING ONLY, and it exists
        because the documented runbook could not otherwise execute: `set_pin`
        has to run before the data zone locks (slots 1, 2 and 4 are
        WriteConfig = Never afterwards), and this constructor demanded both
        locks, so `provision.py new` on a config-locked chip refused the chip
        it was there to provision. Locking data first instead makes those
        slots permanently unwritable. Every other entry point keeps the hard
        requirement.

        The chip cannot be attached to CI, but the arithmetic around it can be:
        the attempt budget, the baseline that survives a power cut, the
        single-use KDF, the refusal to run against an unlocked chip. Those are
        the parts most likely to be subtly wrong, and a fake transport lets
        them be exercised. It proves nothing about the silicon — see
        VALIDATION.md — but a bug found here is a bug not found in the field.
        """
        cal = lib if lib is not None else _lib()
        cfg = cal.cfg_ateccx08a_i2c_default()
        cfg.cfg.atcai2c.bus = bus
        cfg.cfg.atcai2c.slave_address = address << 1
        if cal.atcab_init(cfg) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(
                f"no ATECC608B answered at I2C {address:#04x} on bus {bus}. "
                f"Check the pull-ups and that I2C is enabled.")
        self._cal = cal
        # (role, pin key) between a successful verify_pin and the one derive it
        # authorises. The PIN itself is already in RAM across this window —
        # signer.unlock holds it from the PIN step to the unwrap step — so this
        # adds no exposure that was not there. See _authorise().
        self._auth: tuple[PinResult, bytes] | None = None
        self.assert_locked(require_data_lock)
        self._serial = self._read_serial()

    # ---- configuration ----

    def assert_locked(self, require_data_lock: bool = True) -> None:
        """Refuse to use a chip whose zones are still writable.

        An unlocked chip is a chip whose slots can be read or replaced. Running
        against one gives every appearance of security and none of it, so this
        is a hard failure rather than a warning.

        The config zone is never optional. The data zone is waived only for
        the provisioning window, which is the one moment the slots HAVE to be
        writable — see __init__.
        """
        cal = self._cal
        zones = [(LOCK_ZONE_CONFIG, "config")]
        if require_data_lock:
            zones.append((LOCK_ZONE_DATA, "data"))
        for zone, name in zones:
            locked = cal.AtcaReference(0)
            if cal.atcab_is_locked(zone, locked) != cal.Status.ATCA_SUCCESS:
                raise DeviceError(f"could not read the {name} zone lock state")
            if not bool(locked.value):
                raise ConfigError(
                    f"the {name} zone is not locked. This chip's slots can "
                    f"still be read or rewritten — configure it with "
                    f"tools/atecc_config.py before trusting it.")

    def _read_serial(self) -> bytes:
        cal = self._cal
        buf = bytearray(9)
        if cal.atcab_read_serial_number(buf) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not read the chip's serial number")
        return bytes(buf)

    @property
    def serial(self) -> bytes:
        return self._serial

    # ---- PIN ----

    def attempts_remaining(self) -> int:
        """Budget left before the wipe.

        The chip's counters only ever increase — there is no reset command, by
        design. So "ten attempts, refreshed by a correct PIN" is expressed as a
        distance: the counter now, minus its value at the last correct PIN.
        That baseline lives on the chip, not on the SD card, because a baseline
        an attacker can rewrite is a counter an attacker can roll back, which
        is the exact property this part was bought for. Writing it is an
        encrypted write under the PIN key, so raising it is not something an
        attacker can do without already having the PIN.

        Two baselines, one per PIN, because a slot has exactly one WriteKey and
        a duress unlock has to restore the budget the same way a normal one
        does. The later of the two wins; an attacker who could set only one
        would gain nothing the other did not already allow.
        """
        return max(0, MAX_PIN_ATTEMPTS
                   - (self._counter(COUNTER_PIN) - self._baseline()))

    def verify_pin(self, pin: str) -> PinResult:
        """Spend an attempt, then ask the chip — twice, in a fixed order.

        The counter is spent first because that is the whole reason this chip
        is in the bill of materials: a counter kept on the SD card can be
        rolled back by anyone holding the card.

        Both PIN slots are always tried, and neither short-circuits the other.
        Checking the duress slot only after the normal one failed would make a
        duress entry measurably faster or slower, and a coercer holding a
        stopwatch is exactly who this is hiding from. Three CheckMacs run on
        every call — two probes and one that leaves the chip authorised — no
        matter which PIN was entered or whether either matched.
        """
        if self.attempts_remaining() == 0:
            self.wipe()
            raise PinLockout("attempt counter exhausted; device wiped")

        self._increment(COUNTER_PIN)                    # spend it first

        key = pin_key(pin, self._serial)
        is_normal = self._checkmac(SLOT_PIN, key)
        is_duress = self._checkmac(SLOT_PIN_DURESS, key)
        role = (PinResult.NORMAL if is_normal
                else PinResult.DURESS if is_duress
                else PinResult.NONE)

        # A CheckMac clears whatever authorisation the previous one left, so
        # the one that has to stand is re-run last. On a wrong PIN this repeats
        # the normal-slot probe, which fails again — the point is that the chip
        # sees the same three commands either way.
        auth_slot = FOR_ROLE.get(role, FOR_ROLE[PinResult.NORMAL])[0]
        self._checkmac(auth_slot, key)

        if role:
            # A duress PIN resets the counter exactly as the normal one does.
            # Leaving it debited would let an attacker who tries both spot the
            # difference in what the device reports afterwards.
            self._set_baseline(role, key)
            self._auth = (role, key)
        elif self.attempts_remaining() == 0:
            self.wipe()
            raise PinLockout("attempt counter exhausted; device wiped")
        return role

    def _checkmac(self, slot: int, key: bytes) -> bool:
        """One CheckMac against `slot`. True if the chip agreed.

        On agreement the chip also records that slot as authorised, which is
        what a ReqAuth slot needs before it will act as a key. That record does
        not survive the chip going to sleep, so it is established immediately
        before the derive rather than held across the liveness gate — ten
        minutes of blood tier would outlast it many times over.
        """
        cal = self._cal
        challenge = bytearray(32)
        if cal.atcab_random(challenge) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not draw a CheckMac challenge")
        challenge = bytes(challenge)
        other = other_data_for(slot, self._serial)
        response = checkmac_response(key, challenge, other, self._serial)
        verified = cal.AtcaReference(0)
        status = cal.atcab_checkmac(CHECKMAC_MODE, slot, challenge,
                                    response, other)
        # The binding reports a mismatch as a status, not an exception, and
        # ATCA_CHECKMAC_VERIFY_FAILED is a normal answer here — it is what a
        # wrong PIN looks like. Anything else is the chip complaining.
        if status == cal.Status.ATCA_SUCCESS:
            return True
        if status == cal.Status.ATCA_CHECKMAC_VERIFY_FAILED:
            return False
        raise DeviceError(
            f"CheckMac against slot {slot} returned status {status}. That is "
            f"neither a match nor a mismatch — check the config zone with "
            f"tools/atecc_config.py verify.")

    def set_pin(self, pin: str, duress_pin: str | None = None) -> None:
        """Write the PIN slots. Provisioning only, before the data zone locks.

        A device with no duress PIN configured still gets slot 4 written, with
        a secret nobody can produce. Leaving it blank would make "is duress set
        up on this device" answerable by asking the chip, and the whole point
        is that it should not be. See duress.py.

        There is deliberately no change_pin: the wrapping key is derived from
        the PIN, so changing it would leave the seed blob unopenable. Changing
        the PIN means reprovisioning from the backup words, which is also the
        only path that proves the owner still has them.
        """
        import os
        if duress_pin is not None and duress_pin == pin:
            raise DeviceError("the duress PIN must differ from the normal one")
        self._write_slot(SLOT_PIN, pin_key(pin, self._serial))
        unreachable = os.urandom(32).hex()
        self._write_slot(SLOT_PIN_DURESS,
                         pin_key(duress_pin or unreachable, self._serial))

        # AND THE SLOTS NOTHING ELSE EVER WROTE. This was the only slot-secret
        # writer in the tree and it wrote two of the five: slots 0, 1 and 5
        # kept whatever the un-provisioned data zone happened to hold, and
        # slot 1 is WriteConfig = Never, so after lock-data its contents were
        # permanent. A wrapping key that is the same on every device is not a
        # key that never leaves the chip, and an attestation key that is the
        # same on every device is one identity for every CELL ever built.
        cal = self._cal
        for slot in (SLOT_WRAP, SLOT_ATTEST, SLOT_WRAP_DURESS):
            rand = bytearray(32)
            if cal.atcab_random(rand) != cal.Status.ATCA_SUCCESS:
                raise DeviceError(
                    f"could not draw a secret for slot {slot} from the chip")
            self._write_slot(slot, bytes(rand))

        # The attempt baselines start at zero, which is where the counters
        # start. _baseline() refuses a baseline ABOVE the counter as tamper,
        # so an un-provisioned slot reading anything higher would make the
        # device unbootable and — the slots being WriteConfig = Encrypt after
        # lock-data — unrecoverable.
        for slot in (SLOT_BASELINE, SLOT_BASELINE_DURESS):
            self._write_slot(slot, bytes(32))

    # ---- keys ----

    def kdf(self, context: bytes) -> bytes:
        """HMAC-SHA256 under the wrapping secret, computed inside the chip.

        Gated on a successful PIN, and single use, matching se.SoftSE. Unlike
        SoftSE the gate is not a flag: slot 0 carries ReqAuth against slot 2,
        so the chip itself refuses to act as a key until a CheckMac under the
        PIN-derived secret has just succeeded. The CheckMac happens here rather
        than in verify_pin because the chip forgets it on sleep and the
        liveness gate takes anywhere from fifteen seconds to ten minutes.

        Which slot answers depends on which PIN was entered — slot 0 for the
        normal one, slot 5 for the duress one. Both are the same command
        against a different number, and the blob that opens is whichever the
        resulting key fits. Nothing above this line branches on the role.
        """
        if self._auth is None:
            raise PinLockout("kdf requires a successful verify_pin first")
        role, key = self._auth
        self._auth = None                               # single use
        auth_slot, wrap_slot, _ = FOR_ROLE[role]
        if not self._checkmac(auth_slot, key):
            raise PinLockout(
                "the chip withdrew the PIN authorisation before the derive")
        try:
            return self._hmac(wrap_slot, context)
        except DeviceError as e:
            raise ConfigError(
                f"slot {wrap_slot} refused to derive immediately after a "
                f"successful CheckMac against slot {auth_slot}. Either "
                f"ReqAuth is pointed at the wrong slot or Counter0 has run "
                f"out. Run `tools/atecc_config.py verify --behaviour`. "
                f"({e})") from None

    def attest_sign(self, digest: bytes) -> bytes:
        from attest import schnorr_sign
        sk = self._attest_seckey()
        try:
            return schnorr_sign(digest, sk)
        finally:
            del sk

    def attest_pubkey(self) -> bytes:
        from attest import schnorr_pubkey
        return schnorr_pubkey(self._attest_seckey())

    def _attest_seckey(self) -> bytes:
        """Derive the secp256k1 attestation scalar from the chip's secret.

        See the module docstring: the chip cannot sign secp256k1 itself, so the
        scalar is derived rather than held. It is a pure function of a secret
        that never leaves slot 1, so it is stable for the life of the device
        and unreproducible anywhere else.

        Slot 1 carries no ReqAuth, deliberately. attest_pubkey() has to answer
        at the idle screen, with nothing unlocked and no PIN entered — a
        co-signer asking for your attestation key should not cost you a PIN
        attempt.
        """
        import secp256k1 as ec
        raw = self._hmac(SLOT_ATTEST, b"CELL/attest/v1")
        counter = 0
        while True:
            try:
                ec.seckey_int(raw)
                return raw
            except ec.BadKey:                                   # pragma: no cover
                counter += 1
                raw = self._hmac(SLOT_ATTEST,
                                 b"CELL/attest/v1|" + bytes([counter]))

    def _read_slot(self, slot: int, length: int = 32) -> bytes:
        cal = self._cal
        buf = bytearray(length)
        if cal.atcab_read_zone(ATCA_ZONE_DATA, slot, 0, 0, buf,
                               length) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"could not read slot {slot}")
        return bytes(buf)

    def _write_slot(self, slot: int, value: bytes) -> None:
        if len(value) != 32:
            raise DeviceError("slot writes are 32 bytes")
        cal = self._cal
        if cal.atcab_write_zone(ATCA_ZONE_DATA, slot, 0, 0, value,
                                32) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"could not write slot {slot}")

    def _write_slot_enc(self, slot: int, value: bytes,
                        enc_key: bytes, enc_key_id: int) -> None:
        """An encrypted write, which is the only kind the baselines accept.

        The data travels under `enc_key`, which the chip also holds in
        `enc_key_id`. Since that key is a function of the PIN, this write is
        reachable by someone who knows the PIN and by nobody else — which is
        what stops an attacker refunding their own attempt budget.
        """
        if len(value) != 32:
            raise DeviceError("slot writes are 32 bytes")
        cal = self._cal
        if cal.atcab_write_enc(slot, 0, value, enc_key,
                               enc_key_id) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"could not write slot {slot} under encryption")

    def _hmac(self, slot: int, message: bytes) -> bytes:
        cal = self._cal
        out = bytearray(32)
        status = cal.atcab_sha_hmac(message, len(message), slot, out,
                                    SHA_MODE_TARGET_TEMPKEY)
        if status != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"HMAC on slot {slot} failed: status {status}")
        return bytes(out)

    # ---- counters ----

    def counter(self) -> int:
        """Operation counter, for attestation anti-replay."""
        return self._counter(COUNTER_OPS)

    def increment_counter(self) -> int:
        return self._increment(COUNTER_OPS)

    def _counter(self, which: int) -> int:
        cal = self._cal
        value = cal.AtcaReference(0)
        if cal.atcab_counter_read(which, value) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"could not read counter {which}")
        return int(value.value)

    def _increment(self, which: int) -> int:
        cal = self._cal
        value = cal.AtcaReference(0)
        if cal.atcab_counter_increment(which, value) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(
                f"could not increment counter {which}. If this is the PIN "
                f"counter it may have reached its ceiling of {COUNTER_MAX}, "
                f"which is permanent — the device can no longer unlock and "
                f"the recovery path is the backup words.")
        return int(value.value)

    def _baseline(self) -> int:
        """The counter value at the last correct PIN, of either kind."""
        values = [int.from_bytes(self._read_slot(s)[:4], "big")
                  for s in (SLOT_BASELINE, SLOT_BASELINE_DURESS)]
        # A baseline ahead of the counter would mean the slot was tampered
        # with to buy attempts. Refuse rather than grant them.
        now = self._counter(COUNTER_PIN)
        for value in values:
            if value > now:
                raise DeviceError(
                    f"a PIN baseline ({value}) is ahead of the attempt counter "
                    f"({now}). This chip has been tampered with.")
        return max(values)

    def _set_baseline(self, role: PinResult, key: bytes) -> None:
        """Record the counter after a correct PIN. Only reachable then."""
        auth_slot, _, baseline_slot = FOR_ROLE[role]
        self._write_slot_enc(
            baseline_slot,
            self._counter(COUNTER_PIN).to_bytes(4, "big") + bytes(28),
            key, auth_slot)

    # ---- destruction ----

    def wipe(self) -> None:
        """Destroy both wrapping secrets. The encrypted seeds become noise.

        Both, not just the one the entered PIN reaches: a wipe is a wipe, and
        leaving the decoy openable would announce that there was a decoy.

        The wrapping slots take a clear write, which is a deliberate trade and
        worth naming. It means anyone holding the device can destroy the wallet
        without knowing the PIN — but they can already do that by entering ten
        wrong PINs, so it grants no capability that was not there. What it does
        not grant is any way to READ those slots, which stay secret. The
        alternative, an encrypted write, would need the PIN, and the one moment
        a wipe has to work is the moment nobody has supplied a correct one.
        """
        cal = self._cal
        for slot in (SLOT_WRAP, SLOT_WRAP_DURESS):
            rand = bytearray(32)
            if cal.atcab_random(rand) != cal.Status.ATCA_SUCCESS:
                raise DeviceError(
                    "could not draw randomness to overwrite the slot")
            self._write_slot(slot, bytes(rand))
        self._auth = None


# --------------------------------------------------------------------------


def probe() -> int:                                             # pragma: no cover
    """`python3 se_atecc.py --probe` on a built device."""
    try:
        se = ATECC608B()
    except ConfigError as e:
        print(f"FAIL — {e}\n")
        print("Configure it first:")
        print("    python3 tools/atecc_config.py plan")
        return 1
    except DeviceError as e:
        print(f"FAIL — {e}")
        return 1
    print("ATECC608B responding.")
    print(f"  serial number          {se.serial.hex()}")
    print("  config and data zones  locked")
    print(f"  PIN attempts remaining {se.attempts_remaining()}")
    print(f"  operation counter      {se.counter()}")
    print(f"  attestation pubkey     {se.attest_pubkey().hex()}")
    print("\nRecord that attestation pubkey. Co-signers register it the way "
          "they register an xpub.")
    print("\nThis says the chip answers. It does not say the config zone "
          "grants\nwhat it should — for that, "
          "`tools/atecc_config.py verify --behaviour`.")
    return 0


def _selftest() -> int:
    """Runs without hardware: checks the parts that are pure logic."""
    print("ATECC608B driver — interface conformance (no hardware required)\n")
    checks = []

    checks.append(("implements the SecureElement interface",
                   not getattr(ATECC608B, "__abstractmethods__", None)))
    checks.append(("declares itself a real security boundary",
                   ATECC608B.IS_SECURE is True))
    checks.append(("slot map is distinct",
                   len({SLOT_WRAP, SLOT_ATTEST, SLOT_PIN, SLOT_BASELINE,
                        SLOT_PIN_DURESS, SLOT_WRAP_DURESS,
                        SLOT_BASELINE_DURESS}) == 7))
    checks.append(("I2C address matches BUILD.md", I2C_ADDRESS == 0x60))

    # Both roles must reach a different wrapping slot, or the duress PIN opens
    # the real wallet and the feature is worse than absent.
    checks.append(("the two PIN roles reach different wrapping slots",
                   FOR_ROLE[PinResult.NORMAL][1]
                   != FOR_ROLE[PinResult.DURESS][1]))
    checks.append(("...and different baselines",
                   FOR_ROLE[PinResult.NORMAL][2]
                   != FOR_ROLE[PinResult.DURESS][2]))

    # The CheckMac digest is the transcription this file's PIN check rests on.
    # Its shape can be checked here; only the chip can confirm the contents.
    d = checkmac_response(bytes(32), bytes(32), bytes(13), bytes(9))
    checks.append(("the CheckMac digest is 32 bytes", len(d) == 32))
    checks.append(("...and depends on the slot secret",
                   checkmac_response(b"\x01" * 32, bytes(32), bytes(13),
                                     bytes(9)) != d))
    checks.append(("...and on the challenge",
                   checkmac_response(bytes(32), b"\x01" * 32, bytes(13),
                                     bytes(9)) != d))
    checks.append(("...and on OtherData",
                   checkmac_response(bytes(32), bytes(32), b"\x01" * 13,
                                     bytes(9)) != d))
    sn = bytes(range(9))
    checks.append(("OtherData quotes the chip's own serial",
                   other_data_for(SLOT_PIN, sn)[7:11] == sn[4:8]
                   and other_data_for(SLOT_PIN, sn)[11:13] == sn[2:4]))
    checks.append(("the PIN key is device-bound",
                   pin_key("12345678", sn) != pin_key("12345678", bytes(9))))
    checks.append(("...and PIN-bound",
                   pin_key("12345678", sn) != pin_key("87654321", sn)))

    # Eight digits is not a style choice — see the module docstring.
    checks.append(("an 8-digit keyspace outlives the counter",
                   10 ** 8 > COUNTER_MAX))

    # Without cryptoauthlib the failure must be an explanation, not a traceback
    # from three layers down.
    try:
        __import__("cryptoauthlib")
        checks.append(("cryptoauthlib present — run --probe on hardware", True))
    except ImportError:
        try:
            _lib()
            checks.append(("missing library reports an install hint", False))
        except DeviceError as e:
            checks.append(("missing library reports an install hint",
                           "pip install cryptoauthlib" in str(e)))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe chip itself is unverified until `python3 se_atecc.py --probe`")
    print("and `python3 tools/atecc_config.py verify --behaviour` run on a")
    print("built device. VALIDATION.md tracks that.")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    raise SystemExit(probe() if "--probe" in sys.argv else _selftest())
