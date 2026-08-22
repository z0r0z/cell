"""The real ATECC608B, on I2C at 0x60.

se.py defines the interface and ships a software stub for the laptop. This is
the part that talks to the chip. It cannot be exercised without hardware, so
`run_tests.py` runs its argument checks and skips the rest, and VALIDATION.md
records it as unverified until someone runs `python3 se_atecc.py --probe` on a
built device.

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

SLOT MAP. Configure once, at provisioning, then lock the config zone. A chip
whose config is not locked will happily answer commands that read the slots
back, so `assert_locked()` runs before anything else and refuses if it is not.

    Slot 0   wrapping secret     IsSecret, no read, HMAC use only
    Slot 1   attestation secret  IsSecret, no read, HMAC use only
    Slot 2   PIN verifier        IsSecret, CheckMac target
    Slot 3   PIN baseline        written only after a correct PIN
    Counter0 PIN attempts        monotonic, never decreases
"""

from __future__ import annotations

import hashlib

from se import MAX_PIN_ATTEMPTS, PinLockout, SecureElement

SLOT_WRAP = 0
SLOT_ATTEST = 1
SLOT_PIN = 2
SLOT_PIN_BASELINE = 3
COUNTER_PIN = 0

I2C_ADDRESS = 0x60


class DeviceError(Exception):
    """The chip is missing, misconfigured, or answered an error."""


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

    def __init__(self, bus: int = 1, address: int = I2C_ADDRESS):
        cal = _lib()
        cfg = cal.cfg_ateccx08a_i2c_default()
        cfg.cfg.atcai2c.bus = bus
        cfg.cfg.atcai2c.slave_address = address << 1
        if cal.atcab_init(cfg) != cal.Status.ATCA_SUCCESS:
            raise DeviceError(
                f"no ATECC608B answered at I2C {address:#04x} on bus {bus}. "
                f"Check the pull-ups and that I2C is enabled.")
        self._cal = cal
        self._pin_authorised = False
        self.assert_locked()

    # ---- configuration ----

    def assert_locked(self) -> None:
        """Refuse to use a chip whose zones are still writable.

        An unlocked chip is a chip whose slots can be read or replaced. Running
        against one gives every appearance of security and none of it, so this
        is a hard failure rather than a warning.
        """
        cal = self._cal
        for zone, name in ((cal.ATCA_ZONE_CONFIG, "config"),
                           (cal.ATCA_ZONE_DATA, "data")):
            locked = cal.AtcaReference(0)
            if cal.atcab_is_locked(zone, locked) != cal.Status.ATCA_SUCCESS:
                raise DeviceError(f"could not read the {name} zone lock state")
            if not bool(locked.value):
                raise DeviceError(
                    f"the {name} zone is not locked. This chip's slots can "
                    f"still be read or rewritten — provision it with "
                    f"tools/provision.py --lock before trusting it.")

    # ---- PIN ----

    def attempts_remaining(self) -> int:
        """Budget left before the wipe.

        The chip's counters only ever increase — there is no reset command, by
        design. So "ten attempts, refreshed by a correct PIN" is expressed as a
        distance: the counter now, minus its value at the last correct PIN.
        That baseline lives in slot 3 ON THE CHIP, not on the SD card, because
        a baseline an attacker can rewrite is a counter an attacker can roll
        back, which is the exact property this part was bought for. Writing it
        requires a correct PIN, so raising it is not something an attacker can
        do without already having won.
        """
        return max(0, MAX_PIN_ATTEMPTS
                   - (self._counter(COUNTER_PIN) - self._baseline()))

    def verify_pin(self, pin: str) -> bool:
        """Increment the monotonic counter, THEN compare.

        The order is the whole reason this chip is in the bill of materials.
        A counter kept on the SD card can be rolled back by anyone holding the
        card, which turns a six-digit PIN into an afternoon of guessing.
        """
        if self.attempts_remaining() == 0:
            self.wipe()
            raise PinLockout("attempt counter exhausted; device wiped")

        self._increment(COUNTER_PIN)                    # spend it first
        cal = self._cal
        challenge = hashlib.sha256(b"CELL/pin/v1|" + pin.encode()).digest()
        ok = cal.AtcaReference(0)
        status = cal.atcab_checkmac(
            0, SLOT_PIN, challenge,
            self._pin_mac(challenge), bytes(13), ok)
        if status != cal.Status.ATCA_SUCCESS:
            if self.attempts_remaining() == 0:
                self.wipe()
                raise PinLockout("attempt counter exhausted; device wiped")
            return False
        self._set_baseline()
        self._pin_authorised = True
        return True

    def _pin_mac(self, challenge: bytes) -> bytes:
        """The MAC the chip is asked to reproduce from its stored PIN key."""
        return hashlib.sha256(challenge + bytes([SLOT_PIN])).digest()

    # ---- keys ----

    def kdf(self, context: bytes) -> bytes:
        """HMAC-SHA256 under the slot-0 secret, computed inside the chip.

        Gated on a successful PIN, and single use, matching se.SoftSE. Slot 0
        is configured so the chip itself requires the PIN slot to have been
        satisfied in the same session; this flag is the firmware-side half of
        that, and it is here so a code path that reached the KDF without
        spending an attempt would fail on a laptop as well as on hardware.
        """
        if not self._pin_authorised:
            raise PinLockout("kdf requires a successful verify_pin first")
        self._pin_authorised = False
        return self._hmac(SLOT_WRAP, context)

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

    def _hmac(self, slot: int, message: bytes) -> bytes:
        cal = self._cal
        out = bytearray(32)
        status = cal.atcab_sha_hmac(message, len(message), slot, out,
                                    cal.SHA_MODE_TARGET_TEMPKEY)
        if status != cal.Status.ATCA_SUCCESS:
            raise DeviceError(f"HMAC on slot {slot} failed: status {status}")
        return bytes(out)

    # ---- counters ----

    def counter(self) -> int:
        """Operation counter, for attestation anti-replay."""
        return self._counter(1)

    def increment_counter(self) -> int:
        return self._increment(1)

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
            raise DeviceError(f"could not increment counter {which}")
        return int(value.value)

    def _baseline(self) -> int:
        """The counter value at the last correct PIN, read from slot 3."""
        cal = self._cal
        buf = bytearray(32)
        if cal.atcab_read_zone(cal.ATCA_ZONE_DATA, SLOT_PIN_BASELINE, 0, 0,
                               buf, 32) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not read the PIN baseline slot")
        value = int.from_bytes(bytes(buf[:4]), "big")
        # A baseline ahead of the counter would mean the slot was tampered
        # with to buy attempts. Refuse rather than grant them.
        now = self._counter(COUNTER_PIN)
        if value > now:
            raise DeviceError(
                f"PIN baseline ({value}) is ahead of the attempt counter "
                f"({now}). This chip has been tampered with.")
        return value

    def _set_baseline(self) -> None:
        """Record the counter after a correct PIN. Only reachable then."""
        cal = self._cal
        value = self._counter(COUNTER_PIN).to_bytes(4, "big") + bytes(28)
        if cal.atcab_write_zone(cal.ATCA_ZONE_DATA, SLOT_PIN_BASELINE, 0, 0,
                                value, 32) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not record the PIN baseline")

    # ---- destruction ----

    def wipe(self) -> None:
        """Destroy the wrapping secret. The encrypted seed becomes noise.

        Slot 0 is configured writable-once-per-session under the chip's own
        encryption, so this overwrites it with randomness the chip generates
        and nobody sees. There is no recovery from this and there is not meant
        to be — the recovery path is the owner's backup words.
        """
        cal = self._cal
        rand = bytearray(32)
        if cal.atcab_random(rand) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not draw randomness to overwrite the slot")
        if cal.atcab_write_zone(cal.ATCA_ZONE_DATA, SLOT_WRAP, 0, 0,
                                bytes(rand), 32) != cal.Status.ATCA_SUCCESS:
            raise DeviceError("could not overwrite the wrapping secret")
        self._pin_authorised = False


# --------------------------------------------------------------------------


def probe() -> int:                                             # pragma: no cover
    """`python3 se_atecc.py --probe` on a built device."""
    try:
        se = ATECC608B()
    except DeviceError as e:
        print(f"FAIL — {e}")
        return 1
    print("ATECC608B responding.")
    print("  config and data zones  locked")
    print(f"  PIN attempts remaining {se.attempts_remaining()}")
    print(f"  operation counter      {se.counter()}")
    print(f"  attestation pubkey     {se.attest_pubkey().hex()}")
    print("\nRecord that attestation pubkey. Co-signers register it the way "
          "they register an xpub.")
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
                   len({SLOT_WRAP, SLOT_ATTEST, SLOT_PIN,
                        SLOT_PIN_BASELINE}) == 4))
    checks.append(("I2C address matches BUILD.md", I2C_ADDRESS == 0x60))

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
    print("runs on a built device. VALIDATION.md tracks that.")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    raise SystemExit(probe() if "--probe" in sys.argv else _selftest())
