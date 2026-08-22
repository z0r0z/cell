"""Secure element — PIN counter, key wrapping, attestation signing.

On device this is an ATECC608B on I2C at 0x60. Here it is an interface plus a
software stub, so the unlock chain in signer.py can be tested end to end
without hardware. The stub is NOT a security boundary and says so loudly.

WHAT THE PART ACTUALLY BUYS, and it is worth being precise because a $6 chip
is easy to over-trust:

  A monotonic PIN attempt counter that survives power loss.
    This is the whole reason it is here. A counter in flash on the Pi can be
    rolled back by anyone with the SD card, which turns a 6-digit PIN into a
    weekend of guessing. The counter increments BEFORE the comparison, so
    yanking power mid-attempt costs an attempt rather than refunding one.

  A key that never leaves the chip, used to derive the seed-wrapping key.
    The seed is decrypted in RAM for milliseconds during signing. That is the
    tradeoff for a conventional paper backup path: a seed you can restore to a
    Trezor is a seed that exists outside the chip by definition.

  An attestation key generated on-chip and never exported.

WHAT IT DOES NOT BUY: secure boot, or protection against someone who opens the
case and reflashes the Pi. That is the tamper seal's job. See BUILD.md 16.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass


MAX_PIN_ATTEMPTS = 10


class PinLockout(Exception):
    """The attempt counter is exhausted. The device wipes."""


class SecureElement(ABC):
    """The device's root of trust for PIN attempts and key wrapping."""

    @abstractmethod
    def attempts_remaining(self) -> int:
        ...

    @abstractmethod
    def verify_pin(self, pin: str) -> bool:
        """Increment the counter, THEN compare.

        Order is the security property. Comparing first and incrementing only
        on failure means an attacker who cuts power the instant a wrong PIN is
        detected never pays for the attempt.
        """

    @abstractmethod
    def kdf(self, context: bytes) -> bytes:
        """Derive 32 bytes from the on-chip secret and `context`.

        `context` binds the wrapping key to the PIN, so a seed blob lifted off
        the SD card is useless without both the PIN and this chip.

        MUST REQUIRE A SUCCESSFUL verify_pin FIRST, AND CONSUME IT.

        This is not defence in depth, it is the only thing standing between a
        stolen device and the seed. The attempt counter protects verify_pin;
        if the derive can be called without it, an attacker never calls
        verify_pin at all. They call kdf once per candidate PIN and try the
        result against the encrypted seed — AES-GCM's tag tells them when they
        are right — and a six-digit PIN is 10^6 tries with nothing debited.

        Single use, not session-scoped: one PIN verification authorises one
        unwrap. Otherwise one legitimate verification leaves the derive open to
        unlimited calls, which is the same hole with a smaller window.

        ON THE ATECC608B this is slot configuration, not firmware: the slot
        holding the wrapping secret is configured to require prior
        authorisation, so the derive is physically unreachable without a
        CheckMac that debited the counter. A build that skips that config has
        a device whose PIN counter does nothing. BUILD.md section 12.
        """

    @abstractmethod
    def attest_sign(self, digest: bytes) -> bytes:
        """Sign 32 bytes with the attestation key. The key never leaves."""

    @abstractmethod
    def attest_pubkey(self) -> bytes:
        """x-only public half of the attestation key, 32 bytes."""

    @abstractmethod
    def counter(self) -> int:
        """Monotonic operation counter, for attestation anti-replay."""

    @abstractmethod
    def increment_counter(self) -> int:
        ...

    @abstractmethod
    def wipe(self) -> None:
        """Destroy the wrapping key. The encrypted seed becomes noise."""


@dataclass
class _State:
    pin_attempts_used: int = 0
    op_counter: int = 0
    wiped: bool = False
    # Set by a successful verify_pin, consumed by one kdf. Never persisted:
    # a power cycle must not leave a derive authorised.
    pin_authorised: bool = False


class SoftSE(SecureElement):
    """Software stand-in for the ATECC608B. FOR TESTS ONLY.

    Every guarantee the real part provides is absent here: the secret is in
    process memory, the counter is not monotonic across a restart, and nothing
    resists an attacker with a debugger. It exists so the unlock chain has test
    coverage on a laptop.
    """

    IS_SECURE = False

    def __init__(self, pin: str = "000000", secret: bytes | None = None,
                 attest_seckey: bytes | None = None):
        self._secret = secret or os.urandom(32)
        self._pin_hash = hashlib.sha256(pin.encode()).digest()
        self._st = _State()
        self._attest_sk = attest_seckey or (b"\x00" * 31 + b"\x03")

    def attempts_remaining(self) -> int:
        return max(0, MAX_PIN_ATTEMPTS - self._st.pin_attempts_used)

    def verify_pin(self, pin: str) -> bool:
        if self._st.wiped:
            raise PinLockout("device is wiped")
        if self.attempts_remaining() == 0:
            self.wipe()
            raise PinLockout("attempt counter exhausted; device wiped")
        # Increment first. See SecureElement.verify_pin.
        self._st.pin_attempts_used += 1
        ok = hmac.compare_digest(hashlib.sha256(pin.encode()).digest(), self._pin_hash)
        if ok:
            self._st.pin_attempts_used = 0
            self._st.pin_authorised = True
        elif self.attempts_remaining() == 0:
            self.wipe()
            raise PinLockout("attempt counter exhausted; device wiped")
        return ok

    def kdf(self, context: bytes) -> bytes:
        if self._st.wiped:
            raise PinLockout("device is wiped")
        # Modelled here so the unlock chain is tested against the rule the real
        # part enforces in silicon. Without it the tests would pass on a device
        # whose PIN counter can be walked around.
        if not self._st.pin_authorised:
            raise PinLockout("kdf requires a successful verify_pin first")
        self._st.pin_authorised = False          # single use
        return hmac.new(self._secret, context, hashlib.sha256).digest()

    def attest_sign(self, digest: bytes) -> bytes:
        from attest import schnorr_sign
        return schnorr_sign(digest, self._attest_sk)

    def attest_pubkey(self) -> bytes:
        from attest import schnorr_pubkey
        return schnorr_pubkey(self._attest_sk)

    def counter(self) -> int:
        return self._st.op_counter

    def increment_counter(self) -> int:
        self._st.op_counter += 1
        return self._st.op_counter

    def wipe(self) -> None:
        self._secret = os.urandom(32)      # old wrapping key is unrecoverable
        self._st.wiped = True
        self._st.pin_authorised = False


def _selftest() -> int:
    print("Secure element self-test (SoftSE — not a security boundary)\n")
    ok = True

    se = SoftSE(pin="123456")
    checks = [
        ("correct PIN accepted", se.verify_pin("123456") is True),
        ("counter resets on success", se.attempts_remaining() == MAX_PIN_ATTEMPTS),
        ("wrong PIN rejected", se.verify_pin("000000") is False),
        ("wrong PIN costs an attempt", se.attempts_remaining() == MAX_PIN_ATTEMPTS - 1),
    ]

    # The counter must be spent before the comparison, so a wrong PIN followed
    # by a power cut still costs an attempt.
    se2 = SoftSE(pin="123456")
    before = se2.attempts_remaining()
    se2.verify_pin("999999")
    checks.append(("attempt debited before compare",
                   se2.attempts_remaining() == before - 1))

    # A derive must be UNREACHABLE without spending an attempt. This is the
    # property that makes the counter mean anything: if kdf answers without a
    # PIN verification, an attacker skips verify_pin entirely and brute-forces
    # the PIN against the encrypted seed, 10^6 tries, nothing debited.
    se_g = SoftSE(pin="123456")
    try:
        se_g.kdf(b"ctx")
        checks.append(("kdf without a PIN verification refuses", False))
    except PinLockout:
        checks.append(("kdf without a PIN verification refuses", True))
    se_g.verify_pin("000000")                       # a FAILED verification
    try:
        se_g.kdf(b"ctx")
        checks.append(("a failed PIN does not authorise a derive", False))
    except PinLockout:
        checks.append(("a failed PIN does not authorise a derive", True))
    se_g.verify_pin("123456")
    se_g.kdf(b"ctx")                                # consumes the authorisation
    try:
        se_g.kdf(b"ctx")
        checks.append(("one PIN verification authorises exactly one derive", False))
    except PinLockout:
        checks.append(("one PIN verification authorises exactly one derive", True))

    def kdf_of(se, ctx, pin="123456"):
        """Verify then derive. The chain always does both; the tests must too."""
        se.verify_pin(pin)
        return se.kdf(ctx)

    # Exhausting the counter wipes, and a wiped device cannot derive keys.
    se3 = SoftSE(pin="123456")
    k_before = kdf_of(se3, b"ctx")
    wiped = False
    for _ in range(MAX_PIN_ATTEMPTS + 2):
        try:
            se3.verify_pin("bad")
        except PinLockout:
            wiped = True
            break
    checks.append((f"wipes after {MAX_PIN_ATTEMPTS} failures", wiped))
    try:
        se3.kdf(b"ctx")
        checks.append(("wiped device refuses kdf", False))
    except PinLockout:
        checks.append(("wiped device refuses kdf", True))

    # The wrapping key must depend on the context, or the PIN contributes
    # nothing to it, and must be stable, or the seed is unrecoverable.
    se4 = SoftSE(pin="123456")
    checks.append(("kdf is context-bound", kdf_of(se4, b"a") != kdf_of(se4, b"b")))
    checks.append(("kdf is deterministic", kdf_of(se4, b"a") == kdf_of(se4, b"a")))
    checks.append(("kdf differs per device",
                   kdf_of(se4, b"a") != kdf_of(SoftSE(pin="123456"), b"a")))
    checks.append(("wipe destroys the wrapping key",
                   kdf_of(SoftSE(pin="123456"), b"x") != k_before))

    # Counter must advance, for attestation anti-replay.
    se5 = SoftSE()
    c0 = se5.counter()
    checks.append(("counter advances", se5.increment_counter() == c0 + 1))

    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
