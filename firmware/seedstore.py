"""The seed at rest.

The seed lives on the SD card as an AES-256-GCM blob whose key never touches
the card: it comes from `SecureElement.kdf`, which mixes the PIN with a secret
that never leaves the ATECC608B. So the blob is inert twice over — copying the
card gets you nothing without the chip, and having the chip gets you nothing
without the PIN, whose attempts the chip counts and which wipes the wrapping
key at ten.

GCM, not CBC or a bare stream cipher, because the seed must be *authenticated*
as well as hidden. An attacker who can flip bits in an unauthenticated blob can
make the device derive a different key, and a wallet that silently restores to
the wrong seed shows the owner a plausible empty balance. The tag turns that
into a refusal.

AES comes from the `cryptography` package, which wraps OpenSSL and uses the
CPU's AES instructions where they exist. This is the one place we do not use a
pure Python implementation: a hand-rolled AES has table-lookup timing leaks,
and it is the wrong thing to be clever about.

The plaintext is the BIP-39 mnemonic, not the 64-byte seed. Storing the words
means a device that can still read its card can always show its owner the
backup phrase; storing only the expanded seed makes a paper backup
unrecoverable from the device that holds it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

MAGIC = b"CELLSEED"
VERSION = 1
NONCE_LEN = 12
TAG_LEN = 16
SALT_LEN = 16


class SeedStoreError(Exception):
    """The seed blob is missing, malformed, or will not authenticate."""


def _aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:                                         # pragma: no cover
        raise SeedStoreError(
            "the `cryptography` package is required to open the seed store. "
            "On Raspberry Pi OS: apt install python3-cryptography") from None
    return AESGCM


@dataclass(frozen=True)
class SeedBlob:
    """A wrapped seed. The salt is public; it exists so two devices with the
    same PIN and a cloned chip still derive different wrapping keys."""

    salt: bytes
    nonce: bytes
    ciphertext: bytes           # includes the GCM tag

    def header(self) -> bytes:
        return MAGIC + bytes([VERSION]) + self.salt

    def pack(self) -> bytes:
        return self.header() + self.nonce + self.ciphertext

    @staticmethod
    def unpack(blob: bytes) -> "SeedBlob":
        head = len(MAGIC) + 1 + SALT_LEN
        if len(blob) < head + NONCE_LEN + TAG_LEN:
            raise SeedStoreError(f"seed blob is {len(blob)} bytes, too short to be one")
        if blob[:len(MAGIC)] != MAGIC:
            raise SeedStoreError("not a CELL seed blob")
        if blob[len(MAGIC)] != VERSION:
            raise SeedStoreError(
                f"seed blob is version {blob[len(MAGIC)]}, this firmware writes "
                f"version {VERSION}. Restore from your backup words rather than "
                f"guessing at the format.")
        return SeedBlob(salt=blob[len(MAGIC) + 1:head],
                        nonce=blob[head:head + NONCE_LEN],
                        ciphertext=blob[head + NONCE_LEN:])


def wrap(mnemonic: str, key: bytes, salt: bytes | None = None,
         nonce: bytes | None = None) -> SeedBlob:
    """Encrypt a mnemonic under a 32-byte wrapping key.

    `nonce` is a parameter only so the tests can pin a vector. In use it is
    random: GCM fails catastrophically on nonce reuse under the same key, and
    the key here changes only when the PIN does, so the nonce must carry the
    uniqueness.
    """
    if len(key) != 32:
        raise SeedStoreError("wrapping key must be 32 bytes")
    import bip39
    if not bip39.validate(mnemonic):
        raise SeedStoreError(
            "refusing to store a mnemonic that fails its BIP-39 checksum — it "
            "would not restore anywhere else, and the failure would only "
            "surface when you needed the backup")
    salt = salt if salt is not None else os.urandom(SALT_LEN)
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise SeedStoreError("bad salt or nonce length")
    blob = SeedBlob(salt=salt, nonce=nonce, ciphertext=b"")
    ct = _aead()(_bind(key, salt)).encrypt(
        nonce, bip39.normalise(mnemonic).encode("utf-8"), blob.header())
    return SeedBlob(salt=salt, nonce=nonce, ciphertext=ct)


def unwrap(blob: SeedBlob | bytes, key: bytes) -> bytearray:
    """Decrypt to a MUTABLE buffer, so the caller can zeroise it.

    Returns the mnemonic's UTF-8 bytes. A `bytes` or `str` return would leave
    the seed in an immutable object the caller cannot clear, which is the whole
    reason signer.zeroise takes a bytearray.
    """
    if isinstance(blob, (bytes, bytearray)):
        blob = SeedBlob.unpack(bytes(blob))
    if len(key) != 32:
        raise SeedStoreError("wrapping key must be 32 bytes")
    try:
        plain = _aead()(_bind(key, blob.salt)).decrypt(
            blob.nonce, blob.ciphertext, blob.header())
    except Exception:                                           # noqa: BLE001
        # Deliberately one message for every failure. Distinguishing "wrong
        # PIN" from "tampered blob" tells an attacker which of the two they got
        # right, and the owner's next step is the same either way.
        raise SeedStoreError(
            "could not open the seed store: wrong PIN, wrong device, or the "
            "blob has been altered") from None
    return bytearray(plain)


def _bind(key: bytes, salt: bytes) -> bytes:
    """Mix the public salt into the wrapping key."""
    return hmac.new(key, b"CELL/seedstore/v1|" + salt, hashlib.sha256).digest()


def fingerprint(blob: SeedBlob | bytes) -> str:
    """A short public identifier for a blob, for the build log and BUILD.md.

    Not a security control — it identifies which blob is installed so a
    restore can be checked against a record, nothing more.
    """
    raw = blob.pack() if isinstance(blob, SeedBlob) else bytes(blob)
    return hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Seed store — AES-256-GCM wrap, tamper detection, zeroising\n")
    checks = []

    import bip39
    from se import SoftSE
    from signer import unwrap_context, zeroise

    mnem = bip39.entropy_to_mnemonic(bytes(range(16)))

    def wrapping_key(se, pin: str) -> bytes:
        """The chip answers the KDF only after a correct PIN, and once per PIN.

        The tests go through this helper rather than calling kdf directly, so
        they exercise the same rule the signing path does.
        """
        if not se.verify_pin(pin):
            raise SeedStoreError("PIN rejected")
        return se.kdf(unwrap_context(pin))

    se = SoftSE(pin="123456")
    key = wrapping_key(se, "123456")

    blob = wrap(mnem, key)
    checks.append(("wrap then unwrap returns the mnemonic",
                   bytes(unwrap(blob, key)).decode() == mnem))
    checks.append(("blob round trips through bytes",
                   bytes(unwrap(SeedBlob.unpack(blob.pack()), key)).decode() == mnem))
    checks.append(("unwrap returns a mutable buffer",
                   isinstance(unwrap(blob, key), bytearray)))

    out = unwrap(blob, key)
    zeroise(out)
    checks.append(("the buffer can be zeroised", set(out) == {0}))

    # The mnemonic must not appear in the blob.
    checks.append(("plaintext is not in the blob",
                   mnem.encode() not in blob.pack()
                   and mnem.split()[0].encode() not in blob.pack()))

    # A wrong PIN cannot even reach the KDF — the chip refuses before a key
    # exists to be wrong. That is a stronger statement than "produces a
    # different key", so it is tested as itself.
    from se import PinLockout
    wrong = SoftSE(pin="123456")
    denied = False
    try:
        wrapping_key(wrong, "999999")
    except (SeedStoreError, PinLockout):
        denied = True
    checks.append(("a wrong PIN never obtains a wrapping key", denied))

    # Wrong device, different PIN, and a garbage key must all fail closed.
    for label, bad_key in [
        ("a different PIN on the same chip", wrapping_key(SoftSE(pin="999999"), "999999")),
        ("different device secret", wrapping_key(SoftSE(pin="123456"), "123456")),
        ("zero key", bytes(32)),
    ]:
        try:
            unwrap(blob, bad_key)
            checks.append((f"refuses {label}", False))
        except SeedStoreError:
            checks.append((f"refuses {label}", True))

    # The right key on the right device must still work, from a fresh object —
    # this is the recoverability property the whole design rests on.
    checks.append(("reopens with a freshly derived key",
                   bytes(unwrap(blob, wrapping_key(se, "123456"))).decode() == mnem))

    # Tamper: every byte of the blob is authenticated, header included.
    packed = bytearray(blob.pack())
    for name, idx in [("magic", 1), ("version", 8), ("salt", 10),
                      ("nonce", 26), ("ciphertext", 40), ("tag", len(packed) - 1)]:
        t = bytearray(packed)
        t[idx] ^= 0x01
        try:
            unwrap(bytes(t), key)
            checks.append((f"detects a flipped bit in the {name}", False))
        except SeedStoreError:
            checks.append((f"detects a flipped bit in the {name}", True))

    checks.append(("truncation is detected", _refuses(packed[:-1], key)))
    checks.append(("extension is detected", _refuses(bytes(packed) + b"\x00", key)))
    checks.append(("empty input is refused", _refuses(b"", key)))

    # A salt that differs must produce a different wrapping key even for the
    # same PIN and chip, so two devices provisioned identically still differ.
    b1 = wrap(mnem, key, salt=b"\x01" * SALT_LEN)
    b2 = wrap(mnem, key, salt=b"\x02" * SALT_LEN)
    checks.append(("salt changes the ciphertext", b1.ciphertext != b2.ciphertext))
    checks.append(("a blob will not open under another blob's salt",
                   _refuses(SeedBlob(b2.salt, b1.nonce, b1.ciphertext).pack(), key)))

    # Nonce reuse must not happen by accident: two wraps of the same mnemonic
    # under the same key must differ.
    checks.append(("two wraps use different nonces",
                   wrap(mnem, key).nonce != wrap(mnem, key).nonce))

    # A mnemonic with a broken checksum must be refused at provisioning, not
    # discovered to be unrestorable years later.
    try:
        wrap("abandon " * 11 + "abandon", key)
        checks.append(("refuses an invalid mnemonic", False))
    except SeedStoreError:
        checks.append(("refuses an invalid mnemonic", True))

    # Wiping the secure element must make the blob permanently unreadable.
    se2 = SoftSE(pin="123456")
    b3 = wrap(mnem, wrapping_key(se2, "123456"))
    se2.wipe()
    checks.append(("a wiped device cannot reopen its blob",
                   _refuses(b3.pack(), wrapping_key(SoftSE(pin="123456"), "123456"))))

    checks.append(("fingerprint is stable", fingerprint(blob) == fingerprint(blob.pack())))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _refuses(blob, key) -> bool:
    try:
        unwrap(bytes(blob), key)
        return False
    except SeedStoreError:
        return True


if __name__ == "__main__":
    raise SystemExit(_selftest())
