"""Duress PIN: a second PIN that opens a different wallet.

WHAT IT IS FOR. BUILD.md section 16 concedes one attack outright: someone who
lances you and uses the sample within the minute passes every gate. Sensing
cannot fix that. No measurement distinguishes willing blood from coerced
blood, and a biometric makes it worse rather than better -- a PIN needs your
cooperation, a finger needs only your hand.

This is the one mechanism that helps. Under coercion you give up a PIN that
works: the device unlocks, signs, and behaves in every observable way like a
normal session. It just unlocks a different wallet.

HOW IT WORKS, and why it needs no new cryptography. The wrapping key already
comes from `kdf(unwrap_context(pin))`, so a different PIN derives a different
key. Two PINs therefore open two different seed blobs with no branching in the
unlock chain at all -- the duress path is not a special case in the code, it is
the same code reaching a different secret.

WHAT MAKES IT CREDIBLE, which is harder than making it work:

  A device with no duress PIN configured still stores a hash, of a random
  value nobody can enter. Otherwise "is duress set up on this device" is
  answerable by reading the chip.

  Both PIN hashes are always compared, and neither short-circuits. Checking
  duress only after the normal PIN fails makes a duress entry measurably
  slower, and someone holding you at gunpoint can hold a stopwatch.

  Both seed blobs are always written, even when the second is an unreachable
  random seed. One file on the card would mean duress is off; two would mean
  it is on.

  A duress PIN resets the attempt counter exactly as the normal one does, so
  entering one then the other leaves nothing different to read afterwards.

WHAT IT DOES NOT DO. The firmware is public, so an attacker knows the feature
exists. What they cannot learn is whether THIS device has one configured, or
which of two PINs they were given. That is the whole of the protection: not
that the mechanism is secret, but that its use is unfalsifiable. Anyone who
tells you a duress PIN hides more than that is selling something.

THE DECOY HAS TO BE REAL. An empty wallet tells the coercer they were given
the wrong PIN, which puts you back where you started and angrier. Fund it with
an amount that is plausible for you to hold and survivable to lose. That is a
judgement this code cannot make.

IN A QUORUM IT IS ALSO A SILENT ALARM. The decoy account's key was never
registered in the co-signer roster, so `attest.verify_quorum` fails for that
signer without anything in the record announcing why. The transaction does not
execute and nobody in the room learns that from the device.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import seedstore
from se import PinResult


class NoBlobOpened(Exception):
    """Neither stored blob decrypted under the derived key.

    Means a wrong PIN, the wrong device, or a corrupted store -- deliberately
    not distinguished, because the difference is only useful to an attacker.
    """


@dataclass(frozen=True)
class SeedPair:
    """The two wrapped seeds a provisioned device carries.

    Order is fixed and meaningless: whichever the key opens is the one that was
    meant. Nothing about the pair reveals which slot is the decoy, and code
    that tried to know would be code an attacker could ask.
    """

    primary: bytes
    secondary: bytes

    def blobs(self) -> tuple[bytes, bytes]:
        return (self.primary, self.secondary)


def wrap_pair(mnemonic: str, decoy: str,
              normal_key: bytes, duress_key: bytes) -> SeedPair:
    """Wrap both seeds, each under the key its own PIN derives."""
    if normal_key == duress_key:
        raise ValueError("both PINs derived the same key; they must differ")
    return SeedPair(primary=seedstore.wrap(mnemonic, normal_key).pack(),
                    secondary=seedstore.wrap(decoy, duress_key).pack())


def unwrap_any(pair: SeedPair, key: bytes) -> bytearray:
    """Open whichever blob this key fits.

    Always attempts both, in a fixed order, whichever succeeds. Returning early
    on the first success would make a normal unlock faster than a duress one,
    which is the timing tell this whole design exists to avoid. AES-GCM
    authenticates, so at most one can open.
    """
    found: bytearray | None = None
    for blob in pair.blobs():
        try:
            seed = seedstore.unwrap(blob, key)
        except Exception:                                   # noqa: BLE001
            continue
        if found is None:
            found = seed
        else:
            # Two blobs under one key means the pair was built wrong. Refuse
            # rather than pick, because picking would be silently arbitrary.
            raise NoBlobOpened("both blobs opened under one key")
    if found is None:
        raise NoBlobOpened("no seed blob opened")
    return found


def decoy_mnemonic(entropy: bytes | None = None) -> str:
    """A seed for the decoy wallet.

    Used for the unreachable second blob when no duress PIN is configured, and
    as the starting point for a real decoy when one is. 24 words either way, so
    the two blobs are the same length and the store carries no clue.
    """
    import bip39
    return bip39.entropy_to_mnemonic(entropy or os.urandom(32))


def role_note(role: PinResult) -> str:
    """What the device records internally. NEVER shown on screen.

    The display must be identical on both paths. This exists so a coordinator
    reading a device log after the fact can tell, not so the device can hint.
    """
    return {PinResult.NORMAL: "normal", PinResult.DURESS: "duress"}.get(role, "none")
