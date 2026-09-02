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

HOW THE DEVICE KNOWS WHICH WALLET A SPEND IS FOR, given that it must not ask.
Not from the PIN. The transaction is rendered before the PIN is entered --
that ordering is the unlock chain and it does not bend for this -- so by the
time the PIN could say, the screen is already drawn. It comes from the PSBT
instead: a coordinator spending the decoy's coins quotes the decoy's origin
fingerprint, because that is what its own descriptor says. `wallet._wallet_for`
reads it and picks the matching account xpubs. Nothing is trusted on that
basis; every derivation is rebuilt and compared afterwards exactly as before.
It only decides which of two recorded wallets to check against.

So both halves are recorded at provisioning: two wrapped seeds AND two sets of
watch-only accounts. A device that stored only the real wallet's accounts can
unwrap the decoy seed and then refuse to sign with it, because the signer
checks the unwrapped seed against a recorded fingerprint. That is not a
theory; it is what the first attempt at this did.

WHAT IT DOES NOT DO. The firmware is public, so an attacker knows the feature
exists. What they cannot learn is whether THIS device has one configured, or
which of two PINs they were given. That is the whole of the protection: not
that the mechanism is secret, but that its use is unfalsifiable. Anyone who
tells you a duress PIN hides more than that is selling something.

BOTH CHAINS, BY DIFFERENT ROUTES. Bitcoin reads the wallet off the PSBT, as
above. An Ethereum request has no key origin to read -- one account path, and
nothing in the transaction naming a wallet -- so `wallet.sign_eth` cannot ask
the same question. It does not need to: EthereumSpend renders the chain, the
destination, the amount, the fee cap and the nonce, and never the sender, so
nothing about the account reaches the screen before the PIN and the wallet can
be chosen by the seed that opened. `wallet._wallet_of_seed` does it, after the
gate, comparing both recorded fingerprints without short-circuiting. Signing
Ethereum under duress used to die on "the unwrapped seed derives a different
sending address" -- a refusal that tells a coercer precisely which PIN they
were handed.

AND ONE THING IT DOES NOT YET DO, stated here rather than left to be
discovered. The read-only screens -- IDLE, RECEIVE and THIS DEVICE in app.py --
show the PRIMARY wallet's fingerprint and addresses. They are watch-only and
deliberately need no PIN, which is right for every other reason and wrong for
this one: a coercer who says "show me your receive address" is shown the real
wallet, and a duress signature will not match it. Signing is fully covered;
being interrogated about your addresses is not.

Closing it means those screens asking for a PIN before they will show anything,
which trades a real usability property for a threat that only applies under
coercion. It is a decision for whoever builds this, not one to make silently in
a module docstring -- so until it is made, treat the duress PIN as protecting
what you SIGN -- on either chain -- and not what your device DISPLAYS.
VALIDATION.md carries it.

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

    def pack(self) -> bytes:
        """Both blobs in one file, length-prefixed.

        ONE file, not two. Two files on the card is a count an attacker can
        read, and a count is all it takes: a device with one blob has no duress
        PIN and a device with two does. One file of a fixed size says nothing
        either way, which is the same argument as always writing the second
        blob in the first place.
        """
        if len(self.primary) > 0xFFFF:
            raise ValueError("a wrapped seed does not fit its length prefix")
        return (len(self.primary).to_bytes(2, "big") + self.primary
                + self.secondary)

    @classmethod
    def unpack(cls, raw: bytes) -> "SeedPair":
        if len(raw) < 2:
            raise ValueError("seed store is truncated")
        n = int.from_bytes(raw[:2], "big")
        if len(raw) < 2 + n:
            raise ValueError("seed store is truncated")
        return cls(primary=raw[2:2 + n], secondary=raw[2 + n:])


def wrap_pair(mnemonic: str, decoy: str,
              normal_key: bytes, duress_key: bytes) -> SeedPair:
    """Wrap both seeds, each under the key its own PIN derives."""
    if normal_key == duress_key:
        raise ValueError("both PINs derived the same key; they must differ")
    real = seedstore.wrap(mnemonic, normal_key).pack()
    fake = seedstore.wrap(decoy, duress_key).pack()
    # Shuffled, so the real seed is not reliably the first one. unwrap_any
    # tries both regardless, so the order carries no information the device
    # needs -- which is exactly why it should carry none an attacker can use
    # either. Without this, "the first blob is the real wallet" is true of
    # every CELL ever provisioned.
    if os.urandom(1)[0] & 1:
        real, fake = fake, real
    return SeedPair(primary=real, secondary=fake)


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
            # rather than pick, because picking would be silently arbitrary --
            # and wipe both decrypted buffers on the way out, because this is
            # the one exit from this function that used to leave a plaintext
            # seed in a bytearray nobody had a reference to any more.
            for buf in (found, seed):
                for i in range(len(buf)):
                    buf[i] = 0
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
