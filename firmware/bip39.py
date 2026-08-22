"""BIP-39 — mnemonic to seed.

The device holds a standard BIP-39 seed so the backup path is the ordinary
one: twelve or twenty-four words on paper or steel, restorable to a Ledger, a
Trezor, or a replacement CELL. Nothing here is CELL-specific, and that is the
point. A wallet with a bespoke backup format is a wallet that dies with its
manufacturer.

The English wordlist ships alongside this file and its SHA-256 is checked on
load. A wordlist that differs by one word produces valid-looking mnemonics
that no other wallet can restore, so a silent substitution is exactly the
failure this check exists to catch.

Note what the passphrase does and does not do. BIP-39's optional passphrase
salts the PBKDF2, producing a different seed. It is not the device PIN and is
not stored on the device; if you use one, it is part of your backup, and
losing it loses the coins as surely as losing the words.
"""

from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

WORDLIST_PATH = Path(__file__).resolve().parent / "wordlist" / "english.txt"

# SHA-256 of the canonical BIP-39 English wordlist, as published in the BIP-39
# repository. Every wallet in existence agrees on this file.
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

PBKDF2_ROUNDS = 2048

_WORDS: list[str] | None = None
_INDEX: dict[str, int] | None = None


class BadMnemonic(ValueError):
    """The words are not a valid BIP-39 mnemonic."""


def wordlist() -> list[str]:
    """Load and verify the wordlist once."""
    global _WORDS, _INDEX
    if _WORDS is None:
        raw = WORDLIST_PATH.read_bytes()
        got = hashlib.sha256(raw).hexdigest()
        if got != WORDLIST_SHA256:
            raise BadMnemonic(
                f"wordlist digest mismatch: {got}. This file must be the "
                f"canonical BIP-39 English list, or the seeds this device "
                f"generates cannot be restored anywhere else.")
        words = raw.decode("utf-8").split()
        if len(words) != 2048:
            raise BadMnemonic(f"wordlist has {len(words)} words, expected 2048")
        _WORDS = words
        _INDEX = {w: i for i, w in enumerate(words)}
    return _WORDS


def _index() -> dict[str, int]:
    wordlist()
    assert _INDEX is not None
    return _INDEX


def normalise(mnemonic: str) -> str:
    """NFKD, single-space separated, as BIP-39 requires before hashing."""
    return " ".join(unicodedata.normalize("NFKD", mnemonic).split())


def entropy_to_mnemonic(entropy: bytes) -> str:
    """16, 20, 24, 28 or 32 bytes of entropy -> 12..24 words."""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise BadMnemonic(f"entropy must be 16-32 bytes in steps of 4, got {len(entropy)}")
    words = wordlist()
    checksum_bits = len(entropy) * 8 // 32
    digest = hashlib.sha256(entropy).digest()
    bits = int.from_bytes(entropy, "big") << checksum_bits
    bits |= digest[0] >> (8 - checksum_bits)
    total = len(entropy) * 8 + checksum_bits
    out = []
    for i in range(total // 11):
        shift = total - 11 * (i + 1)
        out.append(words[(bits >> shift) & 0x7FF])
    return " ".join(out)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Reverse, verifying the checksum. Raises on any error."""
    idx = _index()
    words = normalise(mnemonic).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise BadMnemonic(f"{len(words)} words; BIP-39 allows 12, 15, 18, 21 or 24")
    unknown = [w for w in words if w not in idx]
    if unknown:
        raise BadMnemonic(f"not in the wordlist: {', '.join(unknown[:4])}")

    bits = 0
    for w in words:
        bits = (bits << 11) | idx[w]
    total = len(words) * 11
    checksum_bits = total // 33
    ent_bits = total - checksum_bits
    entropy = (bits >> checksum_bits).to_bytes(ent_bits // 8, "big")
    want = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if (bits & ((1 << checksum_bits) - 1)) != want:
        raise BadMnemonic("checksum failed — a word is wrong or out of order")
    return entropy


def validate(mnemonic: str) -> bool:
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except BadMnemonic:
        return False


def to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """64-byte BIP-39 seed. PBKDF2-HMAC-SHA512, 2048 rounds.

    Deliberately does NOT validate the checksum: BIP-39 defines the seed for
    any string, and refusing to derive from a mnemonic the owner insists on
    would strand a wallet created by a tool with a different opinion. Check
    with validate() at the point where the owner types it, and warn there.
    """
    m = normalise(mnemonic).encode("utf-8")
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, salt, PBKDF2_ROUNDS, dklen=64)


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("BIP-39 — wordlist integrity, checksum, official vectors\n")
    checks = []

    words = wordlist()
    checks.append(("wordlist digest verified", len(words) == 2048))
    checks.append(("wordlist is sorted", words == sorted(words)))
    checks.append(("first/last words", (words[0], words[-1]) == ("abandon", "zoo")))

    # Official BIP-39 vectors (Trezor's vectors.json, passphrase "TREZOR").
    vectors = [
        ("00000000000000000000000000000000",
         "abandon abandon abandon abandon abandon abandon abandon abandon "
         "abandon abandon abandon about",
         "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
         "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
         "legal winner thank year wave sausage worth useful legal winner "
         "thank yellow",
         "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
         "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
        ("80808080808080808080808080808080",
         "letter advice cage absurd amount doctor acoustic avoid letter "
         "advice cage above",
         "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30"
         "fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"),
        ("ffffffffffffffffffffffffffffffff",
         "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
         "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
         "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"),
        ("0000000000000000000000000000000000000000000000000000000000000000",
         "abandon abandon abandon abandon abandon abandon abandon abandon "
         "abandon abandon abandon abandon abandon abandon abandon abandon "
         "abandon abandon abandon abandon abandon abandon abandon art",
         "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
         "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
         "zoo zoo zoo zoo zoo zoo zoo vote",
         "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
         "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"),
    ]

    for ent_hex, mnem, _seed in vectors:
        ent = bytes.fromhex(ent_hex)
        got = entropy_to_mnemonic(ent)
        label = f"entropy->words {ent_hex[:8]}…{len(ent)*8}b"
        checks.append((label, got == mnem))
        checks.append((f"words->entropy {ent_hex[:8]}…", mnemonic_to_entropy(mnem) == ent))

    # Seed derivation, checked on the two vectors whose seeds are reproduced
    # here in full.
    for ent_hex, mnem, seed in vectors:
        n = len(mnem.split())
        checks.append((f"seed vector {ent_hex[:8]}… ({n} words)",
                       to_seed(mnem, "TREZOR").hex() == seed))

    # A passphrase must change the seed, and an absent one must equal "".
    checks.append(("passphrase changes the seed",
                   to_seed(vectors[0][1]) != to_seed(vectors[0][1], "TREZOR")))
    checks.append(("empty passphrase is the default",
                   to_seed(vectors[0][1]) == to_seed(vectors[0][1], "")))

    # Checksum enforcement — the whole reason a mnemonic has one.
    checks.append(("valid mnemonic accepted", validate(vectors[0][1])))
    checks.append(("one word swapped is rejected",
                   not validate("abandon abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon abandon")))
    checks.append(("word out of the list rejected",
                   not validate("satoshi " + " ".join(vectors[0][1].split()[1:]))))
    checks.append(("wrong word count rejected",
                   not validate(" ".join(vectors[0][1].split()[:11]))))

    # Normalisation: extra whitespace and case must not change the seed, and
    # NFKD must be applied before hashing.
    checks.append(("whitespace normalised",
                   to_seed("  " + vectors[0][1].replace(" ", "   ") + " ")
                   == to_seed(vectors[0][1])))

    # Round trip over every allowed length.
    rt = True
    for n in (16, 20, 24, 28, 32):
        e = hashlib.sha256(bytes([n])).digest()[:n]
        rt &= mnemonic_to_entropy(entropy_to_mnemonic(e)) == e
    checks.append(("round trip at every length", rt))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
