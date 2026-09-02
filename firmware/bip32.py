"""BIP-32 hierarchical deterministic keys, and the descriptor path handling
the change check depends on.

The important function in this file is not derive() — it is
`ExtendedKey.owns()`, reached through psbt.py. A wallet that cannot prove a
change output belongs to it will happily sign away its own balance while
showing the owner a correct-looking "amount" line, because the difference
went to the attacker as change. That is the single most common way a hardware
wallet loses money without anyone noticing, and defending against it is
arithmetic, not vigilance: rederive the key at the claimed path, rebuild the
script, and compare it to the output byte for byte.

Hardened derivation needs the private key, so a watch-only xpub cannot walk
past a hardened index. That is the property that makes an account xpub safe
to hand a coordinator, and it is why the account level is the hardened floor.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import secp256k1 as ec
from hashes import hash160, sha256d

HARDENED = 0x80000000

# Version bytes. These select the SLIP-132 flavour of an xpub, which changes
# only the four leading bytes and the human-readable prefix — never the keys.
VERSIONS = {
    "xprv": 0x0488ADE4, "xpub": 0x0488B21E,      # mainnet, BIP-44 legacy
    "yprv": 0x049D7878, "ypub": 0x049D7CB2,      # mainnet, BIP-49 p2sh-p2wpkh
    "zprv": 0x04B2430C, "zpub": 0x04B24746,      # mainnet, BIP-84 p2wpkh
    "tprv": 0x04358394, "tpub": 0x043587CF,      # testnet
    "uprv": 0x044A4E28, "upub": 0x044A5262,
    "vprv": 0x045F18BC, "vpub": 0x045F1CF6,
}
_BY_VERSION = {v: k for k, v in VERSIONS.items()}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class BadPath(ValueError):
    """A derivation path that cannot be walked."""


# --------------------------------------------------------------------------
# Base58Check — only used for extended keys and legacy addresses
# --------------------------------------------------------------------------


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256d(payload)[:4])


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5 or sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError("base58 checksum failed")
    return raw[:-4]


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def parse_path(path: str) -> list[int]:
    """"m/84'/0'/0'/0/5" -> [0x80000054, 0x80000000, 0x80000000, 0, 5]."""
    s = path.strip()
    if s in ("", "m", "m/"):
        return []
    parts = s.split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    out = []
    for p in parts:
        if not p:
            raise BadPath(f"empty element in path {path!r}")
        hard = p[-1] in ("'", "h", "H")
        num = p[:-1] if hard else p
        # ASCII digits only. `str.isdigit` is true for Arabic-Indic digits and
        # for superscripts, so "m/\u0663" parsed as index 3 -- a path string
        # that renders as something other than the index it derives -- and
        # "m/\u00b2" escaped as a bare ValueError from int(), past every caller
        # that catches BadPath.
        if not (num.isascii() and num.isdigit()):
            raise BadPath(f"bad path element {p!r} in {path!r}")
        i = int(num)
        if i >= HARDENED:
            raise BadPath(f"index {i} out of range in {path!r}")
        out.append(i + HARDENED if hard else i)
    return out


def format_path(path: list[int]) -> str:
    return "m" + "".join(f"/{i - HARDENED}h" if i >= HARDENED else f"/{i}"
                         for i in path)


# --------------------------------------------------------------------------
# Extended keys
# --------------------------------------------------------------------------


@dataclass
class ExtendedKey:
    """A BIP-32 node. `seckey` is None for a watch-only (public) node."""

    chain_code: bytes
    pubkey: bytes                       # 33, compressed — always present
    seckey: bytes | None = None
    depth: int = 0
    parent_fp: bytes = b"\x00\x00\x00\x00"
    index: int = 0

    # ---- construction ----

    @staticmethod
    def from_seed(seed: bytes) -> "ExtendedKey":
        if not 16 <= len(seed) <= 64:
            raise ValueError("seed must be 16-64 bytes")
        h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        sk = h[:32]
        ec.seckey_int(sk)               # refuses the astronomically unlikely bad seed
        return ExtendedKey(chain_code=h[32:], seckey=sk,
                           pubkey=ec.pubkey_compressed(sk))

    @staticmethod
    def deserialize(s: str) -> "ExtendedKey":
        raw = b58check_decode(s)
        if len(raw) != 78:
            raise ValueError(f"extended key is {len(raw)} bytes, expected 78")
        ver = int.from_bytes(raw[:4], "big")
        if ver not in _BY_VERSION:
            raise ValueError(f"unknown extended key version {ver:#010x}")
        depth, fp, idx = raw[4], raw[5:9], int.from_bytes(raw[9:13], "big")
        cc, key = raw[13:45], raw[45:78]
        # The version bytes and the payload must agree about which half this
        # is. Reading the type off the payload alone -- "leading zero, so it
        # is private" -- accepts both of BIP-32 vector 5's mismatch cases: an
        # `xpub` string carrying a private key, and an `xprv` carrying only a
        # public one. The first is the dangerous direction. Account records on
        # this device are public by design, kept in the clear and backed up in
        # the clear, and everything downstream asks `seckey is None` to decide
        # whether a record is watch-only -- so a string that says xpub while
        # holding a secret is a record whose own prefix lies about what it is.
        private = _BY_VERSION[ver].endswith("prv")
        if private != (key[0] == 0):
            raise ValueError(
                f"{_BY_VERSION[ver]} version byte carries a "
                f"{'public' if private else 'private'} key. The prefix and the "
                f"payload disagree about what this is (BIP-32 test vector 5).")
        # BIP-32: a master key has no parent and no index, so a depth of zero
        # with either set is a key that cannot be what it says it is.
        if depth == 0 and (fp != b"\x00\x00\x00\x00" or idx != 0):
            raise ValueError(
                "depth-0 extended key with a non-zero parent fingerprint or "
                "index; a master key has neither")
        if private:
            sk = key[1:]
            ec.seckey_int(sk)
            return ExtendedKey(cc, ec.pubkey_compressed(sk), sk, depth, fp, idx)
        ec.parse_pubkey(key)            # rejects an off-curve xpub
        return ExtendedKey(cc, key, None, depth, fp, idx)

    def serialize(self, prefix: str = "xpub") -> str:
        want_private = prefix.endswith("prv")
        if want_private and self.seckey is None:
            raise ValueError("cannot serialise a private key from a watch-only node")
        if prefix not in VERSIONS:
            raise ValueError(f"unknown prefix {prefix!r}")
        key = b"\x00" + self.seckey if want_private else self.pubkey
        return b58check_encode(
            VERSIONS[prefix].to_bytes(4, "big") + bytes([self.depth])
            + self.parent_fp + self.index.to_bytes(4, "big") + self.chain_code + key)

    # ---- identity ----

    def fingerprint(self) -> bytes:
        return hash160(self.pubkey)[:4]

    def neutered(self) -> "ExtendedKey":
        return ExtendedKey(self.chain_code, self.pubkey, None,
                           self.depth, self.parent_fp, self.index)

    # ---- derivation ----

    def child(self, index: int) -> "ExtendedKey":
        if not 0 <= index < 2**32:
            raise BadPath(f"index {index} out of range")
        # Depth is one byte on the wire. Without a ceiling, the 256th child of
        # a master is a perfectly usable key object that serialize() then
        # refuses with a bare "bytes must be in range(0, 256)" -- a key that
        # signs and cannot be exported.
        if self.depth >= 255:
            raise BadPath(
                "BIP-32 depth is a single byte; this node is already at 255 "
                "and a deeper key could not be serialised")
        hardened = index >= HARDENED
        if hardened and self.seckey is None:
            raise BadPath(
                f"cannot derive hardened index {index - HARDENED}h from a "
                f"public key. This is the property that makes an account xpub "
                f"safe to publish.")
        # BIP-32 §2: if the tweak is >= n, or the resulting key is zero, the
        # index is INVALID and derivation proceeds with the next one. Both
        # conditions have probability about 2^-128, so this loop runs once in
        # every life that will ever be lived -- but a seed that does hit it is
        # restorable on any wallet that follows the spec, and used to be
        # permanently stuck on this one. The skip stays inside the same
        # domain: a hardened index yields the next hardened index.
        limit = 2**32 if hardened else HARDENED
        while True:
            data = ((b"\x00" + self.seckey) if hardened else self.pubkey) \
                + index.to_bytes(4, "big")
            h = hmac.new(self.chain_code, data, hashlib.sha512).digest()
            tweak, cc = h[:32], h[32:]
            try:
                if int.from_bytes(tweak, "big") >= ec.N:
                    raise ec.BadKey("derived tweak >= N")
                if self.seckey is not None:
                    sk = ec.tweak_seckey_add(self.seckey, tweak)
                    pub = ec.pubkey_compressed(sk)
                else:
                    sk, pub = None, ec.tweak_pubkey_add(self.pubkey, tweak)
            except ec.BadKey:
                index += 1
                if index >= limit:
                    raise BadPath(
                        "no valid child index remains in this range "
                        "(BIP-32 §2)") from None
                continue
            return ExtendedKey(cc, pub, sk, self.depth + 1,
                               self.fingerprint(), index)

    def derive(self, path: str | list[int]) -> "ExtendedKey":
        node = self
        for i in (parse_path(path) if isinstance(path, str) else path):
            node = node.child(i)
        return node

    # ---- what psbt.py actually calls ----

    def owns(self, pubkey: bytes, path: list[int]) -> bool:
        """Does deriving `path` from this node really produce `pubkey`?

        The host asserts a path for every key in a PSBT. This is the check
        that turns that assertion into a fact. A host that lies about a change
        output's path fails here, which is the whole defence.
        """
        try:
            return hmac.compare_digest(self.derive(path).pubkey, pubkey)
        except (BadPath, ValueError):
            return False


def from_mnemonic(mnemonic: str, passphrase: str = "") -> ExtendedKey:
    import bip39
    return ExtendedKey.from_seed(bip39.to_seed(mnemonic, passphrase))


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("BIP-32 — official vectors, hardened isolation, path parsing\n")
    checks = []

    # BIP-32 test vector 1.
    m = ExtendedKey.from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    v1 = [
        ("m",
         "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
         "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
         "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES"
         "FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
        ("m/0h",
         "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL"
         "5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
         "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwB"
         "ZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
        ("m/0h/1",
         "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw"
         "1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
         "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWb"
         "WMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
    ]
    for path, want_prv, want_pub in v1:
        node = m.derive(path)
        checks.append((f"vector 1 {path} xprv", node.serialize("xprv") == want_prv))
        checks.append((f"vector 1 {path} xpub", node.serialize("xpub") == want_pub))

    # BIP-32 test vector 2, first two levels — a different seed length.
    m2 = ExtendedKey.from_seed(bytes.fromhex(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c99"
        "9693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
    checks.append(("vector 2 m xpub", m2.serialize("xpub") ==
                   "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUap"
                   "SCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"))

    # Vector 5 — invalid keys must be refused, not coerced.
    #
    # The two version/payload mismatches are BUILT from a valid key rather than
    # quoted as strings. A transcribed vector that is one character short fails
    # its base58 checksum, so the case passes for the wrong reason and the
    # check it is named after is never run — which is exactly what happened
    # here: `deserialize` took the key type from the payload's leading byte and
    # accepted an xpub carrying a secret.
    _raw_prv = b58check_decode(m.serialize("xprv"))
    _raw_pub = b58check_decode(m.serialize("xpub"))
    _swap = lambda pfx, raw: b58check_encode(
        VERSIONS[pfx].to_bytes(4, "big") + raw[4:])
    for label, bad in [
        ("xpub version over a private key", _swap("xpub", _raw_prv)),
        ("xprv version over a public key", _swap("xprv", _raw_pub)),
        ("depth 0 with a parent fingerprint",
         b58check_encode(_raw_pub[:5] + b"\x01\x02\x03\x04" + _raw_pub[9:])),
        ("depth 0 with a non-zero index",
         b58check_encode(_raw_pub[:9] + b"\x00\x00\x00\x01" + _raw_pub[13:])),
        ("truncated base58", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD"),
    ]:
        try:
            ExtendedKey.deserialize(bad)
            checks.append((label + " refused", False))
        except ValueError:
            checks.append((label + " refused", True))

    # Serialisation round trip, including the SLIP-132 flavours.
    node = m.derive("m/84h/0h/0h")
    for pfx in ("xpub", "ypub", "zpub"):
        checks.append((f"{pfx} round trip",
                       ExtendedKey.deserialize(node.serialize(pfx)).pubkey == node.pubkey))
    checks.append(("xprv round trip",
                   ExtendedKey.deserialize(node.serialize("xprv")).seckey == node.seckey))

    # Public derivation must agree with private derivation on unhardened paths.
    # If it does not, a coordinator's xpub and the device disagree about which
    # addresses are the owner's — which is the change-verification bug.
    acct = m.derive("m/84h/0h/0h")
    watch = ExtendedKey.deserialize(acct.serialize("xpub"))
    agree = all(watch.derive([0, i]).pubkey == acct.derive([0, i]).pubkey
                for i in range(6))
    checks.append(("public derivation matches private", agree))
    checks.append(("watch-only node has no secret", watch.seckey is None))

    # Hardened derivation from a public node must be impossible.
    try:
        watch.child(HARDENED)
        checks.append(("hardened from xpub refused", False))
    except BadPath:
        checks.append(("hardened from xpub refused", True))

    # Fingerprints and depth, which a PSBT's key origins are matched on.
    checks.append(("depth counts", m.derive("m/84h/0h/0h/0/0").depth == 5))
    checks.append(("parent fingerprint links",
                   acct.child(0).parent_fp == acct.fingerprint()))
    checks.append(("master fingerprint is of the master key",
                   m.fingerprint() == hash160(m.pubkey)[:4]))

    # owns() — the change check.
    ck = acct.derive([1, 7])
    checks.append(("owns() accepts the true path", acct.owns(ck.pubkey, [1, 7])))
    checks.append(("owns() rejects a wrong path", not acct.owns(ck.pubkey, [1, 8])))
    checks.append(("owns() rejects a foreign key",
                   not acct.owns(ec.pubkey_compressed(hashlib.sha256(b"thief").digest()),
                                 [1, 7])))
    checks.append(("owns() rejects a hardened path on a watch-only node",
                   not watch.owns(ck.pubkey, [HARDENED])))
    checks.append(("owns() rejects garbage rather than raising",
                   not acct.owns(b"\x02" + b"\xff" * 32, [0, 0])))

    def _raises_badpath(fn) -> bool:
        try:
            fn()
        except BadPath:
            return True
        return False

    # Path parsing.
    checks.append(("parses apostrophe and h",
                   parse_path("m/84'/0h/0H/1/9") == [HARDENED + 84, HARDENED,
                                                     HARDENED, 1, 9]))
    checks.append(("parses the empty path", parse_path("m") == []))
    checks.append(("formats back", format_path(parse_path("m/84h/0h/0h/0/5"))
                   == "m/84h/0h/0h/0/5"))
    # An index whose child key is invalid is skipped, not refused: BIP-32 §2
    # says proceed with the next i, and a seed that hits it (about 2^-128)
    # would otherwise be restorable everywhere except here. The condition
    # cannot be reached with real inputs, so it is forced.
    real_tweak = ec.tweak_seckey_add
    calls = {"n": 0}

    def _first_is_invalid(sk, tweak):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ec.BadKey("forced: derived tweak >= N")
        return real_tweak(sk, tweak)

    ec.tweak_seckey_add = _first_is_invalid
    try:
        skipped = acct.child(7)
    finally:
        ec.tweak_seckey_add = real_tweak
    checks.append(("an invalid child index moves to the next one, not an error",
                   skipped.index == 8 and skipped.pubkey == acct.child(8).pubkey))
    checks.append(("depth stops at the byte the format gives it",
                   _raises_badpath(lambda: ExtendedKey(
                       acct.chain_code, acct.pubkey, acct.seckey,
                       255, acct.parent_fp, 0).child(0))))

    for bad in ("m/84x", "m//0", "m/-1", "m/2147483648"):
        try:
            parse_path(bad)
            checks.append((f"rejects path {bad!r}", False))
        except BadPath:
            checks.append((f"rejects path {bad!r}", True))

    # Base58Check must reject a mutated string rather than decoding it.
    good = m.serialize("xpub")
    bad = good[:-2] + ("11" if good[-2:] != "11" else "22")
    try:
        ExtendedKey.deserialize(bad)
        checks.append(("base58 checksum enforced", False))
    except ValueError:
        checks.append(("base58 checksum enforced", True))

    ok = True
    for label, good_ in checks:
        ok &= good_
        print(f"  {label:<52}{'PASS' if good_ else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
