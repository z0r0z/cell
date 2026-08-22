"""Addresses and scriptPubKeys, for both chains.

This module exists so the device can answer one question in bytes rather than
in trust: *given a key I derived myself, what would the output script look
like?* Every change check in psbt.py is that comparison. Rendering an address
for the display is the secondary job.

Bech32 and bech32m are not interchangeable. BIP-350 changed the checksum
constant for witness version 1 and above after a flaw was found in the
original; a taproot address encoded with the v0 constant is a valid-looking
string that no node will accept, and funds sent to it are gone. So the
constant is selected by witness version, and the decoder refuses a mismatch.

Ethereum's EIP-55 checksum is carried in the capitalisation of the hex. We
display it and we verify it, because a mistyped address with no checksum is
an irreversible transfer to nobody.
"""

from __future__ import annotations

import hashlib

import secp256k1 as ec
from bip32 import b58check_decode, b58check_encode
from hashes import hash160, keccak256

BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Mainnet. Testnet values are here so a build for testing cannot silently
# produce mainnet addresses by falling back to a default.
NETWORKS = {
    "mainnet": {"hrp": "bc", "p2pkh": 0x00, "p2sh": 0x05},
    "testnet": {"hrp": "tb", "p2pkh": 0x6F, "p2sh": 0xC4},
    "regtest": {"hrp": "bcrt", "p2pkh": 0x6F, "p2sh": 0xC4},
}


class BadAddress(ValueError):
    """An address that does not decode, or does not check out."""


# --------------------------------------------------------------------------
# Bech32 / bech32m (BIP-173, BIP-350)
# --------------------------------------------------------------------------


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """BIP-173 for v0, BIP-350 for v1+. The constant follows the version."""
    data = [witver] + _convertbits(list(witprog), 8, 5)
    const = BECH32_CONST if witver == 0 else BECH32M_CONST
    chk = _polymod(_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def bech32_decode(addr: str) -> tuple[str, int, bytes]:
    """Returns (hrp, witness version, program). Raises on any irregularity."""
    if len(addr) > 90:
        raise BadAddress("bech32 address too long")
    if addr.lower() != addr and addr.upper() != addr:
        raise BadAddress("bech32 address mixes case")
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a):
        raise BadAddress("bech32 separator misplaced")
    hrp, body = a[:pos], a[pos + 1:]
    if any(c not in CHARSET for c in body):
        raise BadAddress("bech32 body has a character outside the charset")
    data = [CHARSET.index(c) for c in body]
    const = _polymod(_hrp_expand(hrp) + data)
    witver = data[0]
    want = BECH32_CONST if witver == 0 else BECH32M_CONST
    if const != want:
        # The specific failure BIP-350 exists to prevent.
        other = BECH32M_CONST if witver == 0 else BECH32_CONST
        hint = (" — checksum is the wrong variant for witness version "
                f"{witver}" if const == other else "")
        raise BadAddress(f"bech32 checksum failed{hint}")
    prog = _convertbits(data[1:-6], 5, 8, False)
    if prog is None:
        raise BadAddress("bech32 payload is not a whole number of bytes")
    prog = bytes(prog)
    if witver > 16:
        raise BadAddress(f"witness version {witver} out of range")
    if not 2 <= len(prog) <= 40:
        raise BadAddress(f"witness program is {len(prog)} bytes")
    if witver == 0 and len(prog) not in (20, 32):
        raise BadAddress("witness v0 program must be 20 or 32 bytes")
    return hrp, witver, prog


# --------------------------------------------------------------------------
# scriptPubKeys — what a change output is actually compared against
# --------------------------------------------------------------------------


def p2pkh_script(pubkey: bytes) -> bytes:
    return b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"


def p2wpkh_script(pubkey: bytes) -> bytes:
    return b"\x00\x14" + hash160(pubkey)


def p2wsh_script(witness_script: bytes) -> bytes:
    return b"\x00\x20" + hashlib.sha256(witness_script).digest()


def p2sh_script(redeem_script: bytes) -> bytes:
    return b"\xa9\x14" + hash160(redeem_script) + b"\x87"


def p2sh_p2wpkh_script(pubkey: bytes) -> bytes:
    """BIP-49: a p2sh wrapper whose redeem script is the v0 witness program."""
    return p2sh_script(p2wpkh_script(pubkey))


def p2tr_script(output_xonly: bytes) -> bytes:
    if len(output_xonly) != 32:
        raise BadAddress("taproot output key must be 32 bytes")
    return b"\x51\x20" + output_xonly


def multisig_script(m: int, pubkeys: list[bytes]) -> bytes:
    """Bare m-of-n CHECKMULTISIG, the witness script inside a p2wsh.

    Key order is consensus-relevant: it is part of the script, so the same
    keys in a different order are a different address. Callers must pass them
    already in the order the descriptor specifies (BIP-67 sorts them, and a
    sorted descriptor says so). We do not sort here, because silently
    reordering would change which address the device thinks it owns.
    """
    n = len(pubkeys)
    if not 1 <= m <= n <= 16:
        raise BadAddress(f"{m}-of-{n} is not a valid multisig")
    out = bytes([0x50 + m])
    for pk in pubkeys:
        if len(pk) != 33:
            raise BadAddress("multisig requires compressed pubkeys")
        out += bytes([33]) + pk
    return out + bytes([0x50 + n]) + b"\xae"


def script_to_address(script: bytes, network: str = "mainnet") -> str:
    """Render a scriptPubKey for the display, or raise if we cannot."""
    net = NETWORKS.get(network)
    if net is None:
        raise BadAddress(f"unknown network {network!r}")
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return b58check_encode(bytes([net["p2pkh"]]) + script[3:23])
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[22:] == b"\x87":
        return b58check_encode(bytes([net["p2sh"]]) + script[2:22])
    if len(script) in (22, 34) and script[0] == 0x00 and script[1] == len(script) - 2:
        return bech32_encode(net["hrp"], 0, script[2:])
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        return bech32_encode(net["hrp"], 1, script[2:])
    if 4 <= len(script) <= 42 and script[0] in range(0x52, 0x61) \
            and script[1] == len(script) - 2:
        return bech32_encode(net["hrp"], script[0] - 0x50, script[2:])
    if script[:1] == b"\x6a":
        raise BadAddress("OP_RETURN output has no address")
    raise BadAddress(f"unrecognised script, {len(script)} bytes")


def address_to_script(addr: str, network: str = "mainnet") -> bytes:
    """The inverse. Used to check a destination the owner typed or scanned."""
    net = NETWORKS.get(network)
    if net is None:
        raise BadAddress(f"unknown network {network!r}")
    # Any known human-readable prefix goes down the bech32 path, including one
    # belonging to a different network. Falling through to base58 instead would
    # report "invalid base58 character" for a testnet address, which sends the
    # owner looking for the wrong problem.
    lowered = addr.lower()
    if any(lowered.startswith(n["hrp"] + "1") for n in NETWORKS.values()):
        hrp, witver, prog = bech32_decode(addr)
        if hrp != net["hrp"]:
            raise BadAddress(f"address is for {hrp!r}, this device is on {network}")
        return bytes([witver + 0x50 if witver else 0, len(prog)]) + prog
    try:
        raw = b58check_decode(addr)
    except ValueError as e:
        raise BadAddress(f"not a valid address: {e}") from None
    if len(raw) != 21:
        raise BadAddress("base58 address payload is not 21 bytes")
    if raw[0] == net["p2pkh"]:
        return b"\x76\xa9\x14" + raw[1:] + b"\x88\xac"
    if raw[0] == net["p2sh"]:
        return b"\xa9\x14" + raw[1:] + b"\x87"
    raise BadAddress(f"address version byte {raw[0]:#04x} is not valid on {network}")


# --------------------------------------------------------------------------
# Ethereum
# --------------------------------------------------------------------------


def eth_address(pubkey: bytes) -> str:
    """EIP-55 checksummed address from a public key."""
    point = ec.parse_pubkey(pubkey)
    raw = keccak256(ec.ser_uncompressed(point)[1:])[-20:]
    return to_checksum_address(raw.hex())


def to_checksum_address(addr: str) -> str:
    """Apply EIP-55 capitalisation."""
    a = addr.lower().removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdef" for c in a):
        raise BadAddress(f"not a 20-byte hex address: {addr!r}")
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c
                          for i, c in enumerate(a))


def valid_checksum_address(addr: str) -> bool:
    """True if `addr` is all one case (no checksum claimed) or checksums."""
    a = addr.removeprefix("0x")
    if len(a) != 40:
        return False
    try:
        if a == a.lower() or a == a.upper():
            return all(c in "0123456789abcdefABCDEF" for c in a)
        return to_checksum_address(a) == "0x" + a
    except BadAddress:
        return False


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Addresses — BIP-173/350 vectors, scripts, EIP-55\n")
    checks = []

    # BIP-173 / BIP-350 valid address vectors.
    valid = [
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
         "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
         "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5"
         "xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8"
                        "199196d454941c45d1b3a323f1433bd6"),
        ("BC1SW50QGDZ25J", "6002751e"),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
    ]
    for addr, spk in valid:
        try:
            got = address_to_script(addr).hex()
        except BadAddress as e:                                 # noqa: BLE001
            got = f"raised {e}"
        checks.append((f"decodes {addr[:22]}…", got == spk))

    # BIP-350 invalid vectors — the ones that matter are the wrong-variant
    # checksums, because those are what silently burn taproot funds.
    invalid = [
        ("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
         "v1 with bech32 checksum"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "v0 with bech32m checksum"),
        ("bc1rw5uspcuh", "v1 program too short"),
        ("bc1gmk9yu", "empty data"),
        ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
         "mixed case"),
        ("bc1q9zpgru", "invalid checksum"),
    ]
    for addr, why in invalid:
        try:
            address_to_script(addr)
            checks.append((f"refuses {why}", False))
        except (BadAddress, ValueError):
            checks.append((f"refuses {why}", True))

    # Round trip every script type this device can own.
    sk = hashlib.sha256(b"addr-test").digest()
    pub = ec.pubkey_compressed(sk)
    xonly, _ = ec.taproot_tweak_pubkey(ec.schnorr_pubkey(sk))
    scripts = {
        "p2pkh": p2pkh_script(pub),
        "p2sh-p2wpkh": p2sh_p2wpkh_script(pub),
        "p2wpkh": p2wpkh_script(pub),
        "p2wsh": p2wsh_script(multisig_script(2, [pub, ec.pubkey_compressed(
            hashlib.sha256(b"co-signer").digest())])),
        "p2tr": p2tr_script(xonly),
    }
    for name, spk in scripts.items():
        a = script_to_address(spk)
        checks.append((f"{name} address round trip", address_to_script(a) == spk))

    checks.append(("p2wpkh renders as bc1q", scripts["p2wpkh"].hex()[:4] == "0014"
                   and script_to_address(scripts["p2wpkh"]).startswith("bc1q")))
    checks.append(("p2tr renders as bc1p",
                   script_to_address(scripts["p2tr"]).startswith("bc1p")))
    checks.append(("p2pkh renders as 1",
                   script_to_address(scripts["p2pkh"]).startswith("1")))
    checks.append(("p2sh renders as 3",
                   script_to_address(scripts["p2sh-p2wpkh"]).startswith("3")))

    # Networks must not bleed into each other.
    tb = script_to_address(scripts["p2wpkh"], "testnet")
    checks.append(("testnet renders tb1", tb.startswith("tb1")))
    try:
        address_to_script(tb, "mainnet")
        checks.append(("mainnet refuses a testnet address", False))
    except BadAddress:
        checks.append(("mainnet refuses a testnet address", True))

    # A one-character mutation must not decode.
    a = script_to_address(scripts["p2wpkh"])
    mutated = a[:-1] + ("q" if a[-1] != "q" else "p")
    try:
        address_to_script(mutated)
        checks.append(("single-character mutation caught", False))
    except BadAddress:
        checks.append(("single-character mutation caught", True))

    # OP_RETURN has no address and must say so rather than inventing one.
    try:
        script_to_address(b"\x6a\x04test")
        checks.append(("OP_RETURN has no address", False))
    except BadAddress:
        checks.append(("OP_RETURN has no address", True))

    # Multisig script shape, and that order is preserved.
    a_pub, b_pub = pub, ec.pubkey_compressed(hashlib.sha256(b"b").digest())
    checks.append(("2-of-2 script shape",
                   multisig_script(2, [a_pub, b_pub])[0] == 0x52
                   and multisig_script(2, [a_pub, b_pub])[-1] == 0xAE))
    checks.append(("multisig key order is preserved",
                   multisig_script(2, [a_pub, b_pub]) != multisig_script(2, [b_pub, a_pub])))

    # EIP-55 vectors from the EIP itself.
    for a in ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
              "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
              "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
              "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"]:
        checks.append((f"EIP-55 {a[:10]}…", to_checksum_address(a.lower()) == a))
        checks.append((f"EIP-55 validates {a[:10]}…", valid_checksum_address(a)))

    checks.append(("EIP-55 rejects a flipped case",
                   not valid_checksum_address(
                       "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed")))
    checks.append(("all-lowercase accepted (no checksum claimed)",
                   valid_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")))

    # An Ethereum address derived from a known key. secp256k1's own selftest
    # pins the key arithmetic; this pins the keccak-and-truncate step.
    known_sk = bytes.fromhex(
        "4646464646464646464646464646464646464646464646464646464646464646")
    checks.append(("eth address from a known key",
                   eth_address(ec.pubkey_compressed(known_sk))
                   == "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
