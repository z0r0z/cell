#!/usr/bin/env python3
"""Generate registry test vectors from the real firmware attestation code.

The digest a device signs for CellRegistry.redeem commits to the chain, the
contract and the claimant, so the vectors can only be produced once the
deployment address is known. The test deploys from a fixed address at nonce 0
and asserts the address matches, so the two cannot drift.

keccak and ABI encoding come from `cast`, since hashlib has no keccak256 and
sha3_256 is a different padding.

    python3 contracts/test/gen_registry_vectors.py
"""
import hashlib, json, pathlib, subprocess, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "firmware"))
import attest
import beacon as beacon_mod
from policy import Tier

DEPLOYER = "0x00000000000000000000000000000000000000D1"
USER     = "0x00000000000000000000000000000000000000A1"
OTHER    = "0x00000000000000000000000000000000000000A2"
CHAINID  = 31337                      # foundry default


def cast(*args: str) -> str:
    return subprocess.run(["cast", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def registry_address() -> str:
    out = cast("compute-address", DEPLOYER, "--nonce", "0")
    return out.split()[-1]


def action_digest(reg: str, claimant: str, purpose: str) -> bytes:
    enc = cast("abi-encode", "f(uint256,address,address,bytes32)",
               str(CHAINID), reg, claimant, purpose)
    return bytes.fromhex(cast("keccak", enc)[2:])


def redeem_purpose(purpose: str) -> str:
    """CellRegistry.redeemPurpose, through `cast`, cross-checked against beacon.py.

    An allowlist purpose is chosen by whoever calls redeem(), so it has to be
    tagged or a caller can simply spell a beacon purpose and redeem a proof of
    life as an allowlist entry.
    """
    enc = cast("abi-encode", "f(bytes32,bytes32)",
               "0x" + beacon_mod.REDEEM_TAG.hex(), purpose)
    out = cast("keccak", enc)
    assert out == "0x" + beacon_mod.redeem_purpose(
        bytes.fromhex(purpose[2:])).hex(), "redeemPurpose disagrees with cast"
    return out


def main() -> int:
    reg = registry_address()
    purpose = "0x" + hashlib.sha256(b"cell-allowlist-round-1").hexdigest()

    sk = bytes.fromhex("00" * 31 + "03")
    pk = attest.schnorr_pubkey(sk)
    fw = hashlib.sha256(b"cell-fw-evm-test").digest()
    cal = hashlib.sha256(b"cal-v1").digest()
    live = hashlib.sha256(b"gate-measurements").digest()
    sign = lambda m: attest.schnorr_sign(m, sk)

    tagged = redeem_purpose(purpose)
    d_user = action_digest(reg, USER, tagged)
    d_other = action_digest(reg, OTHER, tagged)

    def rec(tier, counter, digest):
        a = attest.attest(tier, counter, digest, fw, cal, live, sign, pk)
        # Every vector is checked by the Python verifier first. A Solidity test
        # passing against a record the firmware itself rejects proves nothing.
        v = attest.verify(a, pk, digest, counter - 1, [fw], require=tier,
                          allowed_cal=[cal])
        assert v.ok, v.reason
        return "0x" + a.pack().hex()

    # Proof of life. The digest is the same actionDigest, with a purpose word
    # carrying the period index -- firmware/beacon.py builds it, and its ABI
    # encoding is checked against `cast` in test_beacon.py.
    EPOCH = 700
    b = beacon_mod.Beacon(registry=reg, claimant=USER, chain_id=CHAINID,
                          chain_name="foundry", epoch=EPOCH)
    d_beacon = b.digest()
    d_beacon_next = beacon_mod.Beacon(
        registry=reg, claimant=USER, chain_id=CHAINID, chain_name="foundry",
        epoch=EPOCH + 1).digest()
    # The generator computes the purpose word twice, once here and once through
    # `cast`, because an encoder that agrees only with itself proves nothing.
    assert d_beacon == action_digest(
        reg, USER, "0x" + beacon_mod.purpose(EPOCH).hex()), \
        "beacon digest disagrees with cast"

    out = {
        "beaconEpoch":         EPOCH,
        "beaconEpochSeconds":  beacon_mod.DEFAULT_PERIOD_DAYS * 86400,
        "beaconTag":           "0x" + beacon_mod.BEACON_TAG.hex(),
        "beaconDigest":        "0x" + d_beacon.hex(),
        "beaconTouch":         rec(Tier.TOUCH, 21, d_beacon),
        "beaconBlood":         rec(Tier.BLOOD, 23, d_beacon),
        "beaconNextEpoch":     rec(Tier.TOUCH, 25, d_beacon_next),
        # One beacon per period for the next nine, so the dormancy tests can
        # warp forward without an ffi call out to a signer. Counters rise with
        # the period, which is what the registry requires of them anyway.
        "beaconAt": [rec(Tier.TOUCH, 30 + i,
                         beacon_mod.Beacon(registry=reg, claimant=USER,
                                           chain_id=CHAINID,
                                           chain_name="foundry",
                                           epoch=EPOCH + i).digest())
                     for i in range(9)],
        "registry":            reg,
        "user":                USER,
        "purpose":             purpose,
        "redeemPurpose":       tagged,
        "redeemTag":           "0x" + beacon_mod.REDEEM_TAG.hex(),
        "pubkey":              "0x" + pk.hex(),
        "fwHash":              "0x" + fw.hex(),
        "calHash":             "0x" + cal.hex(),
        "record":              rec(Tier.BLOOD, 7, d_user),
        "recordLater":         rec(Tier.BLOOD, 9, d_user),
        "recordTouch":         rec(Tier.TOUCH, 11, d_user),
        "recordOtherClaimant": rec(Tier.BLOOD, 7, d_other),
    }
    p = pathlib.Path(__file__).with_name("registry_vectors.json")
    p.write_text(json.dumps(out, indent=2))
    print(f"wrote {p}")
    print(f"  registry {reg}  ·  16 records, all verified by firmware/attest.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
