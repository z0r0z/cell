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


def main() -> int:
    reg = registry_address()
    purpose = "0x" + hashlib.sha256(b"cell-allowlist-round-1").hexdigest()

    sk = bytes.fromhex("00" * 31 + "03")
    pk = attest.schnorr_pubkey(sk)
    fw = hashlib.sha256(b"cell-fw-evm-test").digest()
    cal = hashlib.sha256(b"cal-v1").digest()
    live = hashlib.sha256(b"gate-measurements").digest()
    sign = lambda m: attest.schnorr_sign(m, sk)

    d_user = action_digest(reg, USER, purpose)
    d_other = action_digest(reg, OTHER, purpose)

    def rec(tier, counter, digest):
        a = attest.attest(tier, counter, digest, fw, cal, live, sign, pk)
        # Every vector is checked by the Python verifier first. A Solidity test
        # passing against a record the firmware itself rejects proves nothing.
        v = attest.verify(a, pk, digest, counter - 1, [fw], require=tier,
                          allowed_cal=[cal])
        assert v.ok, v.reason
        return "0x" + a.pack().hex()

    out = {
        "registry":            reg,
        "user":                USER,
        "purpose":             purpose,
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
    print(f"  registry {reg}  ·  4 records, all verified by firmware/attest.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
