#!/usr/bin/env python3
"""Deploy the contracts, and make a real node accept a beacon the firmware made.

`forge test` proves each contract does what its unit tests say against records
generated for it. This asks the other question, the one `regtest_e2e.py` asks
on the Bitcoin side: does the whole path work at once, against a node that has
never heard of this project?

    anvil runs a private chain with no peers
    CellRegistry and CellDormancy are deployed to it
    firmware/attest.py signs a proof of life for the CURRENT period, which is
      read off the chain's own clock rather than chosen to suit the test
    the chain accepts it, and the dormancy switch behaves through a full
      cycle: claim, cancel on one beacon, then claim again and release

If that completes, then the epoch arithmetic, the purpose word, the ABI
encoding, the BIP-340 signature, the on-chain point lift, the counter rule and
the two-phase switch are all correct TOGETHER, which is a stronger claim than
each of them being correct separately. In particular it is the first thing
that runs the Python epoch and the Solidity epoch against one clock: a
disagreement of one period there would make every beacon this device produces
unredeemable, and no unit test on either side can see it.

The chain is private, the coins are worthless and nothing leaves the machine.
It is not part of `run_tests.py` because it needs foundry, which the suite a
first-time cloner runs has no business downloading.

    tools/evm_e2e.py                       # anvil on a free port
    tools/evm_e2e.py --keep                # leave the chain up afterwards
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "firmware"))

import attest                                                   # noqa: E402
import beacon as beacon_mod                                     # noqa: E402
from policy import Tier                                         # noqa: E402

# anvil's first account, which holds the whole allocation on a private chain.
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# The device, and the person who inherits from it.
DEVICE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
DEVICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
HEIR_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
HEIR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

FW = __import__("hashlib").sha256(b"cell-fw-evm-e2e").digest()
CAL = __import__("hashlib").sha256(b"cal-e2e").digest()
LIVE = __import__("hashlib").sha256(b"gate-measurements").digest()
ATTEST_SK = bytes.fromhex("00" * 31 + "0b")

DORMANCY = 180 * 86400
CHALLENGE = 30 * 86400


class Failed(Exception):
    pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Chain:
    """anvil, and the cast calls that drive it."""

    def __init__(self, port: int):
        self.rpc = f"http://127.0.0.1:{port}"
        self.port = port
        self.proc: "subprocess.Popen | None" = None

    def start(self) -> None:
        anvil = shutil.which("anvil")
        if not anvil:
            raise Failed(
                "anvil is not on PATH. Install foundry "
                "(https://getfoundry.sh) or run with --rpc against a node you "
                "already have.")
        self.proc = subprocess.Popen(
            [anvil, "--port", str(self.port), "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                self.call("block-number")
                return
            except Exception:                                   # noqa: BLE001
                time.sleep(0.1)
        raise Failed("anvil did not come up")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None

    def call(self, *args: str) -> str:
        r = subprocess.run(["cast", *args, "--rpc-url", self.rpc],
                           capture_output=True, text=True)
        if r.returncode:
            raise Failed(f"cast {args[0]}: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    def send(self, key: str, to: str, sig: str, *args: str) -> str:
        return self.call("send", "--private-key", key, to, sig, *args)

    def send_expect_revert(self, key: str, to: str, sig: str, *args: str) -> str:
        try:
            self.send(key, to, sig, *args)
        except Failed as e:
            return str(e)
        raise Failed(f"{sig} was expected to revert and did not")

    def deploy(self, artifact: str, *args: str) -> str:
        path = ROOT / "contracts" / "out" / artifact
        if not path.exists():
            raise Failed(f"{path} is missing. Run `forge build` in contracts/.")
        code = json.loads(path.read_text())["bytecode"]["object"]
        # --rpc-url and --json have to precede --create: everything after it
        # is read as the constructor's signature and arguments.
        cmd = ["cast", "send", "--rpc-url", self.rpc, "--json",
               "--private-key", DEPLOYER_KEY, "--create", code]
        if args:
            abi = json.loads(path.read_text())["abi"]
            ctor = next((f for f in abi if f.get("type") == "constructor"), None)
            types = ",".join(i["type"] for i in (ctor or {}).get("inputs", []))
            cmd += [f"constructor({types})", *args]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise Failed(f"deploy {artifact}: {r.stderr.strip()}")
        return json.loads(r.stdout)["contractAddress"]

    def num(self, *args: str) -> int:
        """A uint out of `cast call`. It prints "1787762204 [1.787e9]"."""
        return int(self.call(*args).split()[0])

    def timestamp(self) -> int:
        return int(self.call("block", "latest", "--field", "timestamp").split()[0])

    def warp(self, seconds: int) -> None:
        subprocess.run(["cast", "rpc", "evm_increaseTime", str(seconds),
                        "--rpc-url", self.rpc],
                       capture_output=True, text=True, check=True)
        subprocess.run(["cast", "rpc", "evm_mine", "--rpc-url", self.rpc],
                       capture_output=True, text=True, check=True)


def ok(label: str, good: bool, detail: str = "") -> bool:
    print(f"  {label:<52}{'PASS' if good else 'FAIL'}"
          + (f"  {detail}" if detail else ""))
    return good


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", help="drive a node you started yourself")
    ap.add_argument("--keep", action="store_true",
                    help="leave anvil running when the run finishes")
    args = ap.parse_args()

    if not shutil.which("cast"):
        print("cast is not on PATH. Install foundry: https://getfoundry.sh")
        return 2

    chain = Chain(_free_port())
    if args.rpc:
        chain.rpc = args.rpc
    else:
        chain.start()
    print(f"chain: {chain.rpc}\n")

    passed = True
    try:
        # ---- deploy ------------------------------------------------------
        reg = chain.deploy("CellRegistry.sol/CellRegistry.json")
        dead = chain.deploy("CellDormancy.sol/CellDormancy.json",
                            reg, DEVICE, HEIR, str(DORMANCY), str(CHALLENGE))
        print("deployed")
        print(f"  CellRegistry  {reg}")
        print(f"  CellDormancy  {dead}\n")

        chain.send(DEPLOYER_KEY, reg, "allowFirmware(bytes32,bool)",
                   "0x" + FW.hex(), "true")
        chain.send(DEPLOYER_KEY, reg, "allowCalibration(bytes32,bool)",
                   "0x" + CAL.hex(), "true")
        pub = attest.schnorr_pubkey(ATTEST_SK)
        chain.send(DEVICE_KEY, reg, "register(bytes32)", "0x" + pub.hex())

        chain_id = int(chain.call("chain-id").split()[0])
        counter = [100]

        def beacon_for(epoch: int, tier=Tier.TOUCH) -> str:
            """A record the firmware produced, for the period given."""
            b = beacon_mod.Beacon(registry=reg, claimant=DEVICE,
                                  chain_id=chain_id, chain_name="anvil",
                                  epoch=epoch)
            counter[0] += 1
            a = attest.attest(tier, counter[0], b.digest(), FW, CAL, LIVE,
                              lambda m: attest.schnorr_sign(m, ATTEST_SK), pub)
            v = attest.verify(a, pub, b.digest(), counter[0] - 1, [FW],
                              require=tier, allowed_cal=[CAL])
            if not v.ok:                                        # pragma: no cover
                raise Failed(f"the firmware rejects its own record: {v.reason}")
            return "0x" + a.pack().hex()

        def epoch_now() -> int:
            return chain.num("call", reg, "currentEpoch()(uint64)")

        # ---- the two clocks agree ---------------------------------------
        print("the period, computed on both sides of the airgap:")
        ts = chain.timestamp()
        theirs = epoch_now()
        ours = ts // (beacon_mod.DEFAULT_PERIOD_DAYS * 86400)
        passed &= ok("the chain's period is the one beacon.py computes",
                     theirs == ours, f"epoch {theirs}")
        start, end = beacon_mod.epoch_dates(theirs)
        print(f"  the device would show: {start} through {end}\n")

        # ---- a beacon lands ---------------------------------------------
        print("proof of life:")
        chain.send(DEVICE_KEY, reg, "heartbeat(bytes,uint64)",
                   beacon_for(theirs), str(theirs))
        seen = chain.num("call", reg, "lastSeen(address)(uint64)", DEVICE)
        passed &= ok("a touch-tier beacon is accepted by the node", seen > 0)
        passed &= ok("the device reads as not dormant",
                     chain.num("call", reg, "dormantFor(address)(uint64)",
                               DEVICE) < 60)
        passed &= ok("a beacon for the next period is refused now",
                     "EpochNotCurrent" in chain.send_expect_revert(
                         DEVICE_KEY, reg, "heartbeat(bytes,uint64)",
                         beacon_for(theirs + 1), str(theirs + 1)))
        passed &= ok("an allowlist record is refused as a beacon",
                     "WrongDigest" in chain.send_expect_revert(
                         DEVICE_KEY, reg, "heartbeat(bytes,uint64)",
                         _allowlist_record(reg, chain_id, pub, counter),
                         str(theirs)))
        print()

        # ---- the switch --------------------------------------------------
        print("the dormancy switch, through a full cycle:")
        passed &= ok("a claim before the silence is refused",
                     "NotDormantYet" in chain.send_expect_revert(
                         HEIR_KEY, dead, "startClaim()"))

        chain.warp(DORMANCY + 3600)
        chain.send(HEIR_KEY, dead, "startClaim()")
        passed &= ok("after the silence the heir may open a claim",
                     chain.num("call", dead, "claimStartedAt()(uint64)") > 0)
        passed &= ok("the claim releases nothing on its own",
                     chain.call("call", dead, "released()(bool)") == "false")

        # The device comes out of the drawer.
        chain.warp(3600)
        ep = epoch_now()
        chain.send(DEVICE_KEY, reg, "heartbeat(bytes,uint64)",
                   beacon_for(ep), str(ep))
        chain.send(HEIR_KEY, dead, "cancelClaim()")
        passed &= ok("one beacon cancels the claim",
                     chain.num("call", dead, "claimStartedAt()(uint64)") == 0)

        chain.warp(CHALLENGE + 3600)
        passed &= ok("and finalising a cancelled claim is refused",
                     "NoClaimOpen" in chain.send_expect_revert(
                         HEIR_KEY, dead, "finalize()"))

        # Now the owner really is gone.
        chain.warp(DORMANCY + 3600)
        chain.send(HEIR_KEY, dead, "startClaim()")
        passed &= ok("finalising inside the window is refused",
                     "StillInChallengeWindow" in chain.send_expect_revert(
                         HEIR_KEY, dead, "finalize()"))
        chain.warp(CHALLENGE + 3600)
        chain.send(HEIR_KEY, dead, "finalize()")
        passed &= ok("silence through the window releases",
                     chain.call("call", dead, "released()(bool)") == "true")
        passed &= ok("and release is final",
                     "AlreadyReleased" in chain.send_expect_revert(
                         HEIR_KEY, dead, "startClaim()"))

        print("\n" + ("PASS — a node accepted a beacon this firmware signed, "
                      "and the switch behaved."
                      if passed else "FAIL"))
        return 0 if passed else 1
    except Failed as e:
        print(f"\nFAILED: {e}")
        return 1
    finally:
        if not args.keep and not args.rpc:
            chain.stop()
        elif args.keep:
            print(f"\nanvil left running on {chain.rpc} (pid "
                  f"{chain.proc.pid if chain.proc else '?'})")


def _allowlist_record(reg: str, chain_id: int, pub: bytes, counter) -> str:
    """A genuine record bound to an allowlist purpose, not to a period.

    Domain separation is the claim: a record that admits somebody to an
    allowlist must not read as proof that they are alive.
    """
    import hashlib

    from hashes import keccak256
    import eip712
    purpose = hashlib.sha256(b"cell-allowlist").digest()
    digest = keccak256(eip712._word(chain_id)
                       + eip712._address_word(reg)
                       + eip712._address_word(DEVICE)
                       + purpose)
    counter[0] += 1
    a = attest.attest(Tier.BLOOD, counter[0], digest, FW, CAL, LIVE,
                      lambda m: attest.schnorr_sign(m, ATTEST_SK), pub)
    return "0x" + a.pack().hex()


if __name__ == "__main__":
    raise SystemExit(main())
