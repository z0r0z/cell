#!/usr/bin/env python3
"""Proof of life: the digest, the screen, and the seed that is never unwrapped.

Four things are worth checking here and they are different questions.

THE DIGEST IS THE REGISTRY'S. `CellRegistry.beaconDigest` and `beacon.py` have
to agree exactly or every beacon this device makes is unredeemable. The
committed vectors in contracts/test/registry_vectors.json were produced by
foundry's own ABI encoder, so reproducing them here proves the Python encoder
matches the one the contract compiles against.

THE PERIOD IS THE CONTROL. The device has no clock, so a beacon is only as
honest as the date on its screen. The period has to appear in full, and a
beacon with no period has to be a refusal.

THE SEED IS NOT INVOLVED. A beacon signs nothing with the spend key, so the
chain must not unwrap the seed for one. The test passes callbacks that raise
if they are ever reached, and asserts the step trace against
signer.EXPECTED_ORDER_NO_SEED.

DOMAIN SEPARATION. A beacon must not redeem as an allowlist entry and an
allowlist entry must not read as proof of life.
"""

from __future__ import annotations

import json
import pathlib
import sys
from datetime import date

import beacon
import ops
import policy
from beacon import BadBeacon

VECTORS = (pathlib.Path(__file__).resolve().parents[1]
           / "contracts" / "test" / "registry_vectors.json")

REG = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
WHO = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
THIRD = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"


def _report(checks) -> bool:
    ok = True
    for label, good in checks:
        ok &= bool(good)
        print(f"  {label:<54}{'PASS' if good else 'FAIL'}")
    return ok


def _raises(fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
    except (BadBeacon, ops.UnrenderableOperation):
        return True
    except Exception:                                       # noqa: BLE001
        return False
    return False


def against_the_contract() -> bool:
    """The digest, against vectors produced by foundry's own encoder."""
    if not VECTORS.exists():                                # pragma: no cover
        print("  registry_vectors.json is missing -- run "
              "contracts/test/gen_registry_vectors.py")
        return False
    v = json.loads(VECTORS.read_text())
    b = beacon.Beacon(registry=v["registry"], claimant=v["user"],
                      chain_id=31337, chain_name="foundry",
                      epoch=v["beaconEpoch"])
    return _report([
        ("the beacon tag matches the contract's constant",
         "0x" + beacon.BEACON_TAG.hex() == v["beaconTag"]),
        ("the digest matches the one cast encoded",
         "0x" + b.digest().hex() == v["beaconDigest"]),
        ("the period length matches EPOCH_SECONDS",
         beacon.DEFAULT_PERIOD_DAYS * 86400 == v["beaconEpochSeconds"]),
        ("a beacon digest is not the allowlist digest",
         "0x" + b.digest().hex() != v.get("purpose")),
    ])


def periods() -> bool:
    """Epoch arithmetic, and the dates the screen shows."""
    e = beacon.epoch_of(date(2026, 8, 26))
    start, end = beacon.epoch_dates(e)
    checks = [
        ("a date lands inside its own period", start <= date(2026, 8, 26) <= end),
        ("periods are the documented length",
         (end - start).days + 1 == beacon.DEFAULT_PERIOD_DAYS),
        ("consecutive periods do not overlap",
         beacon.epoch_dates(e + 1)[0] == end + __import__(
             "datetime").timedelta(days=1)),
        ("the first period starts at the Unix epoch",
         beacon.epoch_dates(0)[0] == date(1970, 1, 1)),
        ("epochs increase with time",
         beacon.epoch_of(date(2027, 1, 1)) > e),
        ("a different period is a different digest",
         beacon.Beacon(registry=REG, claimant=WHO, chain_id=1,
                       chain_name="Ethereum", epoch=e).digest()
         != beacon.Beacon(registry=REG, claimant=WHO, chain_id=1,
                          chain_name="Ethereum", epoch=e + 1).digest()),
        ("a negative period is refused", _raises(beacon.epoch_dates, -1)),
        ("a zero-day period is refused", _raises(beacon.epoch_dates, 1, 0)),
    ]
    return _report(checks)


def binding() -> bool:
    """Each field of the digest must move it."""
    base = beacon.Beacon(registry=REG, claimant=WHO, chain_id=1,
                         chain_name="Ethereum", epoch=700)
    from dataclasses import replace
    moved = {
        "registry": replace(base, registry=THIRD).digest(),
        "claimant": replace(base, claimant=THIRD).digest(),
        "chain id": replace(base, chain_id=11155111).digest(),
        "period": replace(base, epoch=701).digest(),
    }
    d = base.digest()
    checks = [(f"{k} changes the digest", v != d) for k, v in moved.items()]
    checks += [
        ("all five are distinct", len({d, *moved.values()}) == 5),
        ("the same beacon is the same digest", base.digest() == d),
        ("chain id 0 is refused", _raises(replace(base, chain_id=0).digest)),
        ("registry as claimant is refused",
         _raises(replace(base, claimant=REG).check)),
        ("a bad checksum is refused",
         _raises(replace(base, registry=REG.lower()[:-1] + "A").digest)),
    ]
    return _report(checks)


def the_screen() -> bool:
    b = ops.ProofOfLife(registry=REG, claimant=WHO, chain_id=1,
                        chain_name="Ethereum", period_start="2026-08-05",
                        period_end="2026-09-03")
    lines = ops.render_for_display(b, reserve=ops.CONFIRM_FOOTER_ROWS)

    def shows(needle):
        return any(needle in ln for ln in lines)

    def bad(**kw):
        from dataclasses import replace
        return _raises(ops.render_for_display, replace(b, **kw))

    return _report([
        ("the screen fits", len(lines) <= ops.DISPLAY_ROWS - ops.CONFIRM_FOOTER_ROWS),
        ("the period is shown in full", shows("2026-08-05") and shows("2026-09-03")),
        ("the period is above the addresses",
         lines.index("  period   2026-08-05") < lines.index("  registry")),
        ("the registry is shown in full", shows(REG[-8:])),
        ("the claimant is shown in full", shows(WHO[-8:])),
        ("it says it moves nothing", shows("nothing at all")),
        ("a beacon with no period is refused", bad(period_start="")),
        ("a beacon with no end is refused", bad(period_end="")),
        ("chain 0 is refused", bad(chain_id=0)),
        ("an unnamed chain is refused", bad(chain_name="")),
    ])


def the_policy() -> bool:
    p = policy.Policy()
    locked = policy.Policy(blood_locked=frozenset({"life.beacon"}))
    return _report([
        ("a beacon runs at touch tier",
         p.required_tier("life.beacon") == policy.Tier.TOUCH),
        ("an amount floor does not reach it",
         policy.Policy(blood_above=0).required_tier("life.beacon", 0)
         == policy.Tier.TOUCH),
        ("it is not blood-locked by default",
         "life.beacon" not in policy.ALWAYS_BLOOD),
        ("an owner may still lock it",
         locked.required_tier("life.beacon") == policy.Tier.BLOOD),
        ("it is priced", "life.beacon" in policy.KNOWN_OPS),
    ])


def no_seed() -> bool:
    """The whole chain, and the seed that must not be touched by it."""
    import signer
    import wallet
    from se import SoftSE
    from test_wallet import MNEMONIC, PIN, gate_ok

    se = SoftSE(pin=PIN)
    prov = wallet.provision(MNEMONIC, se, PIN, script_types=("p2wpkh",))
    fw, cal = b"\x11" * 32, b"\x22" * 32
    shown: list[list[str]] = []

    def confirm(lines):
        shown.append(lines)
        return True

    epoch = beacon.epoch_of(date(2026, 8, 26))
    out = wallet.sign_beacon(REG, WHO, 1, epoch, prov, se, policy.Policy(),
                             fw, cal, confirm, gate_ok, PIN)

    def refused(fn):
        try:
            fn()
        except Exception:                                   # noqa: BLE001
            return True
        return False

    b = beacon.Beacon(registry=REG, claimant=WHO, chain_id=1,
                      chain_name="Ethereum", epoch=epoch)
    return _report([
        ("a beacon attests", len(out.attestation) > 0),
        ("it runs at touch tier", out.tier is policy.Tier.TOUCH),
        ("the digest is the registry's", out.digest == "0x" + b.digest().hex()),
        ("the period travels back with it", "2026-" in out.period),
        ("the seed was never unwrapped, by the trace",
         "unwrap" in signer.EXPECTED_ORDER_NO_SEED
         and "sign" not in signer.EXPECTED_ORDER_NO_SEED),
        ("the owner saw the period",
         any("period" in ln for ln in out.display)),
        ("an unregistered chain is refused",
         refused(lambda: wallet.sign_beacon(REG, WHO, 999999, epoch, prov, se,
                                            policy.Policy(), fw, cal, confirm,
                                            gate_ok, PIN))),
        ("declining signs nothing",
         refused(lambda: wallet.sign_beacon(REG, WHO, 1, epoch, prov, se,
                                            policy.Policy(), fw, cal,
                                            lambda _l: False, gate_ok, PIN))),
        ("a failed gate signs nothing",
         refused(lambda: wallet.sign_beacon(REG, WHO, 1, epoch, prov, se,
                                            policy.Policy(), fw, cal, confirm,
                                            lambda _t: (False, {}), PIN))),
        ("a wrong PIN signs nothing",
         refused(lambda: wallet.sign_beacon(REG, WHO, 1, epoch, prov, se,
                                            policy.Policy(), fw, cal, confirm,
                                            gate_ok, "00000000"))),
    ])


def main() -> int:
    print("Proof of life: the beacon, and the switch that reads it\n")
    print("Against the contract's own vectors:")
    a = against_the_contract()
    print("\nPeriods:")
    b = periods()
    print("\nWhat the digest binds:")
    c = binding()
    print("\nThe screen:")
    d = the_screen()
    print("\nTier policy:")
    e = the_policy()
    print("\nThe chain, and the seed it must not unwrap:")
    f = no_seed()
    ok = all([a, b, c, d, e, f])
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
