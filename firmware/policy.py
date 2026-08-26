"""CELL tier policy — which gate must run for a given operation.

Touch is the default. Blood is a mode you enter.

    You can always escalate.  You can never de-escalate.

That asymmetry is the whole security argument for having two tiers. Without
it, an attacker holding the device and the PIN simply never chooses blood mode
and the top tier is decorative.

Two rules carry it:

  1. The user may always request a HIGHER tier than policy requires. Entering
     blood mode for a small transfer because it feels significant is a valid
     act and the device must permit it.

     Escalation is PER-OPERATION and does not persist. The next operation
     reverts to the floor. Living permanently at blood tier is not a separate
     mode — it is a Policy with blood_above=0 and the operation classes locked.

  2. The user may never proceed at a LOWER tier than policy requires, and
     CHANGING THE POLICY IS ITSELF BLOOD-LOCKED. Otherwise the attack is not
     "defeat the blood gate", it is "lower the threshold, then use a finger" —
     which needs no blood at all.

Changing the floor costs blood in BOTH directions. Loosening, obviously —
otherwise a thief lowers the bar and uses a finger. Tightening too, or an
attacker locks the owner out by raising the floor to blood-for-everything.

Rule 2 is the one people leave out. It is the only thing standing between a
two-tier device and a one-tier device with extra steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Tier(IntEnum):
    """Ordered. Comparison is the enforcement mechanism, so keep it ordered."""
    TOUCH = 1
    BLOOD = 2


class Op(str):
    """Operation class. Free-form so the wallet layer can add its own, but the
    ones below are locked at provisioning and cannot be unlocked without blood."""


# Blood-locked at provisioning, permanently. These are the operations that, if
# an attacker could perform them at touch tier, would let them dismantle every
# other protection.
# Every operation class this policy knows how to price. Anything outside it is
# a programming error, and required_tier answers BLOOD for it rather than the
# default -- see the note there. The tests check this covers everything ops.py
# can emit.
KNOWN_OPS = frozenset({
    "tx.send",
    "note.spend",
    "policy.change",
    "key.export",
    "device.wipe",
    "device.reprovision",
    "recipient.allowlist",
    "account.delegate",
})

ALWAYS_BLOOD = frozenset({
    "policy.change",       # the rule that makes the whole scheme hold
    "key.export",
    "device.wipe",
    "device.reprovision",
    "recipient.allowlist",
    # An EIP-7702 delegation moves nothing, so an amount-based floor never
    # reaches it. It decides what every later signature from that address
    # means, which makes it reprovisioning under another name.
    "account.delegate",
})


@dataclass(frozen=True)
class Policy:
    """Set at provisioning. Any change is an Op("policy.change")."""

    # Above this amount, blood is required. Denominated in the smallest unit of
    # the chain in question; the wallet layer normalises.
    #
    # None means NO amount-based escalation — the amount never triggers blood,
    # and only the operation class does. That is deliberately spelled None and
    # not 0: "blood_above = 0" reads to everyone as "blood above zero, i.e.
    # blood for everything", and a sentinel that quietly means the exact
    # opposite is the wrong thing to hand someone hardening their own device.
    #
    # So: 0 now means what it looks like. Blood for any positive amount.
    #     None means what it says. Amount is not a factor.
    blood_above: Optional[int] = None
    # Extra operation classes the owner chose to lock, beyond ALWAYS_BLOOD.
    blood_locked: frozenset[str] = field(default_factory=frozenset)

    def required_tier(self, op: str, amount: int = 0) -> Tier:
        """The tier this operation needs. An unknown operation needs blood.

        The default matters more than it looks. Operations arrive here as bare
        strings, and the obvious fallback -- drop through to TOUCH -- means a
        class nobody priced asks for a pulse instead of a drop, silently and
        in the direction that looks safe. A renamed op_class, or one added to
        ops.py without a line here, would quietly downgrade itself.

        So the fallback is the strong tier, and KNOWN_OPS is checked against
        ops.op_classes() by the tests. Getting this wrong now costs friction.
        The other way round it cost a tier.
        """
        if op in ALWAYS_BLOOD or op in self.blood_locked:
            return Tier.BLOOD
        if op not in KNOWN_OPS:
            return Tier.BLOOD
        if self.blood_above is not None and amount > self.blood_above:
            return Tier.BLOOD
        return Tier.TOUCH


@dataclass
class Decision:
    permitted: bool
    tier_to_run: Tier
    reason: str

    def __str__(self) -> str:
        return (f"[{'OK ' if self.permitted else 'DENY'}] "
                f"{self.tier_to_run.name}: {self.reason}")


def decide(policy: Policy, op: str, amount: int = 0,
           requested: Tier | None = None) -> Decision:
    """Resolve the tier for one operation.

    `requested` is what the user asked for at the UI — None means "whatever is
    required". Returning a Decision rather than a bare Tier keeps the reason
    auditable and lets the device tell the user WHY it is asking for blood,
    which is the difference between a ritual and an annoyance.
    """
    required = policy.required_tier(op, amount)

    if requested is None:
        return Decision(True, required, f"{op}: policy requires {required.name}")

    if requested < required:
        # The de-escalation attempt. This is the attack, and it is refused
        # without appeal — there is no override, no timeout, no "are you sure".
        return Decision(False, required,
                        f"{op}: policy requires {required.name}, "
                        f"{requested.name} was requested. Refused.")

    if requested > required:
        return Decision(True, requested,
                        f"{op}: escalated to {requested.name} by choice")

    return Decision(True, required, f"{op}: policy requires {required.name}")


def _selftest() -> int:
    p = Policy(blood_above=10_000_000)          # 0.1 BTC in sats
    cases = [
        # (op, amount, requested, expect_permitted, expect_tier)
        ("tx.send",        1_000,      None,        True,  Tier.TOUCH),
        ("tx.send",        1_000,      Tier.BLOOD,  True,  Tier.BLOOD),   # escalate
        ("tx.send",        50_000_000, None,        True,  Tier.BLOOD),   # over threshold
        ("tx.send",        50_000_000, Tier.TOUCH,  False, Tier.BLOOD),   # de-escalate: THE ATTACK
        ("policy.change",  0,          None,        True,  Tier.BLOOD),
        ("policy.change",  0,          Tier.TOUCH,  False, Tier.BLOOD),   # lower-the-bar attack
        ("key.export",     0,          Tier.TOUCH,  False, Tier.BLOOD),
        ("device.wipe",    0,          None,        True,  Tier.BLOOD),
    ]
    # Every operation the device can be asked to sign has to be priced here.
    # The two modules talk in bare strings, so nothing but this notices a
    # rename -- and a rename fails toward BLOOD now, which is friction the
    # owner would report rather than a tier quietly lost.
    import ops
    missing = ops.op_classes() - KNOWN_OPS
    unknown_needs_blood = (Policy().required_tier("tx.send.typo") is Tier.BLOOD)

    print("Tier policy self-test\n")
    ok = not missing and unknown_needs_blood
    if missing:
        print(f"  ops.py emits {sorted(missing)}, which policy does not price")
    if not unknown_needs_blood:
        print("  an unknown operation did not require blood")
    for op, amt, req, want_p, want_t in cases:
        d = decide(p, op, amt, req)
        good = d.permitted == want_p and d.tier_to_run == want_t
        ok &= good
        label = f"{op}({amt:,}) req={req.name if req else '-':<5}"
        print(f"  {label:<34}{d}{'' if good else '   <-- UNEXPECTED'}")

    # The sentinel must mean what it reads as. blood_above=0 is "blood above
    # zero" — blood for any positive amount, which is how a user hardening
    # their device will expect it to behave. None is how you turn amount-based
    # escalation off.
    p0 = Policy(blood_above=0)
    checks = [
        ("blood_above=0  -> any positive amount needs blood",
         p0.required_tier("tx.send", 1) is Tier.BLOOD),
        ("blood_above=0  -> a zero-amount op still uses the class rules",
         p0.required_tier("tx.send", 0) is Tier.TOUCH),
        ("blood_above=None -> amount never escalates",
         Policy().required_tier("tx.send", 10**18) is Tier.TOUCH),
        ("blood_above=None -> locked classes still need blood",
         Policy().required_tier("key.export", 0) is Tier.BLOOD),
    ]
    print()
    for label, good in checks:
        ok &= good
        print(f"  {label}{'' if good else '   <-- UNEXPECTED'}")

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
