"""Unlock chain tests — the order of operations, and what it refuses.

The interesting assertions here are about SEQUENCE, not just outcome. A chain
that produces a correct signature while taking the PIN before showing the
transaction is broken even though the signature verifies, so the step trace is
checked against signer.EXPECTED_ORDER rather than against prose.
"""

from __future__ import annotations

import hashlib

import attest
import ops
import signer
from policy import Policy, Tier
from se import MAX_PIN_ATTEMPTS, SoftSE
from signer import Refused, SignRequest, Signer, liveness_digest

FW = hashlib.sha256(b"cell-fw-test").digest()
CAL = hashlib.sha256(b"cell-thresholds-test").digest()
PIN = "12345678"
SIGHASH = hashlib.sha256(b"tx-under-test").digest()

GATE_OK = (True, {"gate_scores": {"G1": 0.15, "G6": 0.02}})
GATE_FAIL = (False, {"message": "Rejected at G6 motion arrested."})


def make(pol=None, confirm=True, gate=GATE_OK, se=None, seed=b"\x11" * 32,
         read_chamber=None):
    """A signer wired to instrumented collaborators."""
    log = {"confirmed_with": None, "gate_tier": None, "unwrap_key": None,
           "seed_at_sign": None, "seed_after": None}

    def _confirm(lines):
        log["confirmed_with"] = lines
        return confirm

    def _gate(tier):
        log["gate_tier"] = tier
        return gate

    def _unwrap(key):
        log["unwrap_key"] = key
        # Real builds AES-GCM-open the stored seed with `key`. A bytearray so
        # zeroise() has something it can actually clear.
        return bytearray(hashlib.sha256(key + seed).digest())

    def _sign(seed_buf, sighash):
        log["seed_at_sign"] = bytes(seed_buf)
        log["seed_after"] = seed_buf          # same object, checked after
        return attest.schnorr_sign(sighash, bytes(seed_buf))

    s = Signer(se or SoftSE(pin=PIN), pol or Policy(), FW, CAL,
               _confirm, _gate, _unwrap, _sign, read_chamber)
    return s, log


def run() -> int:
    ok = True
    results = []

    def check(label, cond):
        nonlocal ok
        ok &= bool(cond)
        results.append((label, bool(cond)))

    spend = ops.BitcoinSpend(amount_sats=250_000, destination="bc1qexampledest0000",
                             fee_sats=1_200)

    # ---- the happy path, and the ORDER it happened in --------------------
    s, log = make()
    res = s.authorize_and_sign(SignRequest(spend, SIGHASH), PIN)
    check("signs a renderable operation", len(res.signature) == 64)
    check("step order matches EXPECTED_ORDER", s.trace == signer.EXPECTED_ORDER)
    check("confirm ran before pin",
          s.trace.index("confirm") < s.trace.index("pin"))
    check("render ran before everything", s.trace[0] == "render")
    check("gate ran before unwrap",
          s.trace.index("gate") < s.trace.index("unwrap"))
    check("seed zeroised after signing", set(log["seed_after"]) == {0})
    check("owner saw the amount",
          any("0.00250000 BTC" in ln for ln in log["confirmed_with"]))
    check("owner saw the destination",
          any("bc1qexam" in ln for ln in log["confirmed_with"]))
    check("owner saw the required tier",
          any("requires TOUCH" in ln for ln in log["confirmed_with"]))

    # ---- the attestation is real and bound to this transaction ----------
    v = attest.verify(res.attestation, s.se.attest_pubkey(), SIGHASH,
                      min_counter=0, allowed_fw=[FW], require=Tier.TOUCH)
    check("attestation verifies", v.ok)
    check("attestation carries the calibration in force",
          res.attestation.cal_hash == CAL)
    check("attestation refuses an unregistered calibration",
          not attest.verify(res.attestation, s.se.attest_pubkey(), SIGHASH,
                            min_counter=0, allowed_fw=[FW], require=Tier.TOUCH,
                            allowed_cal=[bytes(32)]).ok)
    other = hashlib.sha256(b"another-tx").digest()
    check("attestation refuses a different tx",
          not attest.verify(res.attestation, s.se.attest_pubkey(), other,
                            min_counter=0, allowed_fw=[FW],
                            require=Tier.TOUCH).ok)
    # Round-trip through the real PSBT encoder rather than eyeballing the
    # bytes. The previous form of this check only asserted the key started
    # with b"CELL", which a malformed key does too — and a malformed
    # proprietary key makes Bitcoin Core reject the entire PSBT, not just skip
    # the field, so "our parser reads it back" proves nothing on its own.
    import psbt as psbtmod
    ident, subtype, val = res.psbt_proprietary()
    check("psbt field carries a parseable record",
          attest.Attestation.unpack(val) == res.attestation)
    key = psbtmod.proprietary_key(ident, subtype)
    check("proprietary key is BIP-174 encoded",
          key[0] == 0xFC and key[1] == len(ident) and
          key[2:2+len(ident)] == ident and key[2+len(ident)] == subtype)

    # ---- the wrapping key is stable, and bound to PIN and device --------
    # RECOVERABILITY IS THE PROPERTY. A wrap key must open tomorrow the seed
    # it wrapped today, so it comes from stable inputs only. Mixing this
    # capture's measurements or the sighash into it yields a key that can
    # never reopen anything — the seed would be lost on the first signature.
    s2, log2 = make(gate=(True, {"gate_scores": {"G1": 0.99, "G6": 0.99}}))
    s2.se = s.se                                    # same device secret
    res2 = s2.authorize_and_sign(SignRequest(spend, SIGHASH), PIN)
    check("different capture -> SAME wrapping key (seed stays recoverable)",
          log["unwrap_key"] == log2["unwrap_key"])

    s3, log3 = make()
    s3.se = s.se
    s3.authorize_and_sign(SignRequest(spend, other), PIN)
    check("different transaction -> SAME wrapping key",
          log["unwrap_key"] == log3["unwrap_key"])

    # ...and inert without the PIN or without this chip.
    s6, log6 = make(se=SoftSE(pin="654321"))
    s6.authorize_and_sign(SignRequest(spend, SIGHASH), "654321")
    check("different PIN -> different wrapping key",
          log["unwrap_key"] != log6["unwrap_key"])

    s7, log7 = make()                               # fresh SoftSE secret
    s7.authorize_and_sign(SignRequest(spend, SIGHASH), PIN)
    check("different device secret -> different wrapping key",
          log["unwrap_key"] != log7["unwrap_key"])

    # ---- and liveness proves itself in the RECORD -----------------------
    # The measurements are what the claim rests on, so they must reach the
    # attestation and must not be interchangeable between captures.
    check("attestation commits to the gate measurements",
          res.attestation.live_hash == liveness_digest(res.tier, GATE_OK[1]))
    check("a different capture attests a different measurement hash",
          res2.attestation.live_hash != res.attestation.live_hash)

    # ---- refusals --------------------------------------------------------
    def refuses(label, fn, expect_substr=None):
        try:
            fn()
            check(label, False)
        except Refused as e:
            check(label, expect_substr is None or expect_substr in str(e))

    s4, _ = make(gate=GATE_FAIL)
    refuses("liveness failure refuses",
            lambda: s4.authorize_and_sign(SignRequest(spend, SIGHASH), PIN),
            "G6")
    check("no attestation after a failed gate", "attest" not in s4.trace)
    check("no unwrap after a failed gate", "unwrap" not in s4.trace)

    s5, _ = make(confirm=False)
    refuses("cancelling at confirm refuses",
            lambda: s5.authorize_and_sign(SignRequest(spend, SIGHASH), PIN))
    check("no PIN taken when cancelled", "pin" not in s5.trace)

    s6, _ = make()
    refuses("wrong PIN refuses",
            lambda: s6.authorize_and_sign(SignRequest(spend, SIGHASH), "999999"),
            "Wrong PIN")
    check("no gate run on a wrong PIN", "gate" not in s6.trace)

    # de-escalation: the attack policy.py exists to stop, through the chain
    s7, _ = make(pol=Policy(blood_above=100_000))
    big = ops.BitcoinSpend(amount_sats=5_000_000, destination="bc1qbig0000000000",
                           fee_sats=500)
    refuses("de-escalation refused end to end",
            lambda: s7.authorize_and_sign(
                SignRequest(big, SIGHASH, requested_tier=Tier.TOUCH), PIN),
            "Refused")
    check("no confirm shown for a refused tier", "confirm" not in s7.trace)

    # escalation is always allowed, and is what gets attested
    s8, log8 = make()
    r8 = s8.authorize_and_sign(
        SignRequest(spend, SIGHASH, requested_tier=Tier.BLOOD), PIN)
    check("owner may escalate", r8.tier is Tier.BLOOD)
    check("gate ran at the escalated tier", log8["gate_tier"] is Tier.BLOOD)
    check("attestation records BLOOD", r8.attestation.tier is Tier.BLOOD)

    # policy.change is blood-locked no matter what policy says
    s9, log9 = make(pol=Policy(blood_above=None))
    pc = ops.PolicyChange(old_blood_above=None, new_blood_above=10_000_000)
    s9.authorize_and_sign(SignRequest(pc, SIGHASH), PIN)
    check("policy change forced to BLOOD", log9["gate_tier"] is Tier.BLOOD)
    check("policy change shows its direction",
          any("LOOSENS" in ln or "TIGHTENS" in ln
              for ln in log9["confirmed_with"]))

    # ---- unrenderable operations never reach the key ---------------------
    class Sneaky:
        """Has the right shape but is not in the closed set."""
        def op_class(self): return "tx.send"
        def amount_for_policy(self): return 0
        def render(self): return ["LOOKS FINE"]

    s10, _ = make()
    refuses("operation outside the closed set refused",
            lambda: s10.authorize_and_sign(SignRequest(Sneaky(), SIGHASH), PIN),
            "closed operation set")
    check("nothing ran past render", s10.trace == ["render"])

    s11, _ = make()
    # An absurd destination is shown IN FULL, so it overruns the 20-row screen
    # and is refused. It is never quietly abbreviated to fit.
    wide = ops.BitcoinSpend(amount_sats=1, fee_sats=1, destination="x" * 900)
    refuses("operation too tall for the display refused",
            lambda: s11.authorize_and_sign(SignRequest(wide, SIGHASH), PIN))

    # The destination must appear in full, never abbreviated — this is the
    # field address-substitution attacks target.
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    shown = "".join(ops.render_for_display(
        ops.BitcoinSpend(amount_sats=1, fee_sats=1, destination=addr)))
    check("destination shown in full, not abbreviated",
          addr in shown.replace(" ", "") and "..." not in shown)

    s12, _ = make()
    refuses("short sighash refused",
            lambda: s12.authorize_and_sign(SignRequest(spend, b"\x00" * 31), PIN))

    # ---- PIN lockout wipes ------------------------------------------------
    se_lock = SoftSE(pin=PIN)
    s13, _ = make(se=se_lock)
    for _ in range(MAX_PIN_ATTEMPTS):
        try:
            s13.authorize_and_sign(SignRequest(spend, SIGHASH), "00000000")
        except Refused:
            pass
    refuses("device wipes after repeated wrong PINs",
            lambda: s13.authorize_and_sign(SignRequest(spend, SIGHASH), PIN),
            "wiped")

    # ---- parser refuses what it does not understand -----------------------
    for label, payload in [
        ("unknown operation type", {"type": "evm_call", "data": "0x9a3f"}),
        ("bare hash", {"type": "raw", "digest": "00" * 32}),
        ("unknown field on a known type",
         {"type": "btc_spend", "amount_sats": 1, "destination": "bc1q",
          "fee_sats": 1, "memo": "surprise"}),
        ("missing required field", {"type": "btc_spend", "amount_sats": 1}),
        ("not an object", ["btc_spend", 1]),
        # A field of the right name and the wrong type reaches the renderer and
        # fails THERE, not in the constructor. These escaped as bare TypeError,
        # past every caller guarding this with `except UnrenderableOperation`.
        ("string where sats belong",
         {"type": "btc_spend", "amount_sats": "100", "destination": "bc1q",
          "fee_sats": 1}),
        ("JSON list where a frozenset belongs",
         {"type": "policy_change", "old_blood_above": None,
          "new_blood_above": 1, "old_locked": [], "new_locked": []}),
        ("string where a nonce belongs",
         {"type": "eth_spend", "amount_wei": 1, "destination": "0xab",
          "chain_id": 1, "chain_name": "eth", "nonce": "0", "max_fee_wei": 1}),
    ]:
        try:
            ops.parse(payload)
            check(f"parser refuses: {label}", False)
        except ops.UnrenderableOperation:
            check(f"parser refuses: {label}", True)

    good = ops.parse({"type": "btc_spend", "amount_sats": 100, "fee_sats": 2,
                      "destination": "bc1qgood0000"})
    check("parser accepts a well-formed spend", isinstance(good, ops.BitcoinSpend))

    # multisig context, matching what the industrial-design mockup shows
    ms = ops.BitcoinSpend(amount_sats=41_800_000, fee_sats=12_000,
                          destination="bc1q4m8z9xkt7fk3p2vq8dl4r6nwe5ta9c0hjuxsqz",
                          quorum_needed=2, quorum_size=3, signatures_present=1)
    ml = ops.render_for_display(ms)
    check("multisig threshold shown", any("MULTISIG 2 of 3" in l for l in ml))
    check("signer position shown", any("signature 2 of 2" in l for l in ml))
    for label, bad in [
        ("needed above size", dict(quorum_needed=4, quorum_size=3)),
        ("zero needed", dict(quorum_needed=0, quorum_size=3)),
        ("more sigs than signers",
         dict(quorum_needed=2, quorum_size=3, signatures_present=3)),
        # The bound is the QUORUM, not n. A 2-of-3 with both signatures already
        # present rendered "YOU ARE signature 3 of 2" -- a line that cannot be
        # true, on the screen the owner is being asked to approve.
        ("quorum already met",
         dict(quorum_needed=2, quorum_size=3, signatures_present=2)),
    ]:
        try:
            ops.BitcoinSpend(amount_sats=1, fee_sats=1, destination="bc1q",
                             **bad).render()
            check(f"refuses nonsensical quorum: {label}", False)
        except ops.UnrenderableOperation:
            check(f"refuses nonsensical quorum: {label}", True)
    check("no multisig lines when not multisig",
          not any("MULTISIG" in l for l in spend.render()))

    # unverified change must be shown as a warning, never folded away
    ch = ops.BitcoinSpend(amount_sats=1000, fee_sats=10, destination="bc1qdest0",
                          unverified_sats=500, unverified_address="bc1qunknown")
    # The confirmation screen is what the owner actually reads, and the signer
    # appends three lines to it AFTER the operation is rendered. An operation
    # that filled the screen exactly used to pass the fit check and then push
    # the tier disclosure off the bottom — the owner bleeding for a screen that
    # no longer said which tier was running. 87 destination lengths did it.
    over = 0
    for n in range(40, 400):
        long_dest = ops.BitcoinSpend(
            amount_sats=1, destination="bc1q" + "x" * n, fee_sats=1,
            change_sats=5, change_address="bc1q" + "z" * 40,
            unverified_sats=5, unverified_address="bc1q" + "y" * 40,
            quorum_needed=2, quorum_size=3)
        try:
            lines = ops.render_for_display(long_dest,
                                           reserve=ops.CONFIRM_FOOTER_ROWS)
        except ops.UnrenderableOperation:
            continue
        if len(lines) + ops.CONFIRM_FOOTER_ROWS > ops.DISPLAY_ROWS:
            over += 1
    check("no operation renders past the screen once the footer is added",
          over == 0)

    # And the composed screen is checked as a whole, so a long policy reason
    # cannot widen it past the display either.
    try:
        ops.check_fits(["x" * (ops.DISPLAY_COLS + 1)])
        check("an over-wide confirmation line is refused", False)
    except ops.UnrenderableOperation:
        check("an over-wide confirmation line is refused", True)
    try:
        ops.check_fits(["ok"] * (ops.DISPLAY_ROWS + 1))
        check("an over-tall confirmation screen is refused", False)
    except ops.UnrenderableOperation:
        check("an over-tall confirmation screen is refused", True)

    check("unverified change is flagged to the owner",
          any("WARNING" in ln for ln in ch.render()))

    # ---- the optical chamber in the KDF ----------------------------------
    # A device that never enrolled must derive exactly what it derived before
    # the chamber existed, or enrolment would strand every seed already
    # wrapped.
    check("no chamber reproduces the original context",
          signer.unwrap_context(PIN)
          == hashlib.sha256(b"CELL/unwrap/v1|"
                            + hashlib.sha256(PIN.encode()).digest()).digest())

    ctx_a = signer.unwrap_context(PIN, b"\xaa" * 32)
    ctx_b = signer.unwrap_context(PIN, b"\xbb" * 32)
    check("a different chamber is a different context", ctx_a != ctx_b)
    check("the chamber changes the context at all",
          ctx_a != signer.unwrap_context(PIN))
    check("the same chamber is stable", ctx_a == signer.unwrap_context(PIN, b"\xaa" * 32))

    # The whole point: dropping the helper must not open the seed. It cannot,
    # because the key is simply different -- no flag decides this.
    s_enrolled, log_enrolled = make(read_chamber=lambda: b"\xaa" * 32)
    s_enrolled.authorize_and_sign(SignRequest(spend, b"\x33" * 32), PIN)
    s_bare, log_bare = make()
    s_bare.authorize_and_sign(SignRequest(spend, b"\x33" * 32), PIN)
    check("dropping the chamber yields a different unwrap key",
          log_enrolled["unwrap_key"] != log_bare["unwrap_key"])

    s_swapped, log_swapped = make(read_chamber=lambda: b"\xcc" * 32)
    s_swapped.authorize_and_sign(SignRequest(spend, b"\x33" * 32), PIN)
    check("a swapped chamber yields a different unwrap key",
          log_swapped["unwrap_key"] != log_enrolled["unwrap_key"])

    # Provisioning with a chamber must produce a seed that needs it. This is
    # the end of the argument: not that the device checks, but that the
    # ciphertext does not open.
    import duress as _duress
    import wallet as _wallet
    _se = SoftSE(pin=PIN)
    _words = ("abandon " * 11 + "about")
    _prov = _wallet.provision(_words, _se, PIN, chamber=b"\xaa" * 32)
    _se.verify_pin(PIN)
    opened = _duress.unwrap_any(
        _prov.seed_pair, _se.kdf(signer.unwrap_context(PIN, b"\xaa" * 32)))
    check("a chamber-wrapped seed opens with its chamber",
          bytes(opened).decode().startswith("abandon"))
    for wrong in (None, b"\xbb" * 32):
        _se.verify_pin(PIN)
        try:
            _duress.unwrap_any(
                _prov.seed_pair, _se.kdf(signer.unwrap_context(PIN, wrong)))
            check(f"a chamber-wrapped seed stays shut without it ({wrong is None})",
                  False)
        except _duress.NoBlobOpened:
            check(f"a chamber-wrapped seed stays shut without it ({wrong is None})",
                  True)

    def _refusal(sgn, op):
        """The Refused message a signing produces, or a failure if it signs."""
        try:
            sgn.authorize_and_sign(SignRequest(op, b"\x33" * 32), PIN)
        except Refused as exc:
            return exc
        raise AssertionError("expected a refusal")

    # A chamber that cannot be decoded must refuse, not fall back.
    def _broken():
        raise RuntimeError("outside the enrolled radius")

    s_broken, _ = make(read_chamber=_broken)
    try:
        s_broken.authorize_and_sign(SignRequest(spend, b"\x33" * 32), PIN)
        check("an unreadable chamber refuses rather than falling back", False)
    except Refused as e:
        check("an unreadable chamber refuses rather than falling back",
              "chamber" in str(e))

    # And it must refuse at unwrap, after the gate -- never before the owner
    # has been shown the transaction.
    check("the chamber is read inside the unlock chain, not before it",
          s_broken.trace == ["render", "policy", "confirm", "pin", "gate",
                             "unwrap"])

    # A chamber that ANSWERED and did not decode, and a chamber that could not
    # be read at all, are different events with opposite remedies. Both refuse;
    # only one of them may say "restore from your recovery words". Telling an
    # owner their wallet is gone because a cartridge bay was open is how a
    # recoverable state turns into a re-flashed device.
    tamper_msg = str(_refusal(make(read_chamber=_broken)[0], spend))

    def _unavailable():
        raise signer.ChamberUnavailable("the cartridge bay is open.")

    open_bay_msg = str(_refusal(make(read_chamber=_unavailable)[0], spend))
    check("a chamber that will not decode says to restore from the words",
          "recovery words" in tamper_msg)
    check("a chamber that could not be READ does not",
          "recovery words" not in open_bay_msg)
    check("...and says the seed is fine", "seed" in open_bay_msg
          and "bay is open" in open_bay_msg)
    check("an unclassified failure still fails toward tamper",
          "recovery words" in tamper_msg)

    print(f"{'check':<52}{'result':>8}")
    print("-" * 60)
    for label, good_ in results:
        print(f"  {label:<50}{'PASS' if good_ else 'FAIL':>8}"
              + ("" if good_ else "   <-- UNEXPECTED"))
    print("-" * 60)
    print(f"{len(results)} checks. " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
