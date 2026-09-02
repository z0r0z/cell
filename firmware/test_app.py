#!/usr/bin/env python3
"""The whole device, driven end to end with fakes.

Everything below `app.py` already has its own tests. This file is about the
seams between them — the places where a correct component can still be used
wrongly, and where the ordering the design depends on could quietly stop
holding:

    the transaction is DISPLAYED before the PIN is asked for
    the PIN is asked for before the gate runs
    the gate runs before anything is unwrapped
    declining at any point signs nothing and says so
    every refusal is a screen the owner can read, never a traceback

A device that drops to a traceback in front of somebody holding a lancet has
failed at the only job it has, so the loop is driven with hostile input and
asserted to keep its footing.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys

import app
import bip32
import ops
import psbt as psbtmod
import eth
import qr
import wallet
from buttons import BACK, CONFIRM, DOWN, UP, FakeButtons
from camera import FakeCamera
from display import ConsoleDisplay
from policy import Policy
from se import SoftSE
from test_wallet import MNEMONIC, build_multisig_psbt, build_psbt, multisig_parts

PIN = "12345678"
FW = hashlib.sha256(b"test firmware").digest()
CAL = hashlib.sha256(b"test thresholds").digest()

FAILURES: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


# --------------------------------------------------------------------------


def pin_presses(pin: str = PIN) -> list[str]:
    """The button sequence that types a PIN on four buttons."""
    out = []
    for ch in pin:
        out += [UP] * int(ch) + [CONFIRM]
    return out


class Recorder(ConsoleDisplay):
    """A display that remembers every screen it was asked to paint."""

    def __init__(self):
        super().__init__(out=io.StringIO())
        self.screens: list[list[str]] = []

    def show(self, lines, highlight=None):
        # Recorded BEFORE the paint. ConsoleDisplay.show raises on a screen
        # that does not fit, so appending afterwards meant an oversized screen
        # was never recorded -- and the "no screen anywhere overflowed" sweep
        # at the end of this suite was checking a list that could not, by
        # construction, contain an offender.
        self.screens.append(list(lines))
        super().show(lines, highlight)

    def text(self) -> str:
        return "\n".join("\n".join(s) for s in self.screens)


def make_device(*, presses, frames, gate=None, policy=None, prov=None, se=None,
                network="mainnet"):
    order: list[str] = []

    def default_gate(tier):
        order.append(f"gate:{tier.name}")
        return True, {"gate_scores": {"G1": 0.98}, "features": {"soret": 0.4}}

    se = se or SoftSE(pin=PIN)
    fake_buttons = FakeButtons(list(presses))
    if prov is None:
        prov = wallet.provision(MNEMONIC, se, PIN,
                                script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh",
                                              "p2pkh"))
    d = app.Device(prov=prov, se=se, display=Recorder(),
                   buttons=fake_buttons, camera=FakeCamera(frames),
                   run_gate=gate or default_gate, policy=policy or Policy(),
                   fw_hash=FW, cal_hash=CAL, network=network,
                   # The device's own default is time.sleep, which is what
                   # gives the output QR its frame time. The suite has no
                   # camera to give it to.
                   sleep=lambda _s: None,
                   clock=fake_buttons.now)
    return d, order


def main() -> int:
    print("Application loop — the seams between the parts\n")
    root = bip32.from_mnemonic(MNEMONIC)

    # ---- the happy path ------------------------------------------------
    print(" a signature, start to finish")
    blob = build_psbt(root, "p2wpkh")
    frames = qr.encode(blob)
    d, order = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                           + [CONFIRM, CONFIRM],
                           frames=frames)
    outcome = d.run_once()
    check("a scanned PSBT is signed", outcome == "signed-psbt")
    text = d.display.text()
    check("the destination was shown in full",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
          in text.replace("\n", "").replace(" ", ""))
    check("the amount was shown", "0.00150000 BTC" in text)
    check("the tier was stated", "requires" in text)
    check("the signed PSBT was emitted as QR frames", len(d.display.frames) > 0)
    emitted = qr.decode(d.display.frames)
    check("the emitted frames reassemble into a PSBT",
          emitted.startswith(psbtmod.PSBT_MAGIC))
    check("...carrying a signature", any(
        k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])
        for k in psbtmod.PSBT.parse(emitted).inputs[0]))
    check("...and the attestation",
          psbtmod.PSBT.parse(emitted).get_proprietary(b"CELL", 1) is not None)

    # ---- the ordering the design rests on -------------------------------
    print("\n ordering")
    screens = d.display.screens

    def first_screen_matching(needle: str) -> int:
        for i, s in enumerate(screens):
            if needle in "\n".join(s):
                return i
        return 10**6

    i_amount = first_screen_matching("0.00150000 BTC")
    i_pin = first_screen_matching("ENTER PIN")
    i_gate = first_screen_matching("REQUIRED")
    check("the transaction is shown before the PIN is asked for",
          i_amount < i_pin)
    check("the PIN is asked for before the gate is run", i_pin < i_gate)
    check("the gate ran after both", order and order[0].startswith("gate:"))

    # ---- declining, at each point ---------------------------------------
    print("\n declining")
    d2, order2 = make_device(presses=[CONFIRM, BACK], frames=frames)
    check("declining at the confirmation signs nothing",
          d2.run_once() == "cancelled")
    check("...and no gate was run", order2 == [])
    check("...and it says so", "CANCELLED" in d2.display.text())
    check("...and nothing was emitted", d2.display.frames == [])

    d3, order3 = make_device(presses=[CONFIRM, CONFIRM, BACK], frames=frames)
    check("backing out of the PIN signs nothing", d3.run_once() == "cancelled")
    check("...and no gate was run", order3 == [])

    def failing_gate(tier):
        return False, {"message": "no pulse detected"}

    d4, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses() + [CONFIRM],
                        frames=frames, gate=failing_gate)
    check("a failed gate signs nothing", d4.run_once() == "refused")
    check("...and the reason reaches the owner",
          "no pulse" in d4.display.text())
    check("...and nothing was emitted", d4.display.frames == [])

    # ---- a wrong PIN ----------------------------------------------------
    print("\n the PIN")
    se = SoftSE(pin=PIN)
    prov = wallet.provision(MNEMONIC, se, PIN,
                            script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh", "p2pkh"))
    d5, order5 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses("99999999")
                             + [CONFIRM],
                             frames=frames, se=se, prov=prov)
    check("a wrong PIN is refused", d5.run_once() == "refused")
    check("...and the gate never ran", order5 == [])
    check("...and the owner is told how many attempts remain",
          "attempts remaining" in d5.display.text())

    # ---- hostile and malformed input ------------------------------------
    print("\n hostile input")
    cases = [
        ("a PSBT with no key of ours",
         qr.encode(build_psbt(bip32.from_mnemonic(
             "zoo " * 11 + "wrong"), "p2wpkh"))),
        ("a truncated PSBT", qr.encode(blob[:-8])),
        ("a PSBT paying two destinations",
         qr.encode(build_psbt(root, "p2wpkh", send=100_000, change=45_000,
                              extra_outputs=((50_000,
                                              "bc1qrp33g0q5c5txsp9arysrx4k6zd"
                                              "kfs4nce4xj0gdcccefvpysxf3qccfmv3"),)))),
        ("a QR that is not a transaction at all", qr.encode(b"hello there")),
        ("a QR full of JSON that is not ours",
         qr.encode(json.dumps({"type": "something-else"}).encode())),
        ("an Ethereum request with an unknown field",
         qr.encode(json.dumps({"type": "cell-eth-tx", "chain_id": 1, "nonce": 0,
                               "max_priority_fee_per_gas": 1, "max_fee_per_gas": 2,
                               "gas_limit": 21000, "value": 0,
                               "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                               "data": "0xdeadbeef"}).encode())),
        ("an Ethereum request missing a field",
         qr.encode(json.dumps({"type": "cell-eth-tx", "chain_id": 1}).encode())),
    ]
    for label, fs in cases:
        dev, _ = make_device(presses=[CONFIRM] * 6, frames=fs)
        try:
            outcome = dev.run_once()
            survived = outcome in ("refused", "unknown-payload", "cancelled")
        except Exception as e:                                  # noqa: BLE001
            print(f"      raised {type(e).__name__}: {e}")
            survived = False
        check(f"refuses {label}", survived)
        check(f"...with a screen, not a traceback ({label[:28]})",
              survived and dev.display.screens
              and all(len(ln) <= ops.DISPLAY_COLS
                      for ln in dev.display.screens[-1]))

    # An incomplete transfer must be reported, not hung on.
    dev, _ = make_device(presses=[CONFIRM, CONFIRM], frames=frames[:-1])
    check("an incomplete scan is reported", dev.run_once() == "scan-failed")
    check("...in words", "SCAN FAILED" in dev.display.text())

    # ---- Ethereum -------------------------------------------------------
    print("\n ethereum")
    req = json.dumps({"type": "cell-eth-tx", "chain_id": 1, "nonce": 3,
                      "max_priority_fee_per_gas": 10**9,
                      "max_fee_per_gas": 25 * 10**9, "gas_limit": 21000,
                      "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                      "value": 10**17}).encode()
    d6, order6 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                             + [CONFIRM, CONFIRM],
                             frames=qr.encode(req))
    check("an Ethereum request is signed", d6.run_once() == "signed-eth")
    t6 = d6.display.text()
    check("the chain is named", "ETHEREUM" in t6.upper())
    check("the chain id is shown", "chain id 1" in t6)
    check("the nonce is shown", "nonce    3" in t6)
    check("the worst-case fee is shown", "max fee" in t6)
    check("amounts carry the chain's own ticker", "0.1 ETH" in t6)

    # A chain the owner registered renders under the name and denomination
    # they registered, not under a ticker the firmware assumed.
    eth.register_chain(137, "Polygon", "POL")
    req_pol = json.dumps({"type": "cell-eth-tx", "chain_id": 137, "nonce": 3,
                          "max_priority_fee_per_gas": 10**9,
                          "max_fee_per_gas": 25 * 10**9, "gas_limit": 21000,
                          "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                          "value": 10**17}).encode()
    d6b, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                         + [CONFIRM, CONFIRM],
                         frames=qr.encode(req_pol))
    check("a registered chain signs", d6b.run_once() == "signed-eth")
    t6b = d6b.display.text()
    check("...under its registered name", "POLYGON" in t6b.upper())
    check("...and its own ticker, not ETH", "0.1 POL" in t6b and "ETH" not in t6b)
    check("the raw transaction was emitted", len(d6.display.frames) > 0)
    raw = qr.decode(d6.display.frames)
    check("...and it is a typed EIP-1559 envelope", raw[0] == 0x02)

    # ---- multisig through the loop --------------------------------------
    print("\n multisig")
    se7 = SoftSE(pin=PIN)
    prov7 = wallet.provision(MNEMONIC, se7, PIN)
    ms, members = multisig_parts(root)
    prov7.register_multisig(ms)
    d7, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses() + [CONFIRM, CONFIRM],
                        frames=qr.encode(build_multisig_psbt(ms, members)),
                        se=se7, prov=prov7)
    check("a registered quorum signs", d7.run_once() == "signed-psbt")
    check("the quorum is on the confirmation screen",
          "MULTISIG 2 of 3" in d7.display.text())

    se8 = SoftSE(pin=PIN)
    prov8 = wallet.provision(MNEMONIC, se8, PIN)
    d8, order8 = make_device(presses=[CONFIRM] * 4,
                             frames=qr.encode(build_multisig_psbt(ms, members)),
                             se=se8, prov=prov8)
    check("an unregistered quorum is refused at the screen",
          d8.run_once() == "refused")
    check("...and never reached the gate", order8 == [])

    # ---- the tier still governs -----------------------------------------
    print("\n the gate still governs")
    d9, order9 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                             + [CONFIRM, CONFIRM],
                             frames=frames, policy=Policy(blood_above=1))
    d9.run_once()
    check("a spend above the floor demands blood", order9 == ["gate:BLOOD"])
    check("...and the owner is told what that means",
          "ten minutes" in d9.display.text())

    d10, order10 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                               + [CONFIRM, CONFIRM], frames=frames)
    d10.run_once()
    check("a small spend runs at touch", order10 == ["gate:TOUCH"])
    check("...and says so", "TOUCH REQUIRED" in d10.display.text())

    # ---- the read-only screens ------------------------------------------
    print("\n the screens that sign nothing")
    d11, order11 = make_device(presses=[UP, CONFIRM], frames=[])
    check("UP shows a receiving address", d11.run_once() == "address")
    addr_text = d11.display.text().replace("\n", "").replace(" ", "")
    expected = d11.prov.account_for("p2wpkh").xpub
    node = bip32.ExtendedKey.deserialize(expected).derive([0, 0])
    import addresses as addr_mod
    want = addr_mod.script_to_address(addr_mod.p2wpkh_script(node.pubkey))
    check("...and it is the address this seed derives", want in addr_text)
    check("...without unlocking anything", order11 == [])

    d12, _ = make_device(presses=[DOWN, CONFIRM], frames=[])
    check("DOWN shows the device's public identity", d12.run_once() == "keys")
    check("...including the fingerprint",
          d12.prov.master_fingerprint.hex() in d12.display.text())


    # ---- the seam to the sensing half -----------------------------------
    # app.load_device wires the gates to the unlock chain. The gates return
    # rich result objects; the signer wants (passed, attestation). This is the
    # adapter, checked against the gates' REAL outputs rather than a mock,
    # because an adapter tested against its own idea of the shape is an
    # adapter that compiles and then fails on a bench.
    print("\n the seam to the gates")
    import blood_gate
    import calibrate
    import touch_gate

    ok_blood, att_blood = app.gate_result(
        blood_gate.evaluate(calibrate.synth_capture("genuine", 0)))
    check("a genuine blood capture is adapted as a pass", ok_blood is True)
    check("...carrying the gate scores the attestation hashes",
          "gate_scores" in att_blood and att_blood["gate_scores"])

    bad_blood, att_bad = app.gate_result(
        blood_gate.evaluate(calibrate.synth_capture("ketchup", 0)))
    check("a spoof is adapted as a failure", bad_blood is False)
    check("...with a message naming the gate that caught it",
          "message" in att_bad and len(att_bad["message"]) > 8)

    tth = touch_gate.TouchThresholds()
    red, ir, bore = touch_gate._synth("genuine", 0, tth)
    ok_touch, att_touch = app.gate_result(
        touch_gate.evaluate(red, ir, bore, tth, fs=tth.fs))
    check("a genuine touch capture is adapted as a pass", ok_touch is True)
    # The two tiers name their measurements differently — blood reports
    # gate_scores, touch reports features — and liveness_digest reads both.
    # What matters is not the key but that the record commits to the capture.
    check("...carrying measurements under one of the names the digest reads",
          bool(att_touch.get("gate_scores") or att_touch.get("features")))

    red_f, ir_f, bore_f = touch_gate._synth("pump_fake", 0, tth)
    ok_fake, att_fake = app.gate_result(
        touch_gate.evaluate(red_f, ir_f, bore_f, tth, fs=tth.fs))
    check("a pumped silicone finger is adapted as a failure", ok_fake is False)
    check("...with a message for the owner", "message" in att_fake)

    # And the digest the attestation commits to must actually change with the
    # capture, or the record attests to nothing in particular.
    import signer as signer_mod
    from policy import Tier as _Tier
    d_a = signer_mod.liveness_digest(_Tier.BLOOD, att_blood)
    d_b = signer_mod.liveness_digest(
        _Tier.BLOOD,
        app.gate_result(blood_gate.evaluate(calibrate.synth_capture("genuine", 1)))[1])
    check("two blood captures attest to different measurements", d_a != d_b)

    # The same must hold for touch, or the touch tier's attestation would be a
    # signed boolean rather than a claim about a capture.
    red_b, ir_b, bore_b = touch_gate._synth("genuine", 1, tth)
    t_a = signer_mod.liveness_digest(_Tier.TOUCH, att_touch)
    t_b = signer_mod.liveness_digest(_Tier.TOUCH, app.gate_result(
        touch_gate.evaluate(red_b, ir_b, bore_b, tth, fs=tth.fs))[1])
    check("two touch captures attest to different measurements", t_a != t_b)
    check("and a touch digest is not a blood digest", t_a != d_a)

    # The thresholds the device loads must be the ones it evaluates against.
    check("both gates expose the load() the device build calls",
          hasattr(blood_gate.Thresholds, "load")
          and hasattr(touch_gate.TouchThresholds, "load"))
    check("touch thresholds carry the capture parameters the adapter uses",
          hasattr(tth, "duration_s") and hasattr(tth, "fs"))

    # ---- the two tiers read their OWN calibration file -------------------
    print("\n each tier loads its own thresholds")
    import json as _json
    import tempfile as _tempfile
    from pathlib import Path as _Path
    with _tempfile.TemporaryDirectory() as _td:
        _d = _Path(_td)
        # A realistic pair: blood's file carries its 600 s capture length,
        # touch's carries a swept contact window.
        (_d / "thresholds.json").write_text(_json.dumps(
            {"duration_s": 600.0, "sam_cos_min": 0.997}))
        (_d / "touch_thresholds.json").write_text(_json.dumps(
            {"duration_s": 15.0, "dc_min": 0.11, "dc_max": 0.77}))

        _bt = blood_gate.Thresholds.load(_d / "thresholds.json")
        _tt = touch_gate.TouchThresholds.load(_d / "touch_thresholds.json")
        check("blood loads its own sweep", _bt.sam_cos_min == 0.997)
        check("touch loads its own sweep",
              _tt.dc_min == 0.11 and _tt.dc_max == 0.77)
        check("...and keeps its 15 s session, not blood's 600 s",
              _tt.duration_s == 15.0)

        # The bug this guards: handing blood's file to the touch loader. The
        # two dataclasses share exactly one field name, so every touch
        # threshold in it is dropped and duration_s crosses over -- a
        # ten-minute finger-hold, evaluated against shipped defaults.
        _crossed = touch_gate.TouchThresholds.load(_d / "thresholds.json")
        check("blood's file is NOT a valid source of touch thresholds",
              _crossed.duration_s != _tt.duration_s
              and _crossed.dc_min != _tt.dc_min)

        # cal_hash must commit to both, or the tier that signs most often is
        # the tier the attestation says nothing about.
        _h_both = blood_gate.calibration_hash(
            _d / "thresholds.json", _d / "touch_thresholds.json")
        _h_blood_only = blood_gate.calibration_hash(_d / "thresholds.json")
        check("the calibration hash covers both threshold sets",
              _h_both != _h_blood_only and len(_h_both) == 32)
        (_d / "touch_thresholds.json").write_text(_json.dumps({"dc_min": 0.5}))
        check("...so a changed touch sweep changes the attested hash",
              blood_gate.calibration_hash(
                  _d / "thresholds.json",
                  _d / "touch_thresholds.json") != _h_both)

    # ---- the empty bore is read BEFORE the finger is on the ring ---------
    print("\n touch reads the empty bore first")

    class _OrderingSensor(touch_gate.TouchSensor):
        """Records the order the gate drives it in.

        T1 is mean(red) / bore_red. A bore reference taken after the capture
        is taken through the finger, the ratio lands near 1, and the contact
        gate rejects every session -- genuine ones included. Nothing in the
        synthetic panel catches that, because _synth hands back a constant
        bore, so the order is asserted directly.
        """

        def __init__(self):
            self.calls = []

        def read_ppg(self, duration_s, fs):
            self.calls.append("ppg")
            r, i, _b = touch_gate._synth("genuine", 0, tth)
            return r, i, tth.fs

        def read_bore_reference(self):
            self.calls.append("bore")
            return (1.0, 1.0)

    _os = _OrderingSensor()
    _res = touch_gate.authorize(_os, tth)
    check("authorize reads the bore before the capture",
          _os.calls == ["bore", "ppg"])
    check("...and still accepts a genuine capture", _res.accepted is True)

    # ---- the tier floor prices everything that leaves the wallet ---------
    print("\n the tier floor prices the whole spend")
    from policy import Policy as _Policy, Tier as _T2
    import policy as _policy

    # blood above 0.1 BTC. The attack is a PSBT whose DESTINATION amount sits
    # under the floor while the value actually leaves via the fee, or via an
    # output the host labelled change and this wallet cannot derive.
    _pol = _Policy(blood_above=10_000_000)

    _honest = ops.BitcoinSpend(amount_sats=1_000, destination="bc1qx",
                               fee_sats=200)
    check("a small honest spend still runs at touch tier",
          _policy.decide(_pol, _honest.op_class(),
                         _honest.amount_for_policy()).tier_to_run is _T2.TOUCH)

    _fee_attack = ops.BitcoinSpend(amount_sats=1, destination="bc1qx",
                                   fee_sats=50_000_000)
    check("value routed through the fee escalates to blood",
          _policy.decide(_pol, _fee_attack.op_class(),
                         _fee_attack.amount_for_policy()).tier_to_run is _T2.BLOOD)

    _change_attack = ops.BitcoinSpend(
        amount_sats=1, destination="bc1qx", fee_sats=200,
        unverified_sats=50_000_000, unverified_address="bc1qattacker")
    check("value routed through an underivable 'change' output escalates",
          _policy.decide(_pol, _change_attack.op_class(),
                         _change_attack.amount_for_policy()).tier_to_run
          is _T2.BLOOD)

    _real_change = ops.BitcoinSpend(
        amount_sats=1_000, destination="bc1qx", fee_sats=200,
        change_sats=50_000_000)
    check("change the wallet DID derive does not escalate — it comes back",
          _policy.decide(_pol, _real_change.op_class(),
                         _real_change.amount_for_policy()).tier_to_run
          is _T2.TOUCH)

    _eth = ops.EthereumSpend(amount_wei=1, destination="0xabc", chain_id=1,
                             chain_name="Ethereum", nonce=0,
                             max_fee_wei=50_000_000, ticker="ETH")
    check("an Ethereum fee cap is priced too, as the screen's MOST line is",
          _policy.decide(_pol, _eth.op_class(),
                         _eth.amount_for_policy()).tier_to_run is _T2.BLOOD)

    # ---- every screen fits the panel ------------------------------------
    print("\n every screen fits")
    over = []
    for dev in (d, d2, d4, d5, d6, d7, d9, d11, d12):
        for s in dev.display.screens:
            if len(s) > ops.DISPLAY_ROWS or any(len(ln) > ops.DISPLAY_COLS for ln in s):
                over.append(s)
    check("no screen anywhere overflowed the display", not over)
    if over:
        print(f"      first offender: {over[0]!r}")

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
