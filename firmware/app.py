"""The device, as a person uses it.

Everything below this file is a component. This is the order they run in when
somebody picks the thing up, and — like signer.py one layer down — the order
is the security property, not an implementation detail.

    scan -> parse -> summarise -> DISPLAY -> confirm -> PIN -> gate -> sign -> emit

Four rules govern it, and each is here because the obvious alternative fails:

  NOTHING IS UNLOCKED TO READ A TRANSACTION.  The summary the owner approves is
      computed from the watch-only account xpubs recorded at provisioning. The
      seed stays encrypted until after the gate. So a hostile PSBT gets as far
      as the screen and no further, and it never meets a private key at all.

  THE OWNER SEES IT BEFORE THEY PAY FOR IT.  Rendering happens before the PIN
      and long before the lancet. An operation that cannot be displayed is
      refused while it is still free to refuse it — nobody should bleed for a
      transaction the device then declines to show them.

  ONE OPERATION PER SCAN.  The device returns to idle after every signature.
      There is no batch mode and no "sign the rest of these": every signature
      costs one physical act, which is the entire argument of the product.

  A REFUSAL IS A SCREEN, NOT A TRACEBACK.  Every failure path ends at
      `_fail()`, which shows the owner what was refused and why in words. A
      device that drops to a Python traceback has told an owner nothing and
      has taught them to power-cycle and retry, which is how people learn to
      click through warnings.

The whole loop is written against protocols — Display, Buttons, Camera,
SecureElement — so `run_once()` can be driven end to end on a laptop with
fakes. `test_app.py` does exactly that.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable

import addresses
import bip32
import buttons as btn
import camera as cam
import eth
import ops
import psbt as psbtmod
import qr
import signer
import wallet
from display import Display
from policy import Policy, Tier
from se import PinLockout, SecureElement
from wallet import Provisioning, WalletError

PIN_LENGTH = 6
VERSION = "0.7"


class Abort(Exception):
    """The owner backed out. Not an error, and never reported as one."""


@dataclass
class Device:
    """Everything the loop needs, injected so it can be driven by fakes."""

    prov: Provisioning
    se: SecureElement
    display: Display
    buttons: btn.Buttons
    camera: cam.Camera
    run_gate: Callable[[Tier], tuple[bool, dict]]
    policy: Policy
    fw_hash: bytes
    cal_hash: bytes
    network: str = "mainnet"
    sleep: Callable[[float], None] = lambda _s: None
    # Injected so the tests can drive the confirmation guard, which measures
    # how long a screen has been up before it will accept consent. Faking the
    # clock is how that guard gets tested; weakening it would be how it stops
    # being one.
    clock: Callable[[], float] = time.monotonic

    # ---- screens ----

    def _screen(self, title: str, body: list[str], footer: str = "") -> None:
        lines = [title, ""] + body
        if footer:
            lines += ["", footer]
        self.display.show(lines)

    def _fail(self, reason: str, detail: str = "") -> None:
        """Show a refusal in words, and wait for the owner to acknowledge it.

        Wrapped rather than truncated: a refusal the owner cannot read is a
        refusal they will work around.
        """
        body = ops.wrap_full(detail, ops.DISPLAY_COLS, indent="  ") if detail else []
        # Leave room for the title, the blank, and the footer.
        room = ops.DISPLAY_ROWS - 5
        if len(body) > room:
            body = body[:room - 1] + ["  ..."]
        self._screen(reason.upper()[:ops.DISPLAY_COLS], body, "CONFIRM to continue")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)

    def _note(self, title: str, *body: str) -> None:
        self._screen(title, [f"  {b}" for b in body])

    # ---- the loop ----

    def idle(self) -> None:
        fp = self.prov.master_fingerprint.hex()
        quorums = len(self.prov.multisig)
        self._screen(f"CELL {VERSION}", [
            f"  wallet   {fp}",
            f"  network  {self.network}",
            f"  quorums  {quorums} registered" if quorums else "  quorums  none",
            f"  tier     {self.policy.describe()}"
            if hasattr(self.policy, "describe") else "",
            "",
            "  CONFIRM  scan a transaction",
            "  UP       show a receiving address",
            "  DOWN     show this device's keys",
        ], "")

    def run_once(self) -> str:
        """One trip round the loop. Returns a short outcome for the log/tests."""
        self.idle()
        press = self.buttons.wait(timeout=600.0)
        if press is None:
            return "idle"
        if press == btn.UP:
            return self.show_address()
        if press == btn.DOWN:
            return self.show_keys()
        if press != btn.CONFIRM:
            return "idle"
        try:
            return self.sign_flow()
        except Abort:
            self._note("CANCELLED", "Nothing was signed.")
            self.buttons.wait(timeout=30.0)
            return "cancelled"

    # ---- signing ----

    def sign_flow(self) -> str:
        self._screen("SCAN", ["  Hold the transaction QR in", "  front of the camera.",
                              "", "  BACK to stop"])
        try:
            payload = cam.scan(self.camera, display=self.display)
        except cam.CameraError as e:
            self._fail("scan failed", str(e))
            return "scan-failed"

        kind = classify(payload)
        if kind == "psbt":
            return self.sign_psbt(payload)
        if kind == "eth":
            return self.sign_eth(payload)
        self._fail("not something this device signs",
                   "The QR did not contain a PSBT or a CELL Ethereum request. "
                   "This device signs those two things and nothing else.")
        return "unknown-payload"

    def _pin(self) -> str:
        """Prompt for the PIN. Called by the signer at step 4, not before.

        The owner has already seen and confirmed the transaction by the time
        this runs — see signer.authorize_and_sign for why that ordering is not
        negotiable.
        """
        pin = btn.pin_entry(self.buttons, self.display, length=PIN_LENGTH)
        if pin is None:
            raise Abort()
        return pin

    def _confirm_screen(self, lines: list[str]) -> bool:
        return btn.confirm(self.buttons, lambda: self.display.show(lines),
                           clock=self.clock)

    def sign_psbt(self, payload: bytes) -> str:
        confirmed = {"ok": False}

        def confirm_cb(lines: list[str]) -> bool:
            confirmed["ok"] = self._confirm_screen(lines)
            return confirmed["ok"]

        def gate_cb(tier: Tier):
            self._gate_screen(tier)
            return self.run_gate(tier)

        try:
            result = wallet.sign_psbt(
                payload, self.prov, self.se, self.policy, self.fw_hash,
                self.cal_hash, confirm_cb, gate_cb, self._pin,
                network=self.network)
        except (psbtmod.BadPSBT, WalletError, ValueError) as e:
            self._fail("refused", str(e))
            return "refused"
        except signer.Refused as e:
            if not confirmed["ok"]:
                raise Abort() from None
            self._fail("refused", str(e))
            return "refused"
        except PinLockout as e:
            self._fail("device wiped", str(e))
            return "wiped"

        self._note("SIGNED", f"tier {result.tier.name}",
                   f"{result.signatures} input(s)",
                   "Show this to your coordinator.")
        self.sleep(1.0)
        cam.emit(self.display, result.psbt, sleep=self.sleep)
        self._note("DONE", f"psbt {qr.digest(result.psbt)}",
                   "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "signed-psbt"

    def sign_eth(self, payload: bytes) -> str:
        try:
            tx = parse_eth_request(payload)
        except (ValueError, eth.BadEthTransaction, addresses.BadAddress) as e:
            self._fail("refused", str(e))
            return "refused"

        confirmed = {"ok": False}

        def confirm_cb(lines: list[str]) -> bool:
            confirmed["ok"] = self._confirm_screen(lines)
            return confirmed["ok"]

        def gate_cb(tier: Tier):
            self._gate_screen(tier)
            return self.run_gate(tier)

        try:
            result = wallet.sign_eth(
                tx, self.prov, self.se, self.policy, self.fw_hash,
                self.cal_hash, confirm_cb, gate_cb, self._pin)
        except (WalletError, eth.BadEthTransaction, ValueError) as e:
            self._fail("refused", str(e))
            return "refused"
        except signer.Refused as e:
            if not confirmed["ok"]:
                raise Abort() from None
            self._fail("refused", str(e))
            return "refused"
        except PinLockout as e:
            self._fail("device wiped", str(e))
            return "wiped"

        self._note("SIGNED", f"tier {result.tier.name}", result.txid[:18] + "…")
        self.sleep(1.0)
        cam.emit(self.display, result.raw, sleep=self.sleep)
        self._note("DONE", "broadcast it from your", "companion", "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "signed-eth"

    def _gate_screen(self, tier: Tier) -> None:
        if tier is Tier.BLOOD:
            self._screen("BLOOD REQUIRED", [
                "  Insert a cartridge and lance",
                "  a fingertip into the well.",
                "",
                "  This takes ten minutes and",
                "  cannot be hurried.",
                "",
                "  SAFETY.md before your first",
                "  time.",
            ])
        else:
            self._screen("TOUCH REQUIRED", [
                "  Rest a fingertip on the ring",
                "  and hold still.",
                "",
                "  Fifteen seconds.",
            ])

    # ---- the read-only screens ----

    def show_address(self) -> str:
        try:
            acct = self.prov.account_for("p2wpkh", self.network)
        except WalletError as e:
            self._fail("no account", str(e))
            return "no-account"
        node = bip32.ExtendedKey.deserialize(acct.xpub).derive([0, 0])
        address = addresses.script_to_address(
            addresses.p2wpkh_script(node.pubkey), self.network)
        self._screen("RECEIVE", ["  first address, m/.../0/0", ""]
                     + ops.wrap_full(address, ops.DISPLAY_COLS, indent="  "),
                     "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "address"

    def show_keys(self) -> str:
        """The device's public identity, for a coordinator or a co-signer."""
        fp = self.prov.master_fingerprint.hex()
        try:
            attest_pub = self.se.attest_pubkey().hex()
        except Exception:                                       # noqa: BLE001
            attest_pub = "(unavailable)"
        self._screen("THIS DEVICE", [
            f"  fingerprint  {fp}",
            "  attestation key",
        ] + ops.wrap_full(attest_pub, ops.DISPLAY_COLS, indent="    ")[:4],
            "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "keys"


# --------------------------------------------------------------------------
# What came through the camera
# --------------------------------------------------------------------------


def classify(payload: bytes) -> str:
    """"psbt", "eth", or "unknown". Structure only — never a claim of intent."""
    if payload.startswith(psbtmod.PSBT_MAGIC):
        return "psbt"
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unknown"
    return "eth" if isinstance(doc, dict) and doc.get("type") == "cell-eth-tx" \
        else "unknown"


def parse_eth_request(payload: bytes) -> eth.EthTransaction:
    """Build the transaction from a request, refusing anything unexpected.

    The device builds the transaction itself from these fields and hashes what
    it built — it never accepts a digest or a pre-encoded transaction. A
    request carrying an unknown field is refused rather than ignored, on the
    same reasoning as `ops.parse`: a field the device does not understand is a
    field it cannot display, and therefore one the owner cannot consent to.
    """
    doc = json.loads(payload.decode("utf-8"))
    known = {"type", "chain_id", "nonce", "max_priority_fee_per_gas",
             "max_fee_per_gas", "gas_limit", "to", "value"}
    unknown = set(doc) - known
    if unknown:
        raise ValueError(
            f"refusing an Ethereum request with unknown field(s): "
            f"{', '.join(sorted(unknown))}")
    missing = known - set(doc)
    if missing:
        raise ValueError(
            f"the Ethereum request is missing {', '.join(sorted(missing))}")
    for name in ("chain_id", "nonce", "max_priority_fee_per_gas",
                 "max_fee_per_gas", "gas_limit", "value"):
        if not isinstance(doc[name], int) or isinstance(doc[name], bool):
            raise ValueError(f"{name} must be an integer")
    if not isinstance(doc["to"], str):
        raise ValueError("`to` must be an address string")
    return eth.EthTransaction(
        chain_id=doc["chain_id"], nonce=doc["nonce"],
        max_priority_fee_per_gas=doc["max_priority_fee_per_gas"],
        max_fee_per_gas=doc["max_fee_per_gas"], gas_limit=doc["gas_limit"],
        to=doc["to"], value=doc["value"])


# --------------------------------------------------------------------------


def load_device(directory: str, console: bool = False, **kw) -> Device:   # pragma: no cover
    """Assemble the real thing from a provisioned directory."""
    import hashlib
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import provision as prov_tool

    import blood_gate
    import touch_gate
    from display import open_display

    d = Path(directory)
    prov = prov_tool.load(d)

    if console:
        se = __import__("se").SoftSE(pin="000000")
    else:
        from se_atecc import ATECC608B
        se = ATECC608B()

    def run_gate(tier: Tier):
        import hardware
        head = hardware.RealSensorHead()
        try:
            if tier is Tier.BLOOD:
                return blood_gate.run(head)
            return touch_gate.run(hardware.RealTouchSensor(head))
        finally:
            head.close()

    fw_hash = hashlib.sha256(
        b"".join(sorted(p.read_bytes() for p in Path(__file__).parent.glob("*.py")))
    ).digest()
    cal = d / "thresholds.json"
    cal_hash = hashlib.sha256(cal.read_bytes() if cal.exists() else b"defaults").digest()

    return Device(prov=prov, se=se, display=open_display(console),
                  buttons=btn.open_buttons(console),
                  camera=cam.open_camera(console), run_gate=run_gate,
                  policy=Policy(), fw_hash=fw_hash, cal_hash=cal_hash, **kw)


def main() -> int:                                              # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="The CELL signing loop.")
    ap.add_argument("--dir", default="/boot/cell")
    ap.add_argument("--console", action="store_true",
                    help="run against stubs, for a dry run on a laptop")
    args = ap.parse_args()

    device = load_device(args.dir, console=args.console)
    while True:
        try:
            device.run_once()
        except KeyboardInterrupt:
            device.display.clear()
            return 0
        except Exception as e:                                  # noqa: BLE001
            # The loop never dies. A device that drops to a shell in front of
            # somebody holding a lancet has failed at the only job it has.
            device._fail("internal error", f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    raise SystemExit(main())
