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
import sys
import time
from dataclasses import dataclass
from typing import Callable

import addresses
import bip32
import duress
import eip712
import buttons as btn
import camera as cam
import eth
import link as lnk
import names
import ops
import psbt as psbtmod
import qr
import ur
import seedstore
import signer
import wallet
from display import Display
from policy import Policy, Tier
from se import PinLockout, SecureElement
from wallet import Provisioning, WalletError

# Eight digits are the input format. PIN-v2 charges a chip-counter use for
# each candidate derivation; the ten-attempt wipe remains firmware policy.
# See se_atecc.py and VALIDATION.md for the hardware validation requirements.
PIN_LENGTH = 8


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
    # None on a device that never enrolled its chamber. See
    # signer.unwrap_context: leaving it None derives exactly what such a
    # device has always derived, and a device that DID enrol cannot be
    # downgraded by dropping it, because its seed will not open.
    read_chamber: "Callable[[], bytes] | None" = None
    # A USB data path, on builds that have one. None on every build BUILD.md
    # section 1 describes, and that is the default. When it IS set it REPLACES
    # the camera rather than joining it: the Pi Zero has one data-capable USB
    # port, the QR webcam occupies it, and a dwc2 controller cannot be host and
    # peripheral at once. Read link.py before enabling this -- it gives up two
    # properties the camera build has, and neither is recoverable in firmware.
    link: "lnk.Link | None" = None
    # The real one. It used to default to a no-op, which is a test
    # convenience: load_device never overrode it, so on the device the SIGNED
    # screen was painted and replaced in the same instant and cam.emit ran its
    # animated output QR with no frame time at all -- flashing the signed
    # transaction past the receiving camera faster than it could latch a
    # frame, on the airgap's only way out.
    sleep: Callable[[float], None] = time.sleep
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
        body = [
            f"  wallet   {fp}",
            f"  network  {self.network}",
            # The firmware hash rather than a version string: it is what
            # co-signers register and what the attestation commits to, so it
            # is the identifier worth being able to read off the screen.
            f"  firmware {self.fw_hash[:4].hex()}",
            f"  quorums  {quorums} registered" if quorums else "  quorums  none",
        ]
        if hasattr(self.policy, "describe"):
            body.append(f"  tier     {self.policy.describe()}")
        self._screen("CELL", body + [
            "",
            "  CONFIRM  scan a transaction",
            "  UP       show a receiving address",
            "  DOWN     show this device's keys",
        ])

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
        try:
            transfer = self._receive()
        except cam.ScanCancelled:
            raise Abort() from None
        except (cam.CameraError, lnk.LinkError) as e:
            self._fail("scan failed", str(e))
            return "scan-failed"

        payload = transfer.payload
        # One route is chosen by the UR type rather than by the bytes, because
        # an EIP-4527 request is a CBOR map with no self-describing prefix for
        # `classify` to read. The type only ROUTES: every field in the request
        # is checked by the parser, exactly as it would be without a label.
        if transfer.ur_type == "eth-sign-request":
            return self.sign_eth_sign_request(payload, transfer)
        kind = classify(payload)
        if kind == "psbt":
            return self.sign_psbt(payload, transfer)
        if kind == "eth":
            return self.sign_eth(payload, transfer)
        if kind == "token":
            return self.sign_token(payload, transfer)
        if kind == "account-execute":
            return self.sign_account_execute(payload, transfer)
        if kind == "account-cancel":
            return self.sign_account_cancel(payload, transfer)
        if kind == "delegate":
            return self.sign_delegation(payload, transfer)
        self._fail("not something this device signs",
                   "The QR did not contain a PSBT or a CELL request. This "
                   "device signs a PSBT, an Ethereum transfer, an ERC-20 "
                   "transfer, a smart-account spend or cancel, and a "
                   "delegation.")
        return "unknown-payload"

    def _receive(self) -> cam.Transfer:
        """One request in, by whichever route this build has.

        Two screens rather than one, because the instruction differs and a
        wrong instruction is how an owner concludes the device is broken:
        "hold the QR up" in front of a build with no camera is advice nobody
        can follow.
        """
        if self.link is not None:
            self._screen("WAITING", ["  Send the transaction from your",
                                     "  companion over the cable.",
                                     "", "  BACK to stop"])
            return self.link.receive(buttons=self.buttons)
        self._screen("SCAN", ["  Hold the transaction QR in",
                              "  front of the camera.",
                              "", "  BACK to stop"])
        return cam.scan_transfer(self.camera, display=self.display,
                                 buttons=self.buttons)

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

    def _reply(self, payload: bytes, reply: cam.Transfer | None,
               ur_type: str | None = None) -> None:
        """Put the result on screen, framed the way the request arrived.

        A coordinator that speaks one dialect need not speak the other, so the
        reply mirrors the request rather than picking a favourite. `reply` is
        None when a flow is driven directly -- the tests do that -- and the
        default is the framing this device shipped with.

        `ur_type` overrides the mirroring, and exactly one flow needs it.
        EIP-4527 names the reply's type: a request arrives as
        `ur:eth-sign-request` and the answer is `ur:eth-signature`, so
        mirroring would send back a reply labelled as another request.
        """
        if reply is not None and reply.framing == cam.LINK:
            if self.link is None:
                # Unreachable: only the link produces this framing. Refusing
                # rather than falling back to a QR is deliberate -- a reply
                # silently rerouted to a screen nobody is pointing a camera at
                # is a signature the owner believes was delivered.
                raise WalletError(
                    "a request arrived over a link this device no longer has")
            self.link.send(payload)
            return
        if reply is None:
            cam.emit(self.display, payload, sleep=self.sleep,
                     framing=cam.UR if ur_type else cam.PNOFM,
                     ur_type=ur_type)
            return
        cam.emit(self.display, payload, sleep=self.sleep,
                 framing=cam.UR if ur_type else reply.framing,
                 ur_type=ur_type or reply.ur_type)

    def sign_psbt(self, payload: bytes,
                  reply: cam.Transfer | None = None) -> str:
        # "asked" as well as "ok". A signer.Refused raised BEFORE the
        # confirmation screen -- an unrenderable operation, a policy refusal,
        # a screen that does not fit -- also leaves "ok" False, and reporting
        # that as CANCELLED tells the owner they declined something they were
        # never shown, with no reason on screen to act on.
        confirmed = {"asked": False, "ok": False}

        def confirm_cb(lines: list[str]) -> bool:
            confirmed["asked"] = True
            confirmed["ok"] = self._confirm_screen(lines)
            return confirmed["ok"]

        def gate_cb(tier: Tier):
            self._gate_screen(tier)
            return self.run_gate(tier)

        try:
            result = wallet.sign_psbt(
                payload, self.prov, self.se, self.policy, self.fw_hash,
                self.cal_hash, confirm_cb, gate_cb, self._pin,
                network=self.network, read_chamber=self.read_chamber)
        except (psbtmod.BadPSBT, WalletError, ops.UnrenderableOperation,
                seedstore.SeedStoreError, duress.NoBlobOpened, ValueError) as e:
            self._fail("refused", str(e))
            return "refused"
        except signer.Refused as e:
            if confirmed["asked"] and not confirmed["ok"]:
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
        self._reply(result.psbt, reply)
        self._note("DONE", f"psbt {qr.digest(result.psbt)}",
                   "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "signed-psbt"

    def sign_token(self, payload: bytes,
                   reply: cam.Transfer | None = None) -> str:
        """An ERC-20 transfer. The same flow, a different parser.

        Everything past the parse is identical -- the same confirm callback,
        the same gate, the same eight-way except clause, the same raw
        transaction on the way out -- because an ERC-20 transfer IS an EIP-1559
        transaction. Only what the screen says differs, and that is decided in
        wallet.sign_eth from the transaction itself rather than here.
        """
        return self.sign_eth(payload, reply, parse=parse_token_request)

    def sign_eth_sign_request(self, payload: bytes,
                              reply: cam.Transfer | None = None) -> str:
        """An EIP-4527 request, which is what a browser wallet sends.

        The same flow again. What differs is that the transaction arrives
        ENCODED rather than as fields, so `eth.from_signing_payload` rebuilds
        it and re-encodes it before anything is displayed, and that the reply
        is an `eth-signature` rather than a raw transaction -- the companion
        assembles and broadcasts, exactly as it does for a smart account.
        """
        # The parsed request is kept rather than decoded a second time in the
        # envelope. Parsing is deterministic, so doing it twice would work --
        # and it would mean the id echoed back came from a second read of the
        # payload instead of from the one the owner's signature was checked
        # against.
        held: dict = {}

        def parse(raw: bytes):
            tx, req = parse_eth_sign_request(raw)
            self._check_request_is_ours(req)
            held["req"] = req
            return tx

        def envelope(_tx, result):
            return (ur.encode_eth_signature(held["req"]["request_id"],
                                            eth.signature_from_raw(result.raw)),
                    "eth-signature")

        return self.sign_eth(payload, reply, parse=parse, envelope=envelope)

    def _check_request_is_ours(self, req: dict) -> None:
        """Refuse a request aimed at a key this device does not hold.

        Neither field can widen anything -- `wallet.sign_eth` checks the
        derived address against the recorded account regardless, and fails
        closed if they differ. Both are here so the refusal happens BEFORE the
        owner spends a PIN attempt and a gate on a request that was never for
        them, and so the reason names what was expected.
        """
        want_path = wallet.eth_path(0, 0)
        if req["path"] != want_path:
            raise ValueError(
                f"this request asks for the key at {req['path']}, and this "
                f"device signs Ethereum at {want_path}. Nothing was signed.")
        if req["address"] is not None:
            claimed = addresses.to_checksum_address(req["address"].hex())
            mine = self.prov.eth_address()
            if claimed != mine:
                raise ValueError(
                    f"this request names {claimed}, and this device is "
                    f"{mine}. It was addressed to another wallet.")

    def sign_eth(self, payload: bytes,
                 reply: cam.Transfer | None = None, parse=None,
                 envelope=None) -> str:
        try:
            tx = (parse or parse_eth_request)(payload)
        except (ValueError, eth.BadEthTransaction, addresses.BadAddress) as e:
            self._fail("refused", str(e))
            return "refused"

        confirmed = {"asked": False, "ok": False}

        def confirm_cb(lines: list[str]) -> bool:
            confirmed["asked"] = True
            confirmed["ok"] = self._confirm_screen(lines)
            return confirmed["ok"]

        def gate_cb(tier: Tier):
            self._gate_screen(tier)
            return self.run_gate(tier)

        try:
            result = wallet.sign_eth(
                tx, self.prov, self.se, self.policy, self.fw_hash,
                self.cal_hash, confirm_cb, gate_cb, self._pin,
                read_chamber=self.read_chamber)
        except (WalletError, eth.BadEthTransaction,
                ops.UnrenderableOperation, seedstore.SeedStoreError,
                duress.NoBlobOpened, ValueError) as e:
            self._fail("refused", str(e))
            return "refused"
        except signer.Refused as e:
            if confirmed["asked"] and not confirmed["ok"]:
                raise Abort() from None
            self._fail("refused", str(e))
            return "refused"
        except PinLockout as e:
            self._fail("device wiped", str(e))
            return "wiped"

        out, out_type = (result.raw, None)
        if envelope is not None:
            out, out_type = envelope(tx, result)
        self._note("SIGNED", f"tier {result.tier.name}", result.txid[:18] + "…")
        self.sleep(1.0)
        self._reply(out, reply, ur_type=out_type)
        self._note("DONE", "broadcast it from your", "companion",
                   "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        if envelope is not None:
            return "signed-eth-request"
        return "signed-token" if tx.is_token_transfer else "signed-eth"

    @staticmethod
    def _envelope(kind: str, doc: dict, result) -> bytes:
        """What leaves the device after an EIP-712 or EIP-7702 signature.

        The EOA path emits a raw transaction, which is self-describing: it can
        be broadcast and nothing else is needed. A signature is not. Sixty-five
        bytes on their own do not say which account they authorise, on which
        chain, at which nonce, or through which of the two routes the account
        accepts -- and a relayer that has to be told those out of band is a
        relayer that can be told them wrong.

        So the fields the device DISPLAYED are the fields it emits, and the
        digest goes with them. A companion that rebuilds the digest from this
        envelope and gets a different answer knows the two disagree before it
        spends any gas finding out.
        """
        return json.dumps({
            "type": "cell-signature",
            "for": kind,
            "account": doc["account"],
            "chain_id": doc["chain_id"],
            "nonce": doc["nonce"],
            "signer": result.signer_address,
            "digest": result.digest,
            "signature": "0x" + result.signature.hex(),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _typed_flow(self, reply, parse, call, outcome: str, done: str,
                    kind: str) -> str:
        """The shared body of the three EIP-712 flows.

        They differ in the parser, the wallet call and the two lines of the
        DONE screen, and in nothing else that matters. Writing the confirm
        callback, the gate callback and the eight-way except clause out three
        times is three places for them to drift apart -- and the clause is the
        part that decides whether a refusal reaches the owner as a reason or
        as an internal error.

        WHAT COMES BACK IS A SIGNATURE, NOT A TRANSACTION. Every one of these
        signs an authorisation the companion relays: the device holds no gas
        and never learns whether it was submitted. So the QR is the signature
        and the DONE screen says who to give it to.
        """
        confirmed = {"asked": False, "ok": False}

        def confirm_cb(lines: list[str]) -> bool:
            confirmed["asked"] = True
            confirmed["ok"] = self._confirm_screen(lines)
            return confirmed["ok"]

        def gate_cb(tier: Tier):
            self._gate_screen(tier)
            return self.run_gate(tier)

        try:
            doc = parse()
        except (ValueError, eth.BadEthTransaction, addresses.BadAddress) as e:
            self._fail("refused", str(e))
            return "refused"

        try:
            result = call(doc, confirm_cb, gate_cb)
        except (WalletError, eip712.BadTypedData, eth.BadEthTransaction,
                ops.UnrenderableOperation, seedstore.SeedStoreError,
                duress.NoBlobOpened, ValueError) as e:
            self._fail("refused", str(e))
            return "refused"
        except signer.Refused as e:
            if confirmed["asked"] and not confirmed["ok"]:
                raise Abort() from None
            self._fail("refused", str(e))
            return "refused"
        except PinLockout as e:
            self._fail("device wiped", str(e))
            return "wiped"

        out = self._envelope(kind, doc, result)
        self._note("SIGNED", f"tier {result.tier.name}", done)
        self.sleep(1.0)
        self._reply(out, reply)
        self._note("DONE", f"sig {qr.digest(out)}",
                   "Give this to your relayer.", "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return outcome

    def sign_account_execute(self, payload: bytes,
                             reply: cam.Transfer | None = None) -> str:
        return self._typed_flow(
            reply,
            lambda: parse_account_execute(payload),
            lambda d, c, g: wallet.sign_account_execute(
                d["account"], d["to"], d["value"], d["nonce"], d["chain_id"],
                self.prov, self.se, self.policy, self.fw_hash, self.cal_hash,
                c, g, self._pin, read_chamber=self.read_chamber),
            "signed-account-execute", "smart-account spend",
            "cell-account-execute")

    def sign_account_cancel(self, payload: bytes,
                            reply: cam.Transfer | None = None) -> str:
        return self._typed_flow(
            reply,
            lambda: parse_account_cancel(payload),
            lambda d, c, g: wallet.sign_account_cancel(
                d["account"], d["tx_hash"], d["nonce"], d["chain_id"],
                self.prov, self.se, self.policy, self.fw_hash, self.cal_hash,
                c, g, self._pin, read_chamber=self.read_chamber),
            "signed-account-cancel", "queued tx cancelled",
            "cell-account-cancel")

    def sign_delegation(self, payload: bytes,
                        reply: cam.Transfer | None = None) -> str:
        return self._typed_flow(
            reply,
            lambda: parse_delegation(payload),
            lambda d, c, g: wallet.sign_delegation(
                d["account"], eip712.account(d["account"]).address, d["nonce"],
                d["chain_id"], self.prov, self.se, self.policy, self.fw_hash,
                self.cal_hash, c, g, self._pin,
                read_chamber=self.read_chamber),
            "signed-delegation", "delegation authorised", "cell-delegate")

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
            # Two screens, in this order, because the measurement needs it.
            # T1 decides "is a finger present" by dividing the capture's DC
            # level by the EMPTY-bore level, so the empty read has to happen
            # while the ring is still clear. Asking for the fingertip here
            # would put it on the ring before that read -- see
            # run_gate_on_hardware, which shows the second screen itself once
            # the bore reference is in hand.
            self._screen("TOUCH REQUIRED", [
                "  Keep the ring CLEAR for a",
                "  moment while the device reads",
                "  the empty port.",
                "",
                "  It will ask for your finger.",
            ])

    # ---- the read-only screens ----

    def show_address(self) -> str:
        """Where to receive. Single-sig, plus every quorum this device is in.

        Showing only the single-sig address was a quiet trap for exactly the
        owners who did the harder thing. A registered quorum's funds live at
        the multisig address, not at m/.../0/0, and an owner who read this
        screen and sent to what it showed would be funding a wallet none of
        their co-signers can spend from -- recoverable only by this one device,
        which is the property they set out to avoid.
        """
        try:
            acct = self.prov.account_for("p2wpkh", self.network)
        except WalletError as e:
            self._fail("no account", str(e))
            return "no-account"
        node = bip32.ExtendedKey.deserialize(acct.xpub).derive([0, 0])
        address = addresses.script_to_address(
            addresses.p2wpkh_script(node.pubkey), self.network)
        body = ["  single-sig, m/.../0/0", ""]
        body += ops.wrap_full(address, ops.DISPLAY_COLS, indent="  ")
        # The owner's own name for their own address, if they registered one.
        # A `.wei` or `.eth` name can publish a Bitcoin address too, and an
        # owner who published theirs wants to see the device agree that this is
        # the address behind it -- which is a check they can make here, once,
        # instead of on every payer's screen.
        mine = names.name_for(address)
        if mine:
            body.append(f"  {mine}")
        # Title, blank and the two footer rows come out of the same twenty.
        # display.show REFUSES a screen that does not fit rather than
        # truncating it, which is the right rule and makes an unbounded list
        # here a crash on the RECEIVE button rather than a scroll: three
        # registered quorums was enough.
        room = ops.DISPLAY_ROWS - 4
        shown = skipped = 0
        for desc in self.prov.descriptors(self.network):
            try:
                quorum = desc.address_at(0, 0, self.network)
            except Exception:                                   # noqa: BLE001
                # A descriptor that cannot produce an address is a registration
                # problem, not a reason to withhold the address above.
                continue
            block = ["", f"  {desc.label} ({desc.threshold} of {desc.n}), 0/0",
                     ""] + ops.wrap_full(quorum, ops.DISPLAY_COLS, indent="  ")
            # +1 keeps a row for the "n more" line this may need to add.
            if len(body) + len(block) + 1 > room:
                skipped += 1
                continue
            body += block
            shown += 1
        if skipped:
            body += ["", f"  {skipped} more quorum(s) not shown"]
        self._screen("RECEIVE", body, "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "address"

    def show_keys(self) -> str:
        """The device's public identity, for a coordinator or a co-signer.

        The Ethereum address belongs here for the same reason the fingerprint
        does. It is what a co-signer needs in order to build a quorum this
        device is an owner of, and what the owner needs in order to register
        that quorum back on the device -- `register_smart_account` refuses an
        account whose owners do not include it. Without it on a screen the
        only way to learn it was to run the firmware on a laptop, which is the
        one place a hardware wallet's keys should not have to go.
        """
        fp = self.prov.master_fingerprint.hex()
        try:
            attest_pub = self.se.attest_pubkey().hex()
        except Exception:                                       # noqa: BLE001
            attest_pub = "(unavailable)"
        try:
            evm = self.prov.eth_address()
        except WalletError:
            evm = "(no eth account)"
        named = names.name_for(evm)
        self._screen("THIS DEVICE", [
            f"  fingerprint  {fp}",
            "  ethereum, same on every chain"
            + (f", as {named}" if named else ""),
        ] + ops.wrap_full(evm, ops.DISPLAY_COLS, indent="    ") + [
            "  attestation key",
        ] + ops.wrap_full(attest_pub, ops.DISPLAY_COLS, indent="    ")[:4] + [
            "",
            "  CONFIRM  export accounts as QR",
            "  BACK     return",
        ])
        self.buttons.drain()
        if self.buttons.wait(timeout=120.0) != btn.CONFIRM:
            return "keys"
        return self.export_accounts()

    def export_accounts(self) -> str:
        """Put the watch-only accounts on screen as a `ur:crypto-account`.

        A coordinator scans it and has every script type at once. It is the
        one thing this device emits that nobody asked it to sign, and it
        authorises nothing -- the same xpubs are already printed on the screen
        above, one character at a time.

        THE WARNING IS PART OF THE FEATURE. An account xpub reveals every
        address the wallet will ever use, forever, to whoever holds it. A
        coordinator on the owner's own machine is the ordinary case and a
        phone camera over somebody's shoulder is not, and the owner is the
        only one who can tell which room they are in.
        """
        try:
            body = self.prov.account_export()
        except WalletError as e:
            self._fail("cannot export", str(e))
            return "export-failed"
        self._screen("EXPORT ACCOUNTS", [
            "  This QR carries every account",
            "  xpub on this device.",
            "",
            "  It signs nothing. It also lets",
            "  whoever reads it see every",
            "  address you will ever use.",
            "",
            "  CONFIRM  show it",
            "  BACK     cancel",
        ])
        self.buttons.drain()
        if self.buttons.wait(timeout=120.0) != btn.CONFIRM:
            self._note("CANCELLED", "Nothing was shown.")
            self.buttons.wait(timeout=30.0)
            return "export-cancelled"
        cam.emit(self.display, body, sleep=self.sleep, framing=cam.UR,
                 ur_type="crypto-account")
        self._note("DONE", "Scan it into your coordinator.",
                   "CONFIRM to return")
        self.buttons.drain()
        self.buttons.wait(timeout=120.0)
        return "exported-accounts"


# --------------------------------------------------------------------------
# What came through the camera
# --------------------------------------------------------------------------


# The request types this device accepts through the camera, and the flow each
# one runs. Structure only: the type says which parser and which screen, and
# every field inside is still checked before anything is displayed.
REQUEST_TYPES = {
    "cell-eth-tx": "eth",                    # an EOA transaction, built here
    "cell-token-tx": "token",                # an ERC-20 transfer, also built here
    "cell-account-execute": "account-execute",   # a spend from a smart account
    "cell-account-cancel": "account-cancel",     # stop a queued transaction
    "cell-delegate": "delegate",                 # an EIP-7702 authorisation
}


def classify(payload: bytes) -> str:
    """One of REQUEST_TYPES' values, "psbt", or "unknown".

    Structure only — never a claim of intent.
    """
    if payload.startswith(psbtmod.PSBT_MAGIC):
        return "psbt"
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        # RecursionError as well: the camera is the whole input surface, and
        # `[` repeated a few hundred thousand times is a payload anybody can
        # hold up to it. json's decoder recurses on nesting.
        return "unknown"
    if not isinstance(doc, dict):
        return "unknown"
    return REQUEST_TYPES.get(doc.get("type"), "unknown")


def _request(payload: bytes, kind: str, known: set) -> dict:
    """Decode one JSON request and check its shape, or raise ValueError.

    Shared by the three smart-account parsers below, which differ only in
    their field list. Every one of them refuses an unknown field rather than
    ignoring it, on `ops.parse`'s reasoning: a field the device does not
    understand is a field it cannot display, and therefore one the owner
    cannot consent to.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except RecursionError:
        raise ValueError(
            "the request is nested too deeply to parse. This device signs a "
            "flat object with the fields below and nothing else.") from None
    if not isinstance(doc, dict):
        raise ValueError(f"the {kind} request is not an object")
    unknown = set(doc) - known - {"type"}
    if unknown:
        raise ValueError(
            f"refusing a {kind} request with unknown field(s): "
            f"{', '.join(sorted(unknown))}")
    missing = known - set(doc)
    if missing:
        raise ValueError(
            f"the {kind} request is missing {', '.join(sorted(missing))}")
    return doc


def _whole(doc: dict, *names: str) -> None:
    """Every named field must be a non-negative int. Booleans are not ints here.

    `True` passes isinstance(x, int) in Python and would sail through as the
    value 1 -- a nonce of `true` is a nonce of 1, silently, and the screen
    would show a number the request never said.
    """
    for name in names:
        v = doc[name]
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ValueError(f"{name} must be a non-negative whole number")


def parse_account_execute(payload: bytes) -> dict:
    """A spend from a registered smart account.

    The account is named by LABEL, never by address: the address, the domain
    and the timelock all come from the device's own registration, so a request
    cannot choose which account it is spending from. That is the whole reason
    `eip712.SmartAccount` is a record rather than a payload.
    """
    doc = _request(payload, "smart-account spend",
                   {"account", "to", "value", "nonce", "chain_id"})
    _whole(doc, "value", "nonce", "chain_id")
    for name in ("account", "to"):
        if not isinstance(doc[name], str):
            raise ValueError(f"`{name}` must be a string")
    return doc


def parse_account_cancel(payload: bytes) -> dict:
    """A cancel of one transaction the account's timelock is holding."""
    doc = _request(payload, "cancel",
                   {"account", "tx_hash", "nonce", "chain_id"})
    _whole(doc, "nonce", "chain_id")
    for name in ("account", "tx_hash"):
        if not isinstance(doc[name], str):
            raise ValueError(f"`{name}` must be a string")
    return doc


def parse_delegation(payload: bytes) -> dict:
    """An EIP-7702 authorisation for this device's own EOA.

    `account` names the registration; the address is read from it and checked
    against this device's own key before anything is signed. The request
    carries no address at all, because a 7702 signature does not commit to the
    address it delegates -- so an address in the payload would be a caption on
    a screen, not a fact about the signature.
    """
    doc = _request(payload, "delegation", {"account", "nonce", "chain_id"})
    _whole(doc, "nonce", "chain_id")
    if not isinstance(doc["account"], str):
        raise ValueError("`account` must be a string")
    return doc


def parse_eth_sign_request(payload: bytes) -> tuple[eth.EthTransaction, dict]:
    """Decode an EIP-4527 request and rebuild the transaction it carries.

    Two refusals matter more than the rest, and both are about what the format
    can carry that this device will not sign:

    ONLY A TYPED TRANSACTION. `dataType` 1 is a legacy encoding this device
    does not build, and 3 and 4 -- a personal message and EIP-712 typed data --
    are the blind-signing surface. A hex string presented as a message is how a
    Permit gets signed by somebody who believed they were logging in, and this
    device has no way to render one as a sentence. Refused by name, so the
    owner learns which it was.

    THE CHAIN IS NAMED ONCE. The request carries a `chainId` beside the
    payload, and the payload commits to its own. Only the inner one is signed,
    so a disagreement is refused instead of resolved: a device that trusted the
    outer field would display one network and sign for another.
    """
    req = ur.decode_eth_sign_request(payload)
    if req["data_type"] != ur.DATA_TYPE_TRANSACTION:
        what = ur.DATA_TYPES.get(req["data_type"],
                                 f"data type {req['data_type']}")
        raise ValueError(
            f"this request carries {what}. This device signs a typed "
            f"transaction, which it can render in full, and refuses messages "
            f"and typed data because it cannot.")
    tx = eth.from_signing_payload(req["sign_data"])
    if req["chain_id"] is not None and req["chain_id"] != tx.chain_id:
        raise ValueError(
            f"the request says chain {req['chain_id']} and the transaction it "
            f"carries is for chain {tx.chain_id}. Only the second is signed.")
    return tx, req


def parse_token_request(payload: bytes) -> eth.EthTransaction:
    """Build an ERC-20 transfer from a request, refusing anything unexpected.

    NO CALLDATA FIELD, DELIBERATELY. The request names a token, a recipient and
    an amount, and `eth.token_transfer` writes the 68 bytes. A request that
    could supply `data` would be a request that could supply any call at all,
    with the device reduced to checking whether it happened to look like a
    transfer -- and the difference between checking bytes and writing them is
    the difference between this operation and blind signing.

    `value` is absent for the same reason: it is always zero, an ERC-20
    transfer moves no native coin, and a field that can only hold one value is
    a field an attacker can only use wrongly.
    """
    doc = _request(payload, "ERC-20 transfer",
                   {"chain_id", "nonce", "max_priority_fee_per_gas",
                    "max_fee_per_gas", "gas_limit", "token", "to", "amount"})
    _whole(doc, "chain_id", "nonce", "max_priority_fee_per_gas",
           "max_fee_per_gas", "gas_limit", "amount")
    for name in ("token", "to"):
        if not isinstance(doc[name], str):
            raise ValueError(f"`{name}` must be an address string")
    return eth.token_transfer(
        chain_id=doc["chain_id"], nonce=doc["nonce"],
        max_priority_fee_per_gas=doc["max_priority_fee_per_gas"],
        max_fee_per_gas=doc["max_fee_per_gas"], gas_limit=doc["gas_limit"],
        token=doc["token"], to=doc["to"], amount=doc["amount"])


def parse_eth_request(payload: bytes) -> eth.EthTransaction:
    """Build the transaction from a request, refusing anything unexpected.

    The device builds the transaction itself from these fields and hashes what
    it built — it never accepts a digest or a pre-encoded transaction. A
    request carrying an unknown field is refused rather than ignored, on the
    same reasoning as `ops.parse`: a field the device does not understand is a
    field it cannot display, and therefore one the owner cannot consent to.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except RecursionError:
        raise ValueError(
            "the request is nested too deeply to parse. This device signs a "
            "flat object with the fields below and nothing else.") from None
    # JSON's top level is not necessarily an object: `4` and `[]` are both
    # valid documents, and iterating them raises TypeError, which is not in
    # the set app.sign_eth catches -- so a refusal became an "internal error"
    # screen. ops.parse makes the same check for the same reason.
    if not isinstance(doc, dict):
        raise ValueError("the Ethereum request is not an object")
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


def gate_result(result) -> tuple[bool, dict]:
    """Adapt a gate's own result object to what signer.py consumes.

    The gates return rich objects — every gate's score, the features behind
    them, and a message naming the specific failure. signer.py wants
    `(passed, attestation)`, where the attestation dict is hashed into the
    record so a co-signer can pin a claim to one capture rather than to a
    boolean. This is the only place those two shapes meet.

    `user_message` is carried through because a refusal that says "liveness
    failed" teaches the owner nothing; one that says which gate failed tells
    them whether to warm their hands or throw the cartridge away.
    """
    att = dict(result.attestation)
    if not result.accepted:
        att.setdefault("message", result.user_message())
    return bool(result.accepted), att


def run_gate_on_hardware(tier: Tier, directory,
                         ready=None) -> tuple[bool, dict]:  # pragma: no cover
    """Drive the sensor head for the tier the policy chose.

    Both tiers share one AS7341 and one bore, so the touch sensor is handed
    the head rather than opening the I2C bus a second time. Thresholds come
    from the calibration file if one is present — `Thresholds.load` falls back
    to the physics-derived defaults, and BUILD.md section 13 is the procedure
    for replacing them with values measured on your own hardware.
    """
    from pathlib import Path

    import blood_gate
    import hardware
    import touch_gate

    # Two tiers, two calibration files. They are separate because the sweeps
    # that write them are separate, and because the field names barely
    # overlap: handing blood's thresholds.json to TouchThresholds.load()
    # silently drops every touch threshold it contains and picks up the ONE
    # name the two dataclasses share -- duration_s, which is 600 s for blood
    # and 15 s for touch. That turns the everyday tier into a ten-minute
    # finger-hold running on shipped defaults. See BUILD.md section 13.
    blood_cal = Path(directory) / "thresholds.json"
    touch_cal = Path(directory) / "touch_thresholds.json"
    head = hardware.RealSensorHead()
    try:
        if tier is Tier.BLOOD:
            th = blood_gate.Thresholds.load(blood_cal) if blood_cal.exists() \
                else blood_gate.Thresholds()
            capture = blood_gate.acquire(head, th)
            return gate_result(blood_gate.evaluate(capture, th))

        th = touch_gate.TouchThresholds.load(touch_cal) if touch_cal.exists() \
            else touch_gate.TouchThresholds()
        sensor = hardware.RealTouchSensor(head)
        # The empty-bore reference FIRST, while the ring is still clear. T1
        # divides the capture's DC level by it to decide whether a finger is
        # present, so reading it after the capture reads it THROUGH the finger
        # and the ratio collapses to a number no window can accept.
        bore = sensor.read_bore_reference()
        # Only now is it safe to ask for the finger.
        if ready is not None:
            ready()
        # fs is a TARGET. The sensor reports what it achieved, and that is what
        # the evaluation must use, because every frequency-derived feature
        # scales with it.
        red, ir, fs = sensor.read_ppg(th.duration_s, th.fs)
        return gate_result(touch_gate.evaluate(red, ir, bore, th, fs=fs))
    finally:
        head.close()


def load_device(directory: str, console: bool = False, **kw) -> Device:   # pragma: no cover
    """Assemble the real thing from a provisioned directory."""
    import hashlib
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import provision as prov_tool

    from display import open_display

    d = Path(directory)
    prov = prov_tool.load(d)

    if console:
        se = __import__("se").SoftSE(pin="0" * PIN_LENGTH)
    else:
        from se_atecc import ATECC608B
        se = ATECC608B()

    # Hoisted out of the Device(...) call below so the gate can drive it. The
    # touch tier needs a second screen mid-capture: the empty-bore reference
    # is read first, and only then may the owner be asked for a fingertip.
    disp = open_display(console)

    def run_gate(tier: Tier):
        def ready():
            disp.show(["TOUCH REQUIRED", "",
                       "  Rest a fingertip on the ring",
                       "  and hold still.",
                       "",
                       "  Fifteen seconds."])
        return run_gate_on_hardware(tier, d, ready=ready)

    fw_hash = hashlib.sha256(
        b"".join(sorted(p.read_bytes() for p in Path(__file__).parent.glob("*.py")))
    ).digest()
    # Both threshold sets, via the helper that defines the ordering. Hashing
    # only thresholds.json attested to the blood tier's numbers and said
    # nothing about the touch tier's -- and the touch tier is the one that
    # authorises most signatures. blood_gate.calibration_hash covers both and
    # substitutes a sentinel for a file that is absent, so an uncalibrated
    # device stays distinguishable rather than unattestable.
    import blood_gate
    cal_hash = blood_gate.calibration_hash(d / "thresholds.json",
                                           d / "touch_thresholds.json")

    # The chamber binding, if this device enrolled one. Absent is the normal
    # state for a device provisioned before enrolment, and it is not a
    # downgrade: a seed wrapped with the chamber does not open without it, so
    # removing the helper turns the device into a brick rather than into an
    # unlocked one. provision.py enroll-chamber writes it.
    read_chamber = None
    chamber_file = d / prov_tool.CHAMBER
    if chamber_file.exists():
        import optical_puf
        helper = optical_puf.load_helper(str(chamber_file))

        def read_chamber():                                 # noqa: F811
            import hardware
            try:
                head = hardware.RealSensorHead()
            except Exception as e:                          # noqa: BLE001
                raise signer.ChamberUnavailable(
                    f"the sensor head did not start ({e}).") from None
            try:
                return optical_puf.chamber_reader(
                    head.read_chamber_burst, helper)()
            except optical_puf.PufError:
                # Answered, did not decode. The tamper signal -- passed
                # through untouched so signer.py reports it as one.
                raise
            except Exception as e:                          # noqa: BLE001
                # Could not read it at all. An open bay is the common case:
                # the laser interlock is wired through the cartridge switch,
                # so the diode is dead with the slot empty and EVERY unlock
                # needs the bay closed, touch tier included. BUILD.md 9.
                raise signer.ChamberUnavailable(
                    f"the chamber could not be read ({e}). Close the "
                    f"cartridge bay -- the laser interlock keeps the diode "
                    f"dead while it is open.") from None
            finally:
                head.close()

    # The network comes from the RECORD, not from Device's default. Every
    # account is filed under it, so a testnet device booting as mainnet finds
    # none of its own: RECEIVE says "no account" and signing dies in
    # _watch_root, both of which read as a broken provisioning rather than as
    # a boot that guessed.
    kw.setdefault("network", prov.network)
    return Device(prov=prov, se=se, display=disp,
                  read_chamber=read_chamber,
                  buttons=btn.open_buttons(console),
                  camera=cam.open_camera(console), run_gate=run_gate,
                  policy=Policy(), fw_hash=fw_hash, cal_hash=cal_hash, **kw)


def _fail_to_boot(args, err: Exception) -> int:            # pragma: no cover
    """Show why the device will not start, and stay showing it.

    Deliberately does not retry. Whatever is wrong with the card will still be
    wrong in a second, and a device flickering through a boot loop tells the
    owner less than one holding a sentence.
    """
    reason = str(err) or type(err).__name__
    try:
        from display import open_display
        disp = open_display(console=args.console)
        # Wrapped to the panel's width rather than trusted to fit: the reason
        # comes from a damaged file and could be any length, and a line that
        # runs off the screen is the half of the message that mattered.
        lines = ["CANNOT START", ""]
        for i in range(0, len(reason), 34):
            lines.append(reason[i:i + 34])
        lines += ["", "Seed is not lost.", "Restore from your backup words."]
        disp.show(lines)
    except Exception:                                           # noqa: BLE001
        # No screen either. The console is all that is left, so make it a
        # sentence rather than a stack trace.
        print(f"CELL cannot start: {reason}", file=sys.stderr)
        print("The seed is not lost. Restore from your backup words.",
              file=sys.stderr)
    return 2


def main() -> int:                                              # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="The CELL signing loop.")
    ap.add_argument("--dir", default="/boot/cell")
    ap.add_argument("--console", action="store_true",
                    help="run against stubs, for a dry run on a laptop")
    args = ap.parse_args()

    try:
        device = load_device(args.dir, console=args.console)
    except Exception as e:                                      # noqa: BLE001
        # load_device runs BEFORE the loop that exists so the device never
        # dies, and before a display exists to say anything on. A damaged
        # record therefore used to end as a traceback on a console nobody is
        # looking at, on a device that simply will not start.
        #
        # Bring the screen up on its own and put the reason on it. The seed is
        # not lost when this happens -- the record is public data and the
        # backup words still restore -- so the one thing the device must do is
        # say which failure this is instead of exiting silently.
        return _fail_to_boot(args, e)

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
