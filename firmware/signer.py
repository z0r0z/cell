"""CELL unlock chain — the sequence from an operation to a signature.

Everything else in this firmware is a component. This file is the order they
run in, and the order IS the security property. BUILD.md section 12 states it;
this is the executable form:

    1. parse and render         refuse anything unrenderable, before anything else
    2. policy decides the tier  the device chooses, never the operation
    3. owner confirms           physical CONFIRM press on its own GPIO
    4. PIN                      counter increments before compare; 10 -> wipe
    5. liveness gate            touch or blood, at the tier policy required
    6. unwrap                   KDF(PIN, liveness) -> AES key -> seed in RAM
    7. sign                     derive, sign, then zeroise immediately
    8. attest                   separate key signs the tier claim for this sighash

Three orderings are load-bearing and are asserted in the tests:

  RENDER BEFORE ANYTHING.        An operation the owner cannot read is refused
                                 before they spend a cartridge on it.

  CONFIRM BEFORE PIN.            The owner approves a specific transaction, not
                                 "a transaction". Taking the PIN first trains
                                 them to authenticate and then read, which is
                                 how people sign the wrong thing.

  GATE BEFORE UNWRAP.            No sample, no seed. The chain refuses above
                                 the unwrap step, and the order is asserted
                                 against EXPECTED_ORDER rather than described
                                 in prose, so a refactor that reorders it
                                 fails loudly.

  MEASUREMENTS IN THE RECORD.    The attestation commits to the gate's actual
                                 numbers, so "signed at blood tier" is a claim
                                 a co-signer can check against one specific
                                 capture — not a boolean, and not a promise
                                 the device makes about itself.

The wrapping key comes from stable inputs only: the PIN and the on-chip secret
that never leaves the ATECC608B. That is what makes a seed blob copied off the
SD card inert, and what makes the seed recoverable on the same device tomorrow.
Liveness proves itself in the signed record, where a third party can verify it
— see `unwrap_context()` and `liveness_digest()` for why that split is the one
that holds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

import attest
import ops
import policy
from policy import Policy, Tier
from se import PinLockout, SecureElement


class Refused(Exception):
    """The device declined to sign. Carries the reason shown to the owner."""


@dataclass
class SignRequest:
    operation: ops.Operation
    sighash: bytes                      # 32, what the wallet layer will sign
    requested_tier: Optional[Tier] = None


@dataclass
class SignResult:
    signature: bytes
    attestation: attest.Attestation
    tier: Tier
    display: list[str] = field(default_factory=list)

    def psbt_proprietary_field(self) -> tuple[bytes, bytes]:
        """(key, value) for the BIP-174 proprietary field, prefix "CELL".

        Travels beside the PSBT and is stripped before broadcast. Publishing it
        on chain fingerprints the address as a CELL device and discloses how it
        was authorised, so that is a deliberate choice and never a default.
        """
        return b"CELL" + bytes([attest.VERSION]), self.attestation.pack()


def liveness_digest(tier: Tier, gate_attestation: dict) -> bytes:
    """Compress a gate result into 32 bytes for the ATTESTATION.

    The gate's own measurements go in — not merely "it passed" — so the record
    commits to the capture that actually produced them, and a co-signer can
    pin a claim to one specific sample rather than to a boolean.

    This deliberately does NOT feed key derivation. A wrapping key has to be
    the same key tomorrow, and a liveness measurement is a fresh physical event
    with no reproducibility at all — that is the entire point of the device.
    Mixing it into the KDF produces a key that can never reopen the seed it
    wrapped. A fuzzy extractor does not rescue this either: those need a
    repeatable trait with bounded noise, and a clotting curve is a one-time
    event, not a trait.

    It never feeds a signing nonce either. A nonce derived from a biometric
    measurement leaks the private key. Field entropy touches BIP-340 aux_rand
    only, where the construction degrades gracefully even if an attacker
    controls it fully.
    """
    parts = [tier.name.encode()]
    for k in sorted(gate_attestation.get("gate_scores", {})):
        parts.append(f"{k}={gate_attestation['gate_scores'][k]:.6f}".encode())
    for k in sorted(gate_attestation.get("features", {})):
        parts.append(f"{k}={gate_attestation['features'][k]:.6f}".encode())
    return hashlib.sha256(b"|".join(parts)).digest()


def unwrap_context(pin: str) -> bytes:
    """Context for the seed-wrapping KDF. STABLE INPUTS ONLY.

    The PIN, and through `SecureElement.kdf` the on-chip secret that never
    leaves the ATECC608B. A seed blob copied off the SD card is inert without
    both: the right PIN and that specific chip.

    Nothing else may go in here, and two things that look tempting are wrong:

      the liveness digest  changes on every capture, so the key that wrapped
                           the seed could never unwrap it again
      the sighash          changes on every transaction, and the signature
                           already commits to it cryptographically — putting
                           it here creates per-transaction key material that
                           protects nothing and breaks recovery

    Liveness is not key material. It is an authorisation on the release path,
    enforced by the order of the unlock chain, and it is PROVEN to third
    parties by the signed attestation, which commits to the gate measurements
    via liveness_digest(). On a Pi with no secure boot that enforcement is a
    firmware property, not a cryptographic one — the same trust boundary the
    attestation already declares through the firmware hash and the tamper
    seal. BUILD.md section 16.
    """
    return hashlib.sha256(b"CELL/unwrap/v1|"
                          + hashlib.sha256(pin.encode()).digest()).digest()


def zeroise(buf: bytearray) -> None:
    """Overwrite key material in place.

    Python cannot guarantee this the way explicit_bzero can — the interpreter
    may have copied the bytes elsewhere. A bytearray at least gives one buffer
    that is definitely cleared, which is why seed material is handled as a
    mutable buffer and never as a str or bytes.
    """
    for i in range(len(buf)):
        buf[i] = 0


class Signer:
    """Orchestrates one signing operation, in order, with no shortcuts.

    Collaborators are injected so every step is testable and swappable:
      confirm     (lines) -> bool               blocks on the CONFIRM button
      run_gate    (Tier) -> (bool, dict)        touch_gate or blood_gate
      unwrap_seed (key) -> bytearray            AES-GCM open of the stored seed
      sign_digest (seed, sighash) -> bytes      derive and sign
    """

    def __init__(self, se: SecureElement, pol: Policy, fw_hash: bytes,
                 cal_hash: bytes,
                 confirm: Callable[[list[str]], bool],
                 run_gate: Callable[[Tier], tuple[bool, dict]],
                 unwrap_seed: Callable[[bytes], bytearray],
                 sign_digest: Callable[[bytearray, bytes], bytes]):
        if len(fw_hash) != 32:
            raise ValueError("fw_hash must be 32 bytes")
        if len(cal_hash) != 32:
            raise ValueError("cal_hash must be 32 bytes")
        self.se, self.policy, self.fw_hash = se, pol, fw_hash
        # Read once at construction, not per signing. Re-reading the threshold
        # files mid-session would let a file swapped underneath the process
        # attest to whichever set it liked.
        self.cal_hash = cal_hash
        self._confirm, self._run_gate = confirm, run_gate
        self._unwrap_seed, self._sign_digest = unwrap_seed, sign_digest
        self.trace: list[str] = []       # step order, asserted in the tests

    def _step(self, name: str) -> None:
        self.trace.append(name)

    def authorize_and_sign(self, req: SignRequest, pin: str) -> SignResult:
        self.trace = []

        # 1. Render first. An operation the owner cannot read is refused before
        #    they spend a lancet, a cartridge, or ten minutes on it.
        self._step("render")
        try:
            # Reserve the rows the confirmation footer will occupy, so an
            # operation cannot render to a full screen and then push the tier
            # disclosure off the bottom.
            display = ops.render_for_display(
                req.operation, reserve=ops.CONFIRM_FOOTER_ROWS)
        except ops.UnrenderableOperation as e:
            raise Refused(f"Refused: {e}") from None
        if len(req.sighash) != 32:
            raise Refused("Refused: sighash must be 32 bytes")

        # 2. The DEVICE picks the tier. The operation never gets a say; the
        #    owner may only escalate.
        self._step("policy")
        decision = policy.decide(self.policy, req.operation.op_class(),
                                 req.operation.amount_for_policy(),
                                 req.requested_tier)
        if not decision.permitted:
            raise Refused(f"Refused: {decision.reason}")
        tier = decision.tier_to_run

        # 3. Confirm THIS transaction, before authenticating.
        self._step("confirm")
        shown = display + ["", f"requires {tier.name}", decision.reason]
        # Validate what is ACTUALLY shown. The reason string comes from policy
        # and an operation class the wallet layer is free to name, so its width
        # is not knowable at render time.
        try:
            ops.check_fits(shown)
        except ops.UnrenderableOperation as e:
            raise Refused(f"Refused: confirmation screen does not fit: {e}") from None
        if not self._confirm(shown):
            raise Refused("Cancelled at confirmation.")

        # 4. PIN. Counter increments before compare; exhaustion wipes.
        self._step("pin")
        try:
            if not self.se.verify_pin(pin):
                raise Refused(f"Wrong PIN. {self.se.attempts_remaining()} "
                              f"attempts remaining before wipe.")
        except PinLockout as e:
            raise Refused(f"Device wiped: {e}") from None

        # 5. Liveness, at the tier policy chose.
        self._step("gate")
        passed, gate_att = self._run_gate(tier)
        if not passed:
            raise Refused(gate_att.get("message", "Liveness gate rejected the sample."))

        # 6. Unwrap. The key comes from stable inputs only — PIN plus the
        #    on-chip secret — because a key mixed with this capture's
        #    measurements could never reopen the seed it wrapped. What the
        #    gate gates is REACHING this step at all: the chain refuses above,
        #    and EXPECTED_ORDER is asserted in the tests.
        self._step("unwrap")
        live = liveness_digest(tier, gate_att)
        key = self.se.kdf(unwrap_context(pin))
        seed = self._unwrap_seed(key)

        # 7. Sign, then zeroise on every path.
        self._step("sign")
        try:
            signature = self._sign_digest(seed, req.sighash)
        finally:
            zeroise(seed)
            self._step("zeroise")

        # 8. Attest the tier, bound to this sighash and a fresh counter.
        self._step("attest")
        counter = self.se.increment_counter()
        # The measurements travel in the record, so the claim is bound to one
        # capture rather than to a boolean somebody could have flipped.
        att = attest.attest(tier, counter, req.sighash, self.fw_hash,
                            self.cal_hash, live, self.se.attest_sign,
                            self.se.attest_pubkey())

        return SignResult(signature=signature, attestation=att, tier=tier,
                          display=display)


# The order every successful signing follows. The tests assert against this
# rather than against a prose description, so a refactor that reorders the
# chain fails loudly instead of quietly.
EXPECTED_ORDER = ["render", "policy", "confirm", "pin", "gate",
                  "unwrap", "sign", "zeroise", "attest"]
