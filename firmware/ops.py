"""CELL operation set — what the device is willing to sign, and how it says so.

The rule this file exists to enforce:

    IF THE DEVICE CANNOT RENDER AN OPERATION AS A SENTENCE A HUMAN CAN READ,
    IT DOES NOT SIGN IT.

A device that displays `0x9a3f...` and asks for blood is worse than one that
refuses, because it converts a deliberate physical act into a rubber stamp on
something the owner cannot evaluate. The blood gate proves a human chose to
sign. That proof is worth nothing if the human could not tell what they chose.

So the operation set is CLOSED. Four spending shapes, all renderable:

    BitcoinSpend   amount, destination, fee, and where the change goes
    NoteSpend      a confidential note, its amount, the recipient owner
    DirectTransfer a transfer to a named pubkey on either chain
    EthereumSpend  an EIP-1559 transfer, with the chain, nonce and fee cap

Everything else is refused, including generic EVM calldata and bare hashes.
This is a scope decision — see BUILD.md section 5.

The renderer is the security control here. Every field that
changes what the signature authorises appears in the rendered text, so what the
owner confirms and what the device signs cannot diverge. `render()` on a class
that forgot a field is a bug of the same severity as a signing bug.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class UnrenderableOperation(Exception):
    """Raised when an operation cannot be shown to the owner in full.

    Always a refusal to sign. Never downgrade this to a warning: the whole
    value of the gate is that the person who bled understood the transaction.
    """


# --------------------------------------------------------------------------
# Amount formatting
#
# Displayed amounts are the thing the owner checks hardest, so they are
# formatted exactly and never rounded. A truncated amount on screen is a
# signature on a number the owner did not read.
# --------------------------------------------------------------------------

SATS_PER_BTC = 100_000_000
WEI_PER_ETH = 10**18

# ST7789 240x240 with a 6x12 font is 40 columns by 20 rows. Both are hard
# limits: a line that overflows is a field the owner did not read, and a screen
# that scrolls is a field they may not have scrolled to.
DISPLAY_COLS = 40
DISPLAY_ROWS = 20


def format_btc(sats: int) -> str:
    if sats < 0:
        raise ValueError("negative amount")
    whole, frac = divmod(sats, SATS_PER_BTC)
    return f"{whole}.{frac:08d} BTC"


def format_eth(wei: int) -> str:
    if wei < 0:
        raise ValueError("negative amount")
    whole, frac = divmod(wei, WEI_PER_ETH)
    return f"{whole}.{frac:018d}".rstrip("0").rstrip(".") + " ETH" if frac else f"{whole} ETH"


def wrap_full(value: str, width: int, indent: str = "           ") -> list[str]:
    """Show a value IN FULL, wrapped across lines. Never abbreviated.

    Abbreviation is where address substitution lives. Showing `bc1qxy...k4h9`
    means an attacker only has to match the visible ends, and prefix grinding
    is cheap enough that people have lost funds to exactly this. A destination
    address is the single field most worth attacking, so it gets shown whole
    even though it costs two lines of a twenty-line screen.

    If the result does not fit the display, render_for_display refuses rather
    than truncating.
    """
    room = max(1, width - len(indent))
    return [indent + value[i:i + room] for i in range(0, len(value), room)]


def truncate_middle(s: str, keep: int = 8) -> str:
    """Shorten an opaque identifier — a note commitment, never an address.

    Only for values the owner cannot meaningfully verify character by character
    anyway. Anything the owner must check against another screen gets
    wrap_full().
    """
    return s if len(s) <= 2 * keep + 3 else f"{s[:keep]}...{s[-keep:]}"


# --------------------------------------------------------------------------
# The operation set
# --------------------------------------------------------------------------


@runtime_checkable
class Operation(Protocol):
    """Every operation renders itself in full and names its policy class."""

    def op_class(self) -> str:
        """Policy class, e.g. "tx.send". See policy.ALWAYS_BLOOD."""

    def amount_for_policy(self) -> int:
        """Value moved, in the smallest unit of its chain, for the tier floor."""

    def render(self) -> list[str]:
        """Lines to display. Must include every field that changes what the
        signature authorises."""


@dataclass(frozen=True)
class BitcoinSpend:
    """A Bitcoin spend the owner can check line by line.

    `change_is_ours` is carried explicitly and displayed. A change output the
    wallet cannot prove it owns is the classic way to lose a balance while the
    displayed 'amount' looks correct, so an unverified change output is shown
    as a warning line rather than quietly folded into the fee.
    """

    amount_sats: int
    destination: str
    fee_sats: int
    change_sats: int = 0
    change_address: str = ""
    change_is_ours: bool = True
    # Multisig context, when the input is an m-of-n script. `quorum_needed`
    # and `quorum_size` come from the witness script and are trustworthy.
    # `signatures_present` is counted from the partial signatures already in
    # the PSBT, which the HOST assembled — so it is shown as progress and is
    # never a security control. What actually establishes that a quorum signed
    # at blood tier is attest.verify_quorum(), run by the coordinator against
    # registered keys. See BUILD.md section 4.
    quorum_needed: int = 0
    quorum_size: int = 0
    signatures_present: int = 0

    def op_class(self) -> str:
        return "tx.send"

    def amount_for_policy(self) -> int:
        return self.amount_sats

    def render(self) -> list[str]:
        if not self.destination:
            raise UnrenderableOperation("spend has no destination address")
        if self.amount_sats < 0 or self.fee_sats < 0 or self.change_sats < 0:
            raise UnrenderableOperation("negative amount, fee or change")
        lines = ["SEND BITCOIN",
                 f"  amount   {format_btc(self.amount_sats)}",
                 "  to"]
        lines += wrap_full(self.destination, DISPLAY_COLS)
        lines.append(f"  fee      {format_btc(self.fee_sats)}")
        if self.change_sats:
            if self.change_is_ours:
                lines.append(f"  change   {format_btc(self.change_sats)} -> your wallet")
            else:
                # The failure the owner must catch, given its own lines.
                lines.append(f"  change   {format_btc(self.change_sats)}")
                lines.append("  WARNING  change to an address this")
                lines.append("           wallet cannot prove it owns:")
                lines += wrap_full(self.change_address or "(none given)", DISPLAY_COLS)
        lines.append(f"  TOTAL    {format_btc(self.amount_sats + self.fee_sats)}")
        if self.quorum_size:
            if not 1 <= self.quorum_needed <= self.quorum_size:
                raise UnrenderableOperation(
                    f"nonsensical quorum {self.quorum_needed}/{self.quorum_size}")
            if not 0 <= self.signatures_present < self.quorum_size:
                raise UnrenderableOperation(
                    f"impossible signature count {self.signatures_present}")
            lines.append(f"  MULTISIG {self.quorum_needed} of {self.quorum_size}")
            lines.append(f"  YOU ARE  signature "
                         f"{self.signatures_present + 1} of {self.quorum_needed}")
        return lines


@dataclass(frozen=True)
class NoteSpend:
    """A confidential note spend.

    The note commitment is opaque by construction, so it is shown as a short
    identifier and the fields the owner can actually evaluate — amount and
    recipient owner — are shown in full.
    """

    note_id: str
    amount: int
    recipient_owner: str
    asset: str = "BTC"

    def op_class(self) -> str:
        return "note.spend"

    def amount_for_policy(self) -> int:
        return self.amount

    def render(self) -> list[str]:
        if not self.note_id or not self.recipient_owner:
            raise UnrenderableOperation("note spend missing note or recipient")
        if self.amount < 0:
            raise UnrenderableOperation("negative amount")
        amt = format_btc(self.amount) if self.asset == "BTC" else f"{self.amount} {self.asset}"
        # The note commitment is opaque by construction — there is nothing for
        # the owner to check it against, so it is abbreviated. The recipient
        # owner is a key they CAN check, so it is shown whole.
        lines = ["SPEND CONFIDENTIAL NOTE",
                 f"  note     {truncate_middle(self.note_id, 6)}",
                 f"  amount   {amt}",
                 "  owner"]
        return lines + wrap_full(self.recipient_owner, DISPLAY_COLS)


@dataclass(frozen=True)
class DirectTransfer:
    """A transfer to a pubkey on either chain.

    The device holds no gas and builds no transaction; it authorises a transfer
    and the companion submits it. There is no nonce here and no calldata,
    because there is nothing for the device to reason about that it could not
    also display.
    """

    amount: int
    recipient_pubkey: str
    chain: str = "BTC"

    def op_class(self) -> str:
        return "tx.send"

    def amount_for_policy(self) -> int:
        return self.amount

    def render(self) -> list[str]:
        if self.chain not in ("BTC", "ETH"):
            raise UnrenderableOperation(f"unknown chain {self.chain!r}")
        if not self.recipient_pubkey:
            raise UnrenderableOperation("transfer has no recipient")
        if self.amount < 0:
            raise UnrenderableOperation("negative amount")
        amt = format_btc(self.amount) if self.chain == "BTC" else format_eth(self.amount)
        return ([f"TRANSFER ({self.chain})", f"  amount   {amt}", "  to"]
                + wrap_full(self.recipient_pubkey, DISPLAY_COLS))


@dataclass(frozen=True)
class EthereumSpend:
    """An EIP-1559 value transfer, with every field the signature commits to.

    DirectTransfer above authorises a transfer in the abstract, for flows where
    a companion builds and submits the transaction. This class is different: it
    is what the device signs when it signs Ethereum itself, so it must carry
    the whole of what that signature authorises.

    That is why the chain, the nonce and the worst-case fee are here rather
    than hidden. A signature that does not pin the chain id replays on every
    other EVM chain the owner holds funds on. One that does not pin the nonce
    can be reordered against another. One that does not pin gas_limit ×
    max_fee_per_gas has no bound on what it costs. The owner cannot consent to
    a field they were not shown, so all of them are shown.

    Calldata is absent by construction, not by omission — eth.py refuses it.
    """

    amount_wei: int
    destination: str                # EIP-55 checksummed
    chain_id: int
    chain_name: str
    nonce: int
    max_fee_wei: int                # gas_limit * max_fee_per_gas, the worst case

    def op_class(self) -> str:
        return "tx.send"

    def amount_for_policy(self) -> int:
        return self.amount_wei

    def render(self) -> list[str]:
        if not self.destination:
            raise UnrenderableOperation("transfer has no destination")
        if self.amount_wei < 0 or self.max_fee_wei < 0 or self.nonce < 0:
            raise UnrenderableOperation("negative amount, fee or nonce")
        if not self.chain_name:
            raise UnrenderableOperation(
                f"chain {self.chain_id} has no name; the owner cannot tell "
                f"which network this lands on")
        lines = [f"SEND ON {self.chain_name.upper()}",
                 f"  amount   {format_eth(self.amount_wei)}",
                 "  to"]
        lines += wrap_full(self.destination, DISPLAY_COLS)
        lines.append(f"  max fee  {format_eth(self.max_fee_wei)}")
        lines.append(f"  chain id {self.chain_id}")
        lines.append(f"  nonce    {self.nonce}")
        lines.append(f"  MOST     {format_eth(self.amount_wei + self.max_fee_wei)}")
        return lines


@dataclass(frozen=True)
class PolicyChange:
    """A change to the tier floor. Blood-locked in both directions.

    Rendered with the old and new value side by side, because "raise the floor"
    and "lower the floor" are the same screen otherwise, and one of them is an
    attack.
    """

    old_blood_above: int | None
    new_blood_above: int | None
    old_locked: frozenset[str] = frozenset()
    new_locked: frozenset[str] = frozenset()

    def op_class(self) -> str:
        return "policy.change"

    def amount_for_policy(self) -> int:
        return 0

    @staticmethod
    def _floor(v: int | None) -> str:
        return "no amount limit" if v is None else f"blood above {format_btc(v)}"

    def render(self) -> list[str]:
        lines = ["CHANGE SIGNING POLICY",
                 f"  from     {self._floor(self.old_blood_above)}",
                 f"  to       {self._floor(self.new_blood_above)}"]
        added = sorted(self.new_locked - self.old_locked)
        removed = sorted(self.old_locked - self.new_locked)
        for op in added:
            lines.append(f"  lock     {op}")
        for op in removed:
            lines.append(f"  UNLOCK   {op}")
        loosening = (
            (self.old_blood_above is None and self.new_blood_above is not None)
            or (self.old_blood_above is not None and self.new_blood_above is not None
                and self.new_blood_above > self.old_blood_above)
            or bool(removed)
        )
        # The direction is the whole security question. "Fewer operations need
        # blood" is the attacker's goal, so it gets the emphatic line.
        lines.append("  effect   " + ("LOOSENS: fewer need blood"
                                      if loosening else
                                      "TIGHTENS: more need blood"))
        return lines


# Every operation the device will sign. Anything not on this list is refused
# before it reaches the renderer, so an unknown type cannot reach the key by
# arriving with a render() method that returns something plausible.
ALLOWED = (BitcoinSpend, NoteSpend, DirectTransfer, EthereumSpend, PolicyChange)


def parse(payload: dict) -> Operation:
    """Build an operation from a decoded QR payload, or refuse.

    Refusal is the default: an unknown `type`, an unknown field, or a field of
    the wrong type all raise. A permissive parser that ignores what it does not
    understand is how a device ends up signing a field it never displayed.
    """
    if not isinstance(payload, dict):
        raise UnrenderableOperation("payload is not an object")
    kind = payload.get("type")
    table = {
        "btc_spend": BitcoinSpend,
        "note_spend": NoteSpend,
        "transfer": DirectTransfer,
        "eth_spend": EthereumSpend,
        "policy_change": PolicyChange,
    }
    if kind not in table:
        raise UnrenderableOperation(
            f"refusing unknown operation {kind!r}. This device signs "
            f"{', '.join(sorted(table))} and nothing else.")
    cls = table[kind]
    fields = {k: v for k, v in payload.items() if k != "type"}
    known = set(cls.__dataclass_fields__)
    unknown = set(fields) - known
    if unknown:
        # A field the device does not understand is a field it cannot display,
        # and therefore a field the owner cannot consent to.
        raise UnrenderableOperation(
            f"refusing {kind}: unknown field(s) {', '.join(sorted(unknown))}")
    try:
        op = cls(**fields)
    except TypeError as e:
        raise UnrenderableOperation(f"refusing {kind}: {e}") from None
    op.render()          # refuse now, not after the owner has bled
    return op


# Lines the signer appends to every confirmation screen: a blank, the tier
# being run, and why policy chose it. They are part of what the owner reads, so
# the operation must be checked against the space that is LEFT, not against the
# whole screen. Rendering to exactly 20 rows and then adding these silently
# pushed the tier disclosure off the bottom.
CONFIRM_FOOTER_ROWS = 3


def check_fits(lines: list[str], width: int = DISPLAY_COLS,
               rows: int = DISPLAY_ROWS) -> list[str]:
    """Refuse anything that does not fit the physical screen, exactly as shown.

    Takes the FINAL composed screen, so nothing can be appended after the
    check. A line that runs off a 240x240 display is a field the owner did not
    read, and silently truncating it defeats the entire point of rendering.
    """
    too_long = [ln for ln in lines if len(ln) > width]
    if too_long:
        raise UnrenderableOperation(
            f"line does not fit the {width}-column display: {too_long[0]!r}")
    if len(lines) > rows:
        # Refusing beats scrolling. A field below the fold is a field the owner
        # may never have seen, and consent to what you did not see is not consent.
        raise UnrenderableOperation(
            f"screen needs {len(lines)} lines, the display shows {rows}")
    return lines


def render_for_display(op: Operation, width: int = DISPLAY_COLS,
                       rows: int = DISPLAY_ROWS,
                       reserve: int = 0) -> list[str]:
    """Render one operation, refusing anything that will not fit.

    `reserve` is rows the caller will add afterwards. The signer reserves
    CONFIRM_FOOTER_ROWS for the tier lines it appends; leaving it at 0 checks
    the operation alone, which is what the operation-set tests want.
    """
    if not isinstance(op, ALLOWED):
        raise UnrenderableOperation(
            f"refusing {type(op).__name__}: not in the closed operation set")
    return check_fits(op.render(), width, max(0, rows - reserve))
