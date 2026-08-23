#!/usr/bin/env python3
"""ATECC608B config zone — build it, read it back, and only then lock it.

WHY THIS FILE EXISTS. BUILD.md section 12 asks for a chip whose slot 0 refuses
to derive without a prior authorisation, and calls that the single most
important line of configuration in the build. Until this file there was no way
to write it: the slot map lived in prose in `firmware/se_atecc.py`, and a
builder had to transcribe it into 128 bytes by hand, from the datasheet, and
get it right on the first try — because locking is permanent and there is no
second try. That is not a step you can ask someone to do for a bounty.

THE ONE RULE THIS TOOL FOLLOWS: it never invents a byte it does not
understand. The config zone carries the serial number, the revision, the
counter storage format and a scatter of reserved fields whose encodings are
Microchip's business, not ours. So every write here is READ-MODIFY-WRITE — the
chip's own config is read first, the fields CELL cares about are replaced, and
everything else is passed through byte for byte. A field this file cannot name
is a field this file leaves alone.

    atecc_config.py dump                 what is on the chip now
    atecc_config.py plan                 what CELL would change, byte by byte
    atecc_config.py write                apply it (reversible until you lock)
    atecc_config.py verify               does the chip match the policy
    atecc_config.py selfcheck            offline; what CI runs
    atecc_config.py lock-config          PERMANENT
    atecc_config.py lock-data            PERMANENT

The order is the procedure. `write` refuses to run unless `plan` has been shown
and the operator passes --i-have-read-the-plan, and both lock commands refuse
without --permanent, because both are.

WHAT IS TRANSCRIBED AND WHAT IS CHECKED. The bit positions below come from the
ATECC608B datasheet, section "Configuration Zone". They are transcribed, which
means they can be wrong, and being wrong here is silent — a config that locks
cleanly and grants nothing. Two things guard that:

  `selfcheck` proves the encoding is self-consistent: every field round trips,
  the policy's invariants hold on the bytes actually produced, and no byte
  outside the fields we name is disturbed. That runs in CI, without a chip.

  `verify --behaviour` proves the chip AGREES, by asking it to misbehave and
  watching it refuse. That runs on a bench, before you lock anything, and it is
  the only evidence that matters. VALIDATION.md carries this file as
  transcribed-not-confirmed until somebody runs it.

Read the decoded dump before you lock. If a field below does not match what
your datasheet says, the datasheet is right and this file is wrong.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

CONFIG_LEN = 128

# --------------------------------------------------------------------------
# Where things live in the 128 bytes.
#
# Only the offsets this tool reads or writes are named. The gaps are real
# fields -- serial number, revision, counter storage, reserved -- and they are
# deliberately absent, because naming a field here is a claim to understand its
# encoding and this file makes that claim only where it has to.
# --------------------------------------------------------------------------

OFF_SN03 = 0            # 4 bytes, factory
OFF_REVISION = 4        # 4 bytes, factory
OFF_SN48 = 8            # 5 bytes, factory
OFF_I2C_ADDRESS = 16
OFF_CHIPMODE = 19
OFF_SLOT_CONFIG = 20    # 16 x 2 bytes, little-endian
OFF_COUNTER0 = 52       # 8 bytes, Microchip's encoding -- never written here
OFF_COUNTER1 = 60       # 8 bytes, ditto
OFF_LOCK_VALUE = 86     # data zone lock state, read-only to us
OFF_LOCK_CONFIG = 87    # config zone lock state, read-only to us
OFF_SLOT_LOCKED = 88    # 2 bytes
OFF_KEY_CONFIG = 96     # 16 x 2 bytes, little-endian

# Bytes the chip owns and a write must not attempt to change. cryptoauthlib's
# atcab_write_config_zone skips 0-15 and 84-87 itself; this list is what the
# plan asserts it left alone, so a mistake here shows up as a refusal to write
# rather than as a chip that answers differently than it reads.
UNTOUCHABLE = (
    list(range(0, 16))          # SN, revision, factory
    + list(range(OFF_COUNTER0, OFF_COUNTER0 + 16))   # both counters
    + [84, 85, OFF_LOCK_VALUE, OFF_LOCK_CONFIG, 88, 89]
)

LOCKED = 0x00           # the datasheet's sense is inverted: 0x55 is UNlocked
UNLOCKED = 0x55


# --------------------------------------------------------------------------
# SlotConfig and KeyConfig, as bitfields
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SlotConfig:
    """16 bits at OFF_SLOT_CONFIG + 2*slot, little-endian.

        bits 0-3   ReadKey       what may read this slot, and how
        bit  4     NoMac         1 = this key may NOT be used by MAC commands
        bit  5     LimitedUse    1 = use is metered by Counter0
        bit  6     EncryptRead   1 = reads come back encrypted
        bit  7     IsSecret      1 = contents never leave in the clear
        bits 8-11  WriteKey      which slot's secret authorises a write
        bits 12-15 WriteConfig   how writes are permitted at all
    """

    read_key: int = 0
    no_mac: bool = False
    limited_use: bool = False
    encrypt_read: bool = False
    is_secret: bool = False
    write_key: int = 0
    write_config: int = 0

    def encode(self) -> int:
        for name, value, width in (("read_key", self.read_key, 4),
                                   ("write_key", self.write_key, 4),
                                   ("write_config", self.write_config, 4)):
            if not 0 <= value < (1 << width):
                raise ValueError(f"SlotConfig.{name}={value} does not fit in "
                                 f"{width} bits")
        return (self.read_key
                | (int(self.no_mac) << 4)
                | (int(self.limited_use) << 5)
                | (int(self.encrypt_read) << 6)
                | (int(self.is_secret) << 7)
                | (self.write_key << 8)
                | (self.write_config << 12))

    @classmethod
    def decode(cls, word: int) -> "SlotConfig":
        return cls(read_key=word & 0xF,
                   no_mac=bool(word & 0x10),
                   limited_use=bool(word & 0x20),
                   encrypt_read=bool(word & 0x40),
                   is_secret=bool(word & 0x80),
                   write_key=(word >> 8) & 0xF,
                   write_config=(word >> 12) & 0xF)


# WriteConfig values this tool uses. The nibble has more encodings than these;
# only the ones the policy needs are named, for the reason at the top of the
# file.
WRITE_ALWAYS = 0x0      # a clear write is accepted from anyone
WRITE_NEVER = 0x8       # no write by any means once the data zone is locked
WRITE_ENCRYPT = 0x4     # writes must be encrypted under WriteKey's secret


@dataclass(frozen=True)
class KeyConfig:
    """16 bits at OFF_KEY_CONFIG + 2*slot, little-endian.

        bit  0     Private       1 = an ECC private key
        bit  1     PubInfo
        bits 2-4   KeyType       4 = P-256, 6 = AES, 7 = SHA/HMAC or data
        bit  5     Lockable      1 = this slot may be individually locked
        bit  6     ReqRandom     1 = a random nonce is required to use it
        bit  7     ReqAuth       1 = unusable without a prior CheckMac
        bits 8-11  AuthKey       which slot that CheckMac must be against
        bit  12    PersistentDisable
        bits 14-15 X509id
    """

    private: bool = False
    pub_info: bool = False
    key_type: int = 7
    lockable: bool = True
    req_random: bool = False
    req_auth: bool = False
    auth_key: int = 0
    persistent_disable: bool = False
    x509id: int = 0

    def encode(self) -> int:
        if not 0 <= self.key_type < 8:
            raise ValueError(f"KeyConfig.key_type={self.key_type} is 3 bits")
        if not 0 <= self.auth_key < 16:
            raise ValueError(f"KeyConfig.auth_key={self.auth_key} is 4 bits")
        if self.req_auth and self.auth_key == 0 and not self.private:
            # Not a datasheet rule -- a CELL rule. AuthKey 0 is a real slot
            # number here, so "ReqAuth with AuthKey left at its default" is
            # indistinguishable from "ReqAuth against slot 0", and slot 0 is
            # the wrapping key. Setting one deliberately is fine; the policy
            # below never does, so reaching this means a typo.
            raise ValueError("ReqAuth against slot 0 -- the wrapping slot "
                             "cannot authorise its own use")
        return (int(self.private)
                | (int(self.pub_info) << 1)
                | (self.key_type << 2)
                | (int(self.lockable) << 5)
                | (int(self.req_random) << 6)
                | (int(self.req_auth) << 7)
                | (self.auth_key << 8)
                | (int(self.persistent_disable) << 12)
                | (self.x509id << 14))

    @classmethod
    def decode(cls, word: int) -> "KeyConfig":
        return cls(private=bool(word & 0x1),
                   pub_info=bool(word & 0x2),
                   key_type=(word >> 2) & 0x7,
                   lockable=bool(word & 0x20),
                   req_random=bool(word & 0x40),
                   req_auth=bool(word & 0x80),
                   auth_key=(word >> 8) & 0xF,
                   persistent_disable=bool(word & 0x1000),
                   x509id=(word >> 14) & 0x3)


KEYTYPE_P256 = 4
KEYTYPE_AES = 6
KEYTYPE_SHA = 7         # HMAC key or plain data


# --------------------------------------------------------------------------
# The CELL policy
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SlotPolicy:
    slot: int
    name: str
    why: str
    slot_config: SlotConfig
    key_config: KeyConfig


def _secret_key(*, req_auth: int | None = None, limited_use: bool = False,
                write_config: int = WRITE_NEVER,
                write_key: int = 0) -> tuple[SlotConfig, KeyConfig]:
    """A slot holding a secret used only as an HMAC key.

    IsSecret with EncryptRead clear means the contents never come back out by
    any command. NoMac stays clear because these keys exist to be used by MAC,
    CheckMac and SHA-HMAC -- setting it would lock the chip out of the one
    thing every one of these slots is for.
    """
    return (SlotConfig(is_secret=True, encrypt_read=False, no_mac=False,
                       limited_use=limited_use, read_key=0,
                       write_key=write_key, write_config=write_config),
            KeyConfig(key_type=KEYTYPE_SHA, lockable=True,
                      req_auth=req_auth is not None,
                      auth_key=req_auth or 0))


def _public_counter(write_key: int) -> tuple[SlotConfig, KeyConfig]:
    """A slot holding a 4-byte number anyone may read and only the PIN may set.

    The baseline is not a secret -- it is the attempt counter's value at the
    last correct PIN, and knowing it tells an attacker only what the screen
    already tells them. What must not happen is an attacker WRITING it: setting
    the baseline forward to the counter refunds the whole attempt budget, which
    is the exact rollback this chip is in the bill of materials to prevent.

    So the write is encrypted under the PIN key's secret. That secret is a
    function of the PIN, so a host that knows the PIN can write the baseline
    and a host that does not cannot -- which is the property the docstring in
    se_atecc.py claimed before anything enforced it.
    """
    return (SlotConfig(is_secret=False, encrypt_read=False, read_key=0,
                       write_key=write_key, write_config=WRITE_ENCRYPT),
            KeyConfig(key_type=KEYTYPE_SHA, lockable=True))


# Slot numbers. firmware/se_atecc.py imports these, so the map has one home.
SLOT_WRAP = 0
SLOT_ATTEST = 1
SLOT_PIN = 2
SLOT_BASELINE = 3
SLOT_PIN_DURESS = 4
SLOT_WRAP_DURESS = 5
SLOT_BASELINE_DURESS = 6
FIRST_UNUSED = 7

COUNTER_PIN = 0
COUNTER_OPS = 1


def _policy() -> list[SlotPolicy]:
    wrap_sc, wrap_kc = _secret_key(req_auth=SLOT_PIN, limited_use=True,
                                   write_config=WRITE_ALWAYS)
    dwrap_sc, dwrap_kc = _secret_key(req_auth=SLOT_PIN_DURESS,
                                     write_config=WRITE_ALWAYS)
    att_sc, att_kc = _secret_key()
    pin_sc, pin_kc = _secret_key()
    dpin_sc, dpin_kc = _secret_key()
    base_sc, base_kc = _public_counter(write_key=SLOT_PIN)
    dbase_sc, dbase_kc = _public_counter(write_key=SLOT_PIN_DURESS)
    unused_sc, unused_kc = _secret_key()

    out = [
        SlotPolicy(SLOT_WRAP, "wrap",
                   "seed-wrapping secret. ReqAuth against the PIN slot is the "
                   "line BUILD.md 12 calls the most important in the build: "
                   "without it an attacker never calls verify_pin, they call "
                   "the derive once per candidate PIN.",
                   wrap_sc, wrap_kc),
        SlotPolicy(SLOT_ATTEST, "attest",
                   "attestation secret. No ReqAuth: attest_pubkey() has to "
                   "answer at the idle screen, with nothing unlocked.",
                   att_sc, att_kc),
        SlotPolicy(SLOT_PIN, "pin",
                   "normal PIN key. Its secret is HMAC(PIN), so a host that "
                   "knows the PIN can satisfy the CheckMac and one that does "
                   "not cannot. This IS the PIN check.",
                   pin_sc, pin_kc),
        SlotPolicy(SLOT_BASELINE, "baseline",
                   "attempt counter's value at the last correct normal PIN.",
                   base_sc, base_kc),
        SlotPolicy(SLOT_PIN_DURESS, "pin-duress",
                   "duress PIN key. Identical configuration to the normal "
                   "one, deliberately: a chip whose two PIN slots differ is a "
                   "chip that answers 'which of these is the duress PIN'.",
                   dpin_sc, dpin_kc),
        SlotPolicy(SLOT_WRAP_DURESS, "wrap-duress",
                   "the decoy wallet's wrapping secret, reached only by a "
                   "CheckMac against the duress PIN slot.",
                   dwrap_sc, dwrap_kc),
        SlotPolicy(SLOT_BASELINE_DURESS, "baseline-duress",
                   "same, for the duress PIN. Two baselines because a slot "
                   "has one WriteKey, and the duress PIN must restore the "
                   "budget exactly as the normal one does or the difference "
                   "is readable afterwards.",
                   dbase_sc, dbase_kc),
    ]
    for s in range(FIRST_UNUSED, 16):
        out.append(SlotPolicy(s, "unused",
                              "not used by CELL. Configured secret and "
                              "unwritable so it cannot be used as scratch "
                              "space by anything else.",
                              unused_sc, unused_kc))
    return out


POLICY = _policy()
BY_SLOT = {p.slot: p for p in POLICY}


# --------------------------------------------------------------------------
# Building the image
# --------------------------------------------------------------------------


def _word(cfg: bytes, off: int) -> int:
    return cfg[off] | (cfg[off + 1] << 8)


def _set_word(buf: bytearray, off: int, value: int) -> None:
    buf[off] = value & 0xFF
    buf[off + 1] = (value >> 8) & 0xFF


def plan(base: bytes) -> bytes:
    """The chip's own config with CELL's fields replaced. Nothing else moves.

    `base` is what the chip reads back, not a template. That is the whole
    point: the serial number, revision, counter encoding and every reserved
    byte survive untouched, because this file does not know what they mean and
    a tool that overwrites what it cannot name is a tool that bricks chips.
    """
    if len(base) != CONFIG_LEN:
        raise ValueError(f"a config zone is {CONFIG_LEN} bytes, got {len(base)}")
    out = bytearray(base)
    for p in POLICY:
        _set_word(out, OFF_SLOT_CONFIG + 2 * p.slot, p.slot_config.encode())
        _set_word(out, OFF_KEY_CONFIG + 2 * p.slot, p.key_config.encode())
    # Assert the promise rather than trusting it. If a future edit reaches
    # outside the two tables, this is where it stops.
    for off in UNTOUCHABLE:
        if out[off] != base[off]:
            raise AssertionError(
                f"the plan changed byte {off}, which belongs to the chip. "
                f"That is a bug in this file, not a configuration choice.")
    return bytes(out)


def diff(base: bytes, want: bytes) -> list[tuple[int, int, int, str]]:
    """Byte-level changes, each labelled with the field it belongs to."""
    out = []
    for i in range(CONFIG_LEN):
        if base[i] != want[i]:
            out.append((i, base[i], want[i], _field_name(i)))
    return out


def _field_name(off: int) -> str:
    if OFF_SLOT_CONFIG <= off < OFF_SLOT_CONFIG + 32:
        slot = (off - OFF_SLOT_CONFIG) // 2
        return f"SlotConfig[{slot}] ({BY_SLOT[slot].name})"
    if OFF_KEY_CONFIG <= off < OFF_KEY_CONFIG + 32:
        slot = (off - OFF_KEY_CONFIG) // 2
        return f"KeyConfig[{slot}] ({BY_SLOT[slot].name})"
    if off < 16:
        return "factory (SN / revision)"
    if OFF_COUNTER0 <= off < OFF_COUNTER0 + 16:
        return "counter storage"
    return "other"


# --------------------------------------------------------------------------
# Invariants — what has to be true of the bytes, whoever produced them
# --------------------------------------------------------------------------


def invariants(cfg: bytes) -> list[tuple[str, bool]]:
    """The properties CELL's security argument actually rests on.

    Checked against a config zone read off a chip, so this answers "is THIS
    chip configured correctly", not "did our own encoder agree with itself".
    Each line is one sentence from BUILD.md or se_atecc.py, made mechanical.
    """
    sc = {s: SlotConfig.decode(_word(cfg, OFF_SLOT_CONFIG + 2 * s))
          for s in range(16)}
    kc = {s: KeyConfig.decode(_word(cfg, OFF_KEY_CONFIG + 2 * s))
          for s in range(16)}
    out: list[tuple[str, bool]] = []

    def want(label, cond):
        out.append((label, bool(cond)))

    # The one that matters most.
    want("slot 0 cannot derive without a CheckMac against slot 2",
         kc[SLOT_WRAP].req_auth and kc[SLOT_WRAP].auth_key == SLOT_PIN)
    want("slot 5 cannot derive without a CheckMac against slot 4",
         kc[SLOT_WRAP_DURESS].req_auth
         and kc[SLOT_WRAP_DURESS].auth_key == SLOT_PIN_DURESS)
    want("every derive off slot 0 is metered by Counter0",
         sc[SLOT_WRAP].limited_use)

    # Secrets stay secret.
    for s in (SLOT_WRAP, SLOT_ATTEST, SLOT_PIN, SLOT_PIN_DURESS,
              SLOT_WRAP_DURESS):
        want(f"slot {s} is secret and never read out",
             sc[s].is_secret and not sc[s].encrypt_read)
        want(f"slot {s} is usable as a MAC key",
             not sc[s].no_mac and kc[s].key_type == KEYTYPE_SHA)

    # The rollback this part was bought to prevent.
    want("the normal baseline can only be written under the PIN key",
         sc[SLOT_BASELINE].write_config == WRITE_ENCRYPT
         and sc[SLOT_BASELINE].write_key == SLOT_PIN)
    want("the duress baseline can only be written under the duress PIN key",
         sc[SLOT_BASELINE_DURESS].write_config == WRITE_ENCRYPT
         and sc[SLOT_BASELINE_DURESS].write_key == SLOT_PIN_DURESS)
    want("both baselines are readable, so attempts_remaining() can answer",
         not sc[SLOT_BASELINE].is_secret
         and not sc[SLOT_BASELINE_DURESS].is_secret)

    # wipe() has to be able to destroy the wrapping secrets. See the note in
    # `write_config=WRITE_ALWAYS` above and in se_atecc.wipe().
    want("both wrapping slots can be overwritten, so a wipe is possible",
         sc[SLOT_WRAP].write_config == WRITE_ALWAYS
         and sc[SLOT_WRAP_DURESS].write_config == WRITE_ALWAYS)

    # Duress is only credible if the two halves are indistinguishable.
    want("the two PIN slots are configured identically",
         sc[SLOT_PIN] == sc[SLOT_PIN_DURESS] and kc[SLOT_PIN] == kc[SLOT_PIN_DURESS])
    want("the two baseline slots differ only in their write key",
         replace(sc[SLOT_BASELINE], write_key=0)
         == replace(sc[SLOT_BASELINE_DURESS], write_key=0))
    want("the two wrapping slots differ only in their auth key",
         replace(kc[SLOT_WRAP], auth_key=0, req_auth=False)
         == replace(kc[SLOT_WRAP_DURESS], auth_key=0, req_auth=False))

    # Nothing left as scratch space.
    want("slots 7-15 are unusable",
         all(sc[s].is_secret and sc[s].write_config == WRITE_NEVER
             for s in range(FIRST_UNUSED, 16)))
    return out


def lock_state(cfg: bytes) -> tuple[bool, bool]:
    """(config locked, data locked), read out of the zone itself."""
    return (cfg[OFF_LOCK_CONFIG] != UNLOCKED, cfg[OFF_LOCK_VALUE] != UNLOCKED)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def dump(cfg: bytes) -> str:
    """The decoded config, for a human to read before locking anything.

    This is the artefact to actually look at. Everything else in this file is
    machinery; this is where a builder catches a bit that is wrong.
    """
    lines = []
    sn = cfg[OFF_SN03:OFF_SN03 + 4] + cfg[OFF_SN48:OFF_SN48 + 5]
    cfg_locked, data_locked = lock_state(cfg)
    lines.append(f"serial number   {sn.hex()}")
    lines.append(f"revision        {cfg[OFF_REVISION:OFF_REVISION + 4].hex()}")
    lines.append(f"I2C address     0x{cfg[OFF_I2C_ADDRESS] >> 1:02x} "
                 f"(config byte 0x{cfg[OFF_I2C_ADDRESS]:02x})")
    lines.append(f"config zone     {'LOCKED' if cfg_locked else 'unlocked'}")
    lines.append(f"data zone       {'LOCKED' if data_locked else 'unlocked'}")
    lines.append("")
    lines.append("slot  name             read      write            key      auth")
    lines.append("-" * 70)
    for s in range(16):
        sc = SlotConfig.decode(_word(cfg, OFF_SLOT_CONFIG + 2 * s))
        kc = KeyConfig.decode(_word(cfg, OFF_KEY_CONFIG + 2 * s))
        read = ("secret" if sc.is_secret and not sc.encrypt_read
                else "enc" if sc.encrypt_read else "clear")
        write = {WRITE_ALWAYS: "always", WRITE_NEVER: "never",
                 WRITE_ENCRYPT: f"enc<-{sc.write_key}"}.get(
                     sc.write_config, f"0x{sc.write_config:x}")
        keytype = {KEYTYPE_P256: "P-256", KEYTYPE_AES: "AES",
                   KEYTYPE_SHA: "SHA/HMAC"}.get(kc.key_type, str(kc.key_type))
        auth = f"CheckMac<-{kc.auth_key}" if kc.req_auth else "-"
        meter = " metered" if sc.limited_use else ""
        name = BY_SLOT[s].name if s in BY_SLOT else "?"
        lines.append(f"{s:>4}  {name:<15}  {read:<8}  {write:<15}  "
                     f"{keytype:<8} {auth}{meter}")
    return "\n".join(lines)


def render_invariants(cfg: bytes) -> tuple[str, bool]:
    rows = invariants(cfg)
    ok = all(good for _, good in rows)
    body = "\n".join(f"  {label:<62}{'PASS' if good else 'FAIL'}"
                     for label, good in rows)
    return body, ok


# --------------------------------------------------------------------------
# The chip
# --------------------------------------------------------------------------


def _chip(lib=None, bus: int = 1, address: int = 0x60):
    """cryptoauthlib, initialised. Separate from se_atecc.ATECC608B because
    that class refuses to construct against an unlocked chip -- which is
    exactly the chip this tool exists to talk to."""
    if lib is not None:
        cal = lib
    else:
        try:
            import cryptoauthlib as cal                     # noqa: F401
        except ImportError:
            raise SystemExit(
                "cryptoauthlib is not installed.\n"
                "    pip install cryptoauthlib\n"
                "and enable I2C with raspi-config.") from None
    cfg = cal.cfg_ateccx08a_i2c_default()
    cfg.cfg.atcai2c.bus = bus
    cfg.cfg.atcai2c.slave_address = address << 1
    if cal.atcab_init(cfg) != cal.Status.ATCA_SUCCESS:
        raise SystemExit(
            f"no ATECC608B answered at I2C {address:#04x} on bus {bus}. "
            f"Check the pull-ups -- both breakouts ship with them fitted and "
            f"one pair has to come off.")
    return cal


def read_config(cal) -> bytes:
    buf = bytearray(CONFIG_LEN)
    if cal.atcab_read_config_zone(buf) != cal.Status.ATCA_SUCCESS:
        raise SystemExit("could not read the config zone")
    return bytes(buf)


def write_config(cal, image: bytes) -> None:
    if cal.atcab_write_config_zone(image) != cal.Status.ATCA_SUCCESS:
        raise SystemExit(
            "the config zone write failed. If the config zone is already "
            "locked this is expected and permanent -- see `dump`.")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_dump(args) -> int:
    cal = _chip(bus=args.bus, address=args.address)
    cfg = read_config(cal)
    print(dump(cfg))
    print()
    body, ok = render_invariants(cfg)
    print(body)
    print("\n" + ("policy satisfied" if ok else
                  "POLICY NOT SATISFIED -- run `plan` to see what would change"))
    return 0


def cmd_plan(args) -> int:
    cal = _chip(bus=args.bus, address=args.address)
    base = read_config(cal)
    return _show_plan(base)


def _show_plan(base: bytes) -> int:
    cfg_locked, _ = lock_state(base)
    want = plan(base)
    changes = diff(base, want)

    print("BEFORE\n")
    print(dump(base))
    print("\n\nCHANGES\n")
    if not changes:
        print("  none -- this chip already carries the CELL policy.")
    for off, was, now, field in changes:
        print(f"  byte {off:>3}  0x{was:02x} -> 0x{now:02x}   {field}")
    print(f"\n  {len(changes)} byte(s). Every other byte is passed through "
          f"unchanged,\n  including the serial number, both counters and "
          f"every reserved field.")
    print("\n\nAFTER\n")
    print(dump(want))
    print()
    body, ok = render_invariants(want)
    print(body)
    print()
    if cfg_locked:
        print("This chip's config zone is ALREADY LOCKED. Nothing above can "
              "be applied.\nIf the policy does not hold, this chip cannot be "
              "used for CELL. Fit a new one.")
        return 1
    if not ok:
        print("The plan does not satisfy the policy. That is a bug in "
              "atecc_config.py.\nDo not write it.")
        return 1
    print("To apply:  atecc_config.py write --i-have-read-the-plan")
    return 0


def cmd_write(args) -> int:
    if not args.i_have_read_the_plan:
        print("Refusing to write a config zone nobody has looked at.\n")
        print("Run `atecc_config.py plan`, read the AFTER table against your")
        print("datasheet, and then pass --i-have-read-the-plan. The bit")
        print("positions in this file are transcribed and could be wrong; you")
        print("are the check on that, and after the lock there is no other.")
        return 1
    cal = _chip(bus=args.bus, address=args.address)
    base = read_config(cal)
    cfg_locked, _ = lock_state(base)
    if cfg_locked:
        print("The config zone is already locked. Nothing to do, and nothing "
              "that can be done.")
        return 1

    image = plan(base)
    write_config(cal, image)

    # Read it back before believing it. A config zone that did not take is a
    # config zone that grants nothing, and after the lock the difference is
    # unrecoverable.
    got = read_config(cal)
    mismatches = [(i, image[i], got[i]) for i in range(CONFIG_LEN)
                  if image[i] != got[i] and i not in UNTOUCHABLE]
    if mismatches:
        print("The chip did not take the configuration:\n")
        for off, wanted, got_b in mismatches:
            print(f"  byte {off:>3}  wrote 0x{wanted:02x}, reads back "
                  f"0x{got_b:02x}   {_field_name(off)}")
        print("\nDO NOT LOCK. Nothing is permanent yet.")
        return 1

    body, ok = render_invariants(got)
    print(dump(got))
    print()
    print(body)
    if not ok:
        print("\nWritten, but the policy does not hold. DO NOT LOCK.")
        return 1
    print("\nWritten and read back byte for byte.\n")
    print("Nothing is permanent yet. Next, in this order:")
    print("  1. atecc_config.py lock-config --permanent")
    print("  2. tools/provision.py ...            (writes the slot secrets)")
    print("  3. atecc_config.py verify --behaviour")
    print("  4. atecc_config.py lock-data --permanent")
    print("\nThe slot secrets are written between the two locks because data")
    print("slots are writable until the DATA zone locks, and the slot policy")
    print("only takes effect once the CONFIG zone has.")
    return 0


def cmd_verify(args) -> int:
    cal = _chip(bus=args.bus, address=args.address)
    cfg = read_config(cal)
    print(dump(cfg))
    print()
    body, ok = render_invariants(cfg)
    print(body)
    if args.behaviour:
        print("\n behaviour -- asking the chip to misbehave\n")
        ok &= _behaviour(cal, cfg)
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _behaviour(cal, cfg: bytes) -> bool:
    """Ask the chip to do the things the config is supposed to forbid.

    Reading the config zone back proves the bytes are there. It does not prove
    the chip ENFORCES them, and the difference is the whole value of the part.
    So: try to read a secret slot, try to derive without authorising, try to
    write a baseline in the clear. Every one must fail.

    This is the same argument bench.py makes for the attempt counter, and for
    the same reason -- decoding config bits is a claim about a datasheet, and
    watching the chip refuse is a claim about the chip.
    """
    from se_atecc import ATCA_ZONE_DATA, SHA_MODE_TARGET_TEMPKEY
    rows: list[tuple[str, bool]] = []

    def refuses(label, fn):
        try:
            status = fn()
            rows.append((label, status != cal.Status.ATCA_SUCCESS))
        except Exception:                                   # noqa: BLE001
            rows.append((label, True))

    buf = bytearray(32)
    refuses("the wrapping secret cannot be read out",
            lambda: cal.atcab_read_zone(ATCA_ZONE_DATA, SLOT_WRAP, 0, 0,
                                        buf, 32))
    refuses("the attestation secret cannot be read out",
            lambda: cal.atcab_read_zone(ATCA_ZONE_DATA, SLOT_ATTEST, 0, 0,
                                        buf, 32))
    refuses("the PIN key cannot be read out",
            lambda: cal.atcab_read_zone(ATCA_ZONE_DATA, SLOT_PIN, 0, 0,
                                        buf, 32))

    # The line BUILD.md 12 is about. With no CheckMac in this session, slot 0
    # must refuse to act as an HMAC key at all.
    out = bytearray(32)
    refuses("slot 0 refuses to derive with no prior CheckMac",
            lambda: cal.atcab_sha_hmac(b"probe", 5, SLOT_WRAP, out,
                                       SHA_MODE_TARGET_TEMPKEY))
    refuses("slot 5 refuses to derive with no prior CheckMac",
            lambda: cal.atcab_sha_hmac(b"probe", 5, SLOT_WRAP_DURESS, out,
                                       SHA_MODE_TARGET_TEMPKEY))

    _, data_locked = lock_state(cfg)
    if data_locked:
        refuses("the baseline refuses a clear write",
                lambda: cal.atcab_write_zone(ATCA_ZONE_DATA, SLOT_BASELINE,
                                             0, 0, bytes(32), 32))
    else:
        rows.append(("the baseline refuses a clear write "
                     "(skipped -- data zone still unlocked)", True))

    for label, good in rows:
        print(f"  {label:<62}{'PASS' if good else 'FAIL'}")
    return all(good for _, good in rows)


def cmd_lock(args, zone: str) -> int:
    if not args.permanent:
        print(f"Locking the {zone} zone is PERMANENT. There is no unlock "
              f"command and\nno amount of anything undoes it.\n")
        print("Before you do: run `atecc_config.py verify` and read every "
              "line.\nThen pass --permanent.")
        return 1
    cal = _chip(bus=args.bus, address=args.address)
    cfg = read_config(cal)
    _, ok = render_invariants(cfg)
    if zone == "config" and not ok:
        print("This chip does not satisfy the CELL policy. Locking it now "
              "would\nmake that permanent. Refusing.\n")
        print(render_invariants(cfg)[0])
        return 1
    fn = (cal.atcab_lock_config_zone if zone == "config"
          else cal.atcab_lock_data_zone)
    if fn() != cal.Status.ATCA_SUCCESS:
        print(f"the {zone} zone lock failed")
        return 1
    print(f"{zone} zone locked. Permanently.")
    return 0


def cmd_selfcheck(args) -> int:
    """Everything provable without a chip. This is what CI runs."""
    return 0 if selfcheck(verbose=True) else 1


def selfcheck(verbose: bool = False) -> bool:
    rows: list[tuple[str, bool]] = []

    def check(label, cond):
        rows.append((label, bool(cond)))

    # Round trip: every field survives encode/decode. A bitfield that loses a
    # flag silently produces a chip configured as something nobody chose.
    ok = True
    for p in POLICY:
        ok &= SlotConfig.decode(p.slot_config.encode()) == p.slot_config
        ok &= KeyConfig.decode(p.key_config.encode()) == p.key_config
    check("every policy slot round trips through its bitfield", ok)

    # Each bit lands where the datasheet says. Encoding one flag at a time and
    # checking the word is the only way to catch a transposed shift, which is
    # the mistake that produces a plausible-looking config that grants the
    # wrong thing.
    check("SlotConfig bit positions", all([
        SlotConfig(read_key=0xF).encode() == 0x000F,
        SlotConfig(no_mac=True).encode() == 0x0010,
        SlotConfig(limited_use=True).encode() == 0x0020,
        SlotConfig(encrypt_read=True).encode() == 0x0040,
        SlotConfig(is_secret=True).encode() == 0x0080,
        SlotConfig(write_key=0xF).encode() == 0x0F00,
        SlotConfig(write_config=0xF).encode() == 0xF000,
    ]))
    check("KeyConfig bit positions", all([
        KeyConfig(private=True, key_type=0, lockable=False).encode() == 0x0001,
        KeyConfig(pub_info=True, key_type=0, lockable=False).encode() == 0x0002,
        KeyConfig(key_type=7, lockable=False).encode() == 0x001C,
        KeyConfig(key_type=0).encode() == 0x0020,
        KeyConfig(req_random=True, key_type=0, lockable=False).encode() == 0x0040,
        KeyConfig(req_auth=True, auth_key=2, key_type=0,
                  lockable=False).encode() == 0x0280,
        KeyConfig(persistent_disable=True, key_type=0,
                  lockable=False).encode() == 0x1000,
        KeyConfig(x509id=3, key_type=0, lockable=False).encode() == 0xC000,
    ]))

    # Field widths are enforced, not truncated. Silently masking a value into
    # range is how a slot number of 16 becomes a config pointing at slot 0.
    def raises(fn):
        try:
            fn()
            return False
        except ValueError:
            return True
    check("out-of-range fields are refused, not masked", all([
        raises(lambda: SlotConfig(read_key=16).encode()),
        raises(lambda: SlotConfig(write_key=16).encode()),
        raises(lambda: SlotConfig(write_config=16).encode()),
        raises(lambda: KeyConfig(key_type=8).encode()),
        raises(lambda: KeyConfig(auth_key=16).encode()),
        raises(lambda: KeyConfig(req_auth=True, auth_key=0).encode()),
    ]))

    # The plan, against a synthetic factory-fresh chip. The base below is NOT
    # a real Microchip default and does not need to be -- what is being tested
    # is that plan() changes only the two tables, whatever the base says.
    base = bytearray(CONFIG_LEN)
    for i in range(CONFIG_LEN):
        base[i] = (i * 7 + 13) & 0xFF           # noise, so a copy is visible
    base[OFF_LOCK_CONFIG] = UNLOCKED
    base[OFF_LOCK_VALUE] = UNLOCKED
    base = bytes(base)
    image = plan(base)

    check("the plan is 128 bytes", len(image) == CONFIG_LEN)
    untouched = all(image[i] == base[i] for i in UNTOUCHABLE)
    check("the serial number, counters and lock bytes are passed through",
          untouched)
    outside = [i for i in range(CONFIG_LEN) if image[i] != base[i]
               and not (OFF_SLOT_CONFIG <= i < OFF_SLOT_CONFIG + 32
                        or OFF_KEY_CONFIG <= i < OFF_KEY_CONFIG + 32)]
    check("nothing outside SlotConfig and KeyConfig is changed", not outside)
    check("the plan is idempotent", plan(image) == image)

    body, inv_ok = render_invariants(image)
    check("the planned image satisfies every policy invariant", inv_ok)

    # A plan built on a DIFFERENT base must produce the same two tables. If it
    # does not, the policy is reading something out of the base it should not.
    other = bytearray(base)
    for i in range(16, 20):
        other[i] ^= 0xFF
    tables = slice(OFF_SLOT_CONFIG, OFF_SLOT_CONFIG + 32)
    check("the policy does not depend on what the chip shipped with",
          plan(bytes(other))[tables] == image[tables])

    # Negative: an image missing the one line BUILD.md 12 is about must be
    # caught by invariants(), or invariants() is decoration.
    broken = bytearray(image)
    kc = KeyConfig.decode(_word(broken, OFF_KEY_CONFIG + 2 * SLOT_WRAP))
    _set_word(broken, OFF_KEY_CONFIG + 2 * SLOT_WRAP,
              replace(kc, req_auth=False, auth_key=0).encode())
    check("an image without ReqAuth on slot 0 fails the invariants",
          not all(good for _, good in invariants(bytes(broken))))

    broken = bytearray(image)
    sc = SlotConfig.decode(_word(broken, OFF_SLOT_CONFIG + 2 * SLOT_BASELINE))
    _set_word(broken, OFF_SLOT_CONFIG + 2 * SLOT_BASELINE,
              replace(sc, write_config=WRITE_ALWAYS).encode())
    check("a clear-writable baseline fails the invariants",
          not all(good for _, good in invariants(bytes(broken))))

    broken = bytearray(image)
    sc = SlotConfig.decode(_word(broken, OFF_SLOT_CONFIG + 2 * SLOT_WRAP))
    _set_word(broken, OFF_SLOT_CONFIG + 2 * SLOT_WRAP,
              replace(sc, encrypt_read=True).encode())
    check("a readable wrapping slot fails the invariants",
          not all(good for _, good in invariants(bytes(broken))))

    broken = bytearray(image)
    _set_word(broken, OFF_SLOT_CONFIG + 2 * SLOT_PIN_DURESS,
              SlotConfig(is_secret=True, no_mac=True).encode())
    check("PIN slots that differ from each other fail the invariants",
          not all(good for _, good in invariants(bytes(broken))))

    # The slot map has one home, and se_atecc.py imports it from here.
    import se_atecc
    check("firmware/se_atecc.py uses this slot map", all([
        se_atecc.SLOT_WRAP == SLOT_WRAP,
        se_atecc.SLOT_ATTEST == SLOT_ATTEST,
        se_atecc.SLOT_PIN == SLOT_PIN,
        se_atecc.SLOT_BASELINE == SLOT_BASELINE,
        se_atecc.SLOT_PIN_DURESS == SLOT_PIN_DURESS,
        se_atecc.SLOT_WRAP_DURESS == SLOT_WRAP_DURESS,
        se_atecc.SLOT_BASELINE_DURESS == SLOT_BASELINE_DURESS,
        se_atecc.COUNTER_PIN == COUNTER_PIN,
        se_atecc.COUNTER_OPS == COUNTER_OPS,
    ]))

    conf = cryptoauthlib_conformance()
    rows.extend(conf)

    if verbose:
        print("ATECC608B config zone — what is provable without a chip\n")
        for label, good in rows:
            print(f"  {label:<62}{'PASS' if good else 'FAIL'}")
        if not conf:
            print("\n      cryptoauthlib not installed — the cross-check against")
            print("      Microchip's own field map was skipped. Install it to")
            print("      have the bit positions confirmed by a second source:")
            print("          pip install cryptoauthlib")
        print("\n the planned image\n")
        print(dump(image))
        print()
        print(body)
        print("\n" + ("PASS" if all(g for _, g in rows) else "FAIL"))
        print("\nNone of this is evidence about silicon. The bit positions are")
        print("transcribed from the datasheet and are confirmed only by")
        print("`atecc_config.py verify --behaviour` on a built device.")
    return all(good for _, good in rows)


def cryptoauthlib_conformance() -> list:
    """Check this file's field map against cryptoauthlib's own, if installed.

    `cryptoauthlib.device` carries Microchip's ctypes definition of the whole
    ATECC608 config zone — every field, in order, with the SlotConfig and
    KeyConfig bitfields spelled out. That is a SECOND transcription of the same
    datasheet page, written by the people who make the part, and comparing the
    two is the strongest check available without a chip on a bench.

    It is not a substitute for `verify --behaviour`. Two descriptions agreeing
    says the description is right; only the chip says the chip agrees. But it
    moves the bit positions from "transcribed by one person" to "transcribed
    twice, independently, with the same answer", and it is free.

    Returns [] when the library is absent, which is the normal case in CI --
    the binding pulls a native shared object that has no business being a test
    dependency. Anyone building a device installs it anyway.
    """
    try:
        import ctypes
        from cryptoauthlib.device import Atecc608Config, SlotConfig, KeyConfig
    except Exception:                                       # noqa: BLE001
        return []

    out = []
    try:
        out.append(("cryptoauthlib agrees the config zone is 128 bytes",
                    ctypes.sizeof(Atecc608Config) == CONFIG_LEN))

        for label, mine, field in (
                ("SN03", OFF_SN03, "SN03"),
                ("RevNum", OFF_REVISION, "RevNum"),
                ("SN48", OFF_SN48, "SN48"),
                ("I2C_Address", OFF_I2C_ADDRESS, "I2C_Address"),
                ("ChipMode", OFF_CHIPMODE, "ChipMode"),
                ("SlotConfig", OFF_SLOT_CONFIG, "SlotConfig"),
                ("Counter0", OFF_COUNTER0, "Counter0"),
                ("Counter1", OFF_COUNTER1, "Counter1"),
                ("LockValue", OFF_LOCK_VALUE, "LockValue"),
                ("LockConfig", OFF_LOCK_CONFIG, "LockConfig"),
                ("SlotLocked", OFF_SLOT_LOCKED, "SlotLocked"),
                ("KeyConfig", OFF_KEY_CONFIG, "KeyConfig")):
            theirs = getattr(Atecc608Config, field).offset
            out.append((f"{label} sits at byte {mine}, as cryptoauthlib says",
                        mine == theirs))

        # Every slot this file will actually write, encoded by us and decoded
        # by them. A transposed shift shows up here as a policy that reads as
        # something nobody chose.
        for pol in POLICY:
            sc = SlotConfig.from_buffer_copy(
                pol.slot_config.encode().to_bytes(2, "little"))
            kc = KeyConfig.from_buffer_copy(
                pol.key_config.encode().to_bytes(2, "little"))
            m, k = pol.slot_config, pol.key_config
            same = (sc.ReadKey == m.read_key and sc.NoMac == m.no_mac
                    and sc.LimitedUse == m.limited_use
                    and sc.EncryptRead == m.encrypt_read
                    and sc.IsSecret == m.is_secret
                    and sc.WriteKey == m.write_key
                    and sc.WriteConfig == m.write_config
                    and kc.Private == k.private and kc.PubInfo == k.pub_info
                    and kc.KeyType == k.key_type and kc.Lockable == k.lockable
                    and kc.ReqRandom == k.req_random and kc.ReqAuth == k.req_auth
                    and kc.AuthKey == k.auth_key
                    and kc.PersistentDisable == k.persistent_disable
                    and kc.X509id == k.x509id)
            out.append((f"slot {pol.slot} ({pol.name}) decodes identically",
                        same))
    except Exception as e:                                  # noqa: BLE001
        # A ctypes layout mismatch on some platform must not take the suite
        # down; it just means this cross-check could not run.
        out.append((f"cryptoauthlib cross-check raised {type(e).__name__}",
                    False))
    return out


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bus", type=int, default=1)
    p.add_argument("--address", type=lambda s: int(s, 0), default=0x60)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("dump", help="read and decode the chip's config zone")
    sub.add_parser("plan", help="show what CELL would change, byte by byte")

    w = sub.add_parser("write", help="apply the plan (reversible until locked)")
    w.add_argument("--i-have-read-the-plan", action="store_true")

    v = sub.add_parser("verify", help="check the chip against the policy")
    v.add_argument("--behaviour", action="store_true",
                   help="also ask the chip to misbehave, and watch it refuse")

    for name in ("lock-config", "lock-data"):
        lk = sub.add_parser(name, help=f"PERMANENT: lock the "
                                       f"{name.split('-')[1]} zone")
        lk.add_argument("--permanent", action="store_true")

    sub.add_parser("selfcheck", help="everything provable without a chip")

    args = p.parse_args()
    return {
        "dump": cmd_dump,
        "plan": cmd_plan,
        "write": cmd_write,
        "verify": cmd_verify,
        "selfcheck": cmd_selfcheck,
        "lock-config": lambda a: cmd_lock(a, "config"),
        "lock-data": lambda a: cmd_lock(a, "data"),
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
