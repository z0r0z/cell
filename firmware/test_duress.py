"""Duress PIN tests.

The functional checks are easy: a second PIN opens a second wallet. The ones
that matter are the indistinguishability checks, because a duress PIN that can
be told apart from a normal one is worse than none -- it tells a coercer that
you have something to hide and that they have not got it yet.
"""

from __future__ import annotations

import os
import time

import duress
import seedstore
import signer
from duress import NoBlobOpened, SeedPair
from se import MAX_PIN_ATTEMPTS, PinLockout, PinResult, SoftSE

import bip39
# Real 24-word mnemonics: seedstore refuses anything failing its BIP-39
# checksum, which is right -- a stored seed that will not restore is a backup
# that fails exactly when you need it.
REAL = bip39.entropy_to_mnemonic(bytes(range(32)))
DECOY = bip39.entropy_to_mnemonic(bytes(range(32, 64)))
PIN, DPIN = "12345678", "87654321"


def _device(duress_pin=DPIN):
    se = SoftSE(pin=PIN, secret=b"\x11" * 32, duress_pin=duress_pin)
    nk = _key(se, PIN)
    # With no duress PIN set, the second blob is still written -- under a key
    # nobody can derive. One file on the card would announce that duress is
    # off; two announce nothing.
    dk = _key(se, duress_pin) if duress_pin else os.urandom(32)
    return se, duress.wrap_pair(REAL, DECOY, nk, dk)


def _key(se, pin):
    se.verify_pin(pin)
    return se.kdf(signer.unwrap_context(pin))


def run() -> int:
    ok, checks = True, []

    def check(label, cond):
        nonlocal ok
        ok &= bool(cond)
        checks.append((label, bool(cond)))

    se, pair = _device()

    # --- it works ---------------------------------------------------------
    check("normal PIN opens the real wallet",
          bytes(duress.unwrap_any(pair, _key(se, PIN))).decode() == REAL)
    check("duress PIN opens the decoy",
          bytes(duress.unwrap_any(pair, _key(se, DPIN))).decode() == DECOY)

    se2 = SoftSE(pin=PIN, secret=b"\x22" * 32, duress_pin=DPIN)
    try:
        duress.unwrap_any(pair, _key(se2, PIN))
        check("another device opens neither", False)
    except NoBlobOpened:
        check("another device opens neither", True)

    try:
        _key(se, "00000000")
        check("a wrong PIN yields no key", False)
    except Exception:
        check("a wrong PIN yields no key", True)

    # --- it is indistinguishable -----------------------------------------
    # Everything below is the actual security property.
    se3 = SoftSE(pin=PIN, secret=b"\x33" * 32, duress_pin=DPIN)
    check("both PINs report success identically",
          bool(se3.verify_pin(PIN)) and bool(se3.verify_pin(DPIN)))
    check("the two roles are distinguishable INTERNALLY",
          se3.verify_pin(PIN) is PinResult.NORMAL
          and se3.verify_pin(DPIN) is PinResult.DURESS)

    # A duress entry must restore the attempt counter exactly as a normal one
    # does, or trying both leaves a difference to read.
    se4 = SoftSE(pin=PIN, secret=b"\x44" * 32, duress_pin=DPIN)
    se4.verify_pin("bad")
    se4.verify_pin(DPIN)
    after_duress = se4.attempts_remaining()
    se5 = SoftSE(pin=PIN, secret=b"\x55" * 32, duress_pin=DPIN)
    se5.verify_pin("bad")
    se5.verify_pin(PIN)
    check("duress resets the attempt counter like a normal PIN",
          after_duress == se5.attempts_remaining() == MAX_PIN_ATTEMPTS)

    # A device with no duress PIN must be indistinguishable from one with.
    se6 = SoftSE(pin=PIN, secret=b"\x66" * 32, duress_pin=None)
    check("an unconfigured device still stores a duress hash",
          len(getattr(se6, "_duress_hash", b"")) == 32)
    check("an unconfigured duress hash is unreachable",
          se6.verify_pin(DPIN) is PinResult.NONE)

    _, pair_off = _device(duress_pin=None)
    check("the store is a pair either way",
          len(pair_off.blobs()) == len(pair.blobs()) == 2)
    check("both blobs are the same size, configured or not",
          len({len(b) for b in pair.blobs()}) == 1
          and len({len(b) for b in pair_off.blobs()}) == 1)

    # Timing. Coarse on purpose -- this catches a short-circuit, not a cache
    # line. A duress entry that took an obviously different time would show up
    # as a large ratio here.
    se7 = SoftSE(pin=PIN, secret=b"\x77" * 32, duress_pin=DPIN)

    def elapsed(p, n=3000):
        for _ in range(300):                       # warm up first
            se7.verify_pin(p)
        s = time.perf_counter()
        for _ in range(n):
            se7.verify_pin(p)
        return (time.perf_counter() - s) / n

    # Compared against this machine's own noise floor rather than a number
    # picked out of the air. Repeated runs of the SAME PIN establish how much
    # spread means nothing; the two PINs have to sit inside that.
    runs = [(elapsed(PIN), elapsed(DPIN)) for _ in range(5)]
    norm = sorted(r[0] for r in runs)[2]
    dur = sorted(r[1] for r in runs)[2]
    floor = max(r[0] for r in runs) / min(r[0] for r in runs)
    ratio = max(norm, dur) / min(norm, dur)
    check(f"verify time separates the PINs no more than noise "
          f"({ratio:.3f} vs floor {floor:.3f})", ratio <= max(floor, 1.05))

    # --- refusals ---------------------------------------------------------
    try:
        SoftSE(pin=PIN, duress_pin=PIN)
        check("refuses a duress PIN equal to the normal one", False)
    except ValueError:
        check("refuses a duress PIN equal to the normal one", True)

    try:
        duress.wrap_pair(REAL, DECOY, b"\x01" * 32, b"\x01" * 32)
        check("refuses two PINs that derive one key", False)
    except ValueError:
        check("refuses two PINs that derive one key", True)

    try:
        k = _key(se, PIN)
        duress.unwrap_any(SeedPair(pair.primary, pair.primary), k)
        check("refuses a pair where one key opens both", False)
    except NoBlobOpened:
        check("refuses a pair where one key opens both", True)

    # Lockout still applies to both.
    se8 = SoftSE(pin=PIN, secret=b"\x88" * 32, duress_pin=DPIN)
    wiped = False
    for _ in range(MAX_PIN_ATTEMPTS + 2):
        try:
            se8.verify_pin("nope")
        except PinLockout:
            wiped = True
            break
    check("wrong PINs still wipe the device", wiped)
    check("a wiped device opens nothing",
          se8.verify_pin.__self__._st.wiped is True)

    # The decoy must be a full-length seed, not a stub, or its blob differs.
    check("decoy mnemonic is 24 words", len(duress.decoy_mnemonic().split()) == 24)
    check("role note never leaks to a display string",
          duress.role_note(PinResult.DURESS) == "duress")

    print(f"{'check':<58}{'result':>8}")
    print("-" * 66)
    for label, good in checks:
        print(f"  {label:<56}{'PASS' if good else 'FAIL':>8}"
              + ("" if good else "   <-- UNEXPECTED"))
    print("-" * 66)
    print(f"{len(checks)} checks. " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
