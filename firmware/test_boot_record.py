"""A damaged provisioning record must produce a sentence, not a traceback.

The record lives on /boot/cell, so this is not an attack surface: anyone who
can edit it already holds the device. It is an availability one. A partial
write during provisioning, or a bit flipped on an SD card that spent a year in
a drawer, and the device stops booting.

What made that worse than it needed to be is where the read happens. It runs
before the loop that exists so the device never dies, and before a display
exists to say anything on -- so the failure arrived as a traceback on a serial
console nobody is attached to, on a device that simply would not start.

The seed is never lost when this happens. The record is public data and the
backup words still restore. So the only thing the device has to do is say
which of those two things has gone wrong.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import provision


def _dir(accounts: str | None = None, blob: bytes | None = None) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(prefix="cell-record-"))
    if accounts is not None:
        (d / provision.ACCOUNTS).write_text(accounts)
    if blob is not None:
        (d / provision.BLOB).write_bytes(blob)
    return d


def run() -> int:
    ok, checks = True, []

    def case(label: str, d: pathlib.Path):
        nonlocal ok
        try:
            provision.load(d)
            good, detail = False, "no error raised"
        except provision.BadRecord as e:
            # A reason a person can act on: which file, and what about it.
            good = bool(str(e)) and any(
                n in str(e) for n in (provision.ACCOUNTS, provision.BLOB))
            detail = str(e)[:58]
        except Exception as e:                                  # noqa: BLE001
            good, detail = False, f"{type(e).__name__} leaked: {e}"[:58]
        ok &= good
        checks.append((label, good, detail))

    case("nothing on the card", _dir())
    case("accounts.json absent", _dir(blob=b"\x00" * 64))
    case("accounts.json truncated mid-write", _dir("{\"accounts\": [", b"\x00" * 64))
    case("accounts.json is not JSON at all", _dir("\x00\xff garbage", b"\x00" * 64))
    case("a required field is missing",
         _dir(json.dumps({"accounts": []}), b"\x00" * 64))
    case("a field has the wrong type",
         _dir(json.dumps({"master_fingerprint": 12345, "accounts": []}),
              b"\x00" * 64))
    case("an account entry is malformed",
         _dir(json.dumps({"master_fingerprint": "aabbccdd",
                          "accounts": [{"nonsense": 1}]}), b"\x00" * 64))
    case("the seed blob is corrupt",
         _dir(json.dumps({"master_fingerprint": "aabbccdd", "accounts": []}),
              b"not a seed blob"))

    # BadRecord must be reachable from the boot path without importing the
    # provisioning tool, or app.py cannot catch it by type.
    checks.append(("BadRecord is exported for the boot path",
                   hasattr(provision, "BadRecord")
                   and issubclass(provision.BadRecord, Exception), ""))
    ok &= checks[-1][1]

    print(f"{'corruption':<38}{'result':>8}")
    print("-" * 72)
    for label, good, detail in checks:
        print(f"  {label:<36}{'PASS' if good else 'FAIL':>8}"
              + (f"   {detail}" if detail else ""))
    print("-" * 72)
    print(f"{len(checks)} checks. " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
