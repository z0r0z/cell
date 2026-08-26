#!/usr/bin/env python3
"""Prose lint: keep the reference documents flat.

The docs suite in run_tests.py checks that the numbers in the documentation
match the code. This checks the prose itself, for one specific failure: the
cadence that creeps in when a reference document gets written in the voice of
a pitch.

Two rules.

BANNED PHRASES are a hard error anywhere. They are the ones that address the
reader as a pupil ("use common sense", "make sure") or minimise the thing they
are asking for ("two minutes"). A build document tells you what to do and what
it costs; it does not tell you how you ought to feel about the effort.

TIC DENSITY is a budget, in hits per thousand words, per file. The tics are
constructions that are fine once and conspicuous at scale -- antithesis
("X, not Y"), the em-dash used where a full stop would do, the closing clause
that restates the paragraph as an aphorism. README and BOUNTY sell the thing
and are allowed a looser budget. BUILD, VALIDATION and PRINTING are reference
material read by someone holding a soldering iron, and are held tight.

The budgets are a ratchet, set just above where the documents actually sit.
Lowering one is a contribution. Raising one needs a reason in the commit.

    python3 tools/prose_lint.py            # report and exit non-zero on failure
    python3 tools/prose_lint.py --verbose  # quote every hit
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Hits per thousand words. Set from the measured value, rounded up a little.
BUDGETS = {
    "README.md": 9.0,
    "BOUNTY.md": 9.0,
    "BUILD.md": 6.0,
    "VALIDATION.md": 6.0,
    "PRINTING.md": 6.0,
    "SAFETY.md": 6.0,
    "CONTRIBUTING.md": 6.0,
    "models/README.md": 6.0,
}

BANNED = {
    "use common sense": "say the rule instead",
    "two minutes": "do not price the reader's attention for them",
    "make sure": "state the check",
    "be sure to": "state the check",
    "remember to": "state the check",
    "don't forget": "state the check",
    "needless to say": "then do not say it",
    "it goes without saying": "then do not say it",
    "as you can see": "the reader can see",
    "obviously": "if it were, it would not need saying",
    "of course": "if it were, it would not need saying",
}

TICS = {
    "antithesis": r",\s+not\s+(?:a|an|the|to|one|two|three|what|how|because|by|its|their|something|someone)\b",
    "rather than": r"\brather than\b",
    "em dash": r"—",
    "that is why": r"\b(?:that is why|which is why|that is what|which is what|is the reason)\b",
    "the one thing": r"\bthe (?:one|only) thing\b",
    "worth noting": r"\bworth (?:doing|noting|having|reading|knowing|stating|saying)\b",
    "what it is not": r"(?i)\bwhat (?:it|this) is not\b",
}

FENCE = re.compile(r"```.*?```", re.S)
INLINE = re.compile(r"`[^`\n]*`")


def prose(text: str) -> str:
    """The document with the parts nobody reads as prose removed.

    Code is exempt: a shell line is allowed an em-dash and a Python
    identifier is allowed to contain "not_a". Everything else counts,
    including table cells, because that is where BUILD.md keeps most of
    its sentences.
    """
    return INLINE.sub(" ", FENCE.sub(" ", text))


def scan(path: pathlib.Path) -> tuple[int, dict[str, list[str]], list[tuple[str, str]]]:
    body = prose(path.read_text())
    words = len(body.split())
    hits: dict[str, list[str]] = {}
    for name, pattern in TICS.items():
        found = [m.group(0) for m in re.finditer(pattern, body)]
        if found:
            hits[name] = found
    banned = [(phrase, why) for phrase, why in BANNED.items()
              if re.search(rf"\b{re.escape(phrase)}\b", body, re.I)]
    return words, hits, banned


def quote(path: pathlib.Path, pattern: str, limit: int = 4) -> list[str]:
    body = prose(path.read_text())
    out = []
    for m in re.finditer(pattern, body):
        a, b = max(0, m.start() - 60), min(len(body), m.end() + 40)
        out.append("..." + " ".join(body[a:b].split()) + "...")
        if len(out) >= limit:
            break
    return out


def check() -> tuple[bool, list[str]]:
    """(ok, report lines). What run_tests.py calls."""
    ok, lines = True, []
    for name in sorted(BUDGETS):
        path = ROOT / name
        if not path.exists():
            lines.append(f"{name}: MISSING")
            ok = False
            continue
        words, hits, banned = scan(path)
        total = sum(len(v) for v in hits.values())
        density = total / words * 1000 if words else 0.0
        budget = BUDGETS[name]
        if density > budget:
            worst = sorted(hits.items(), key=lambda kv: -len(kv[1]))[:3]
            lines.append(f"{name}: {density:.1f} per 1k against a budget of "
                         f"{budget:.1f} ({', '.join(f'{k} x{len(v)}' for k, v in worst)})")
            ok = False
        for phrase, why in banned:
            lines.append(f'{name}: banned phrase "{phrase}" -- {why}')
            ok = False
    return ok, lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="quote the hits behind each over-budget file")
    ap.add_argument("files", nargs="*", help="default: every file with a budget")
    args = ap.parse_args()

    names = args.files or sorted(BUDGETS)
    ok = True
    print(f"{'file':<20}{'per 1k':>8}{'budget':>8}{'hits':>6}{'words':>7}  worst")
    for name in names:
        path = ROOT / name
        if not path.exists():
            print(f"{name:<20}  MISSING")
            ok = False
            continue
        words, hits, banned = scan(path)
        total = sum(len(v) for v in hits.values())
        density = total / words * 1000 if words else 0.0
        budget = BUDGETS.get(name, 6.0)
        worst = max(hits.items(), key=lambda kv: len(kv[1]), default=("", []))
        flag = " " if density <= budget else "F"
        print(f"{name:<20}{density:>8.1f}{budget:>8.1f}{total:>6}{words:>7}  "
              f"{worst[0]}:{len(worst[1])}{flag:>2}")
        if density > budget:
            ok = False
            if args.verbose:
                for tic, found in sorted(hits.items(), key=lambda kv: -len(kv[1])):
                    print(f"    {tic} x{len(found)}")
                    for q in quote(path, TICS[tic]):
                        print(f"      {q}")
        for phrase, why in banned:
            print(f"    BANNED: \"{phrase}\" -- {why}")
            ok = False

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
