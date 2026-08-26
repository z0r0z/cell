#!/usr/bin/env python3
"""Check viewer/instrument-standalone.html still carries this tree's viewer.

The standalone bundle is what gets deployed — cell.wei.is serves it, and it is
the file you paste into IPFS or a gist. It inlines four things out of the
source tree:

    viewer/model.js          the parametric model
    viewer/three-d-stage.js  the renderer shell
    viewer/instrument.html   its <style> block, and its .wrap markup

Nothing rebuilt it. Change any of those four and every other job stays green
while the bundle keeps serving the previous version, which is exactly how the
deployed page spent three commits without the link-preview tags that had
already landed in the repository.

Rebuilding here would need the network (three.js is fetched from unpkg and
checked against the pinned integrity map), and a CI job that reaches out to a
CDN fails for reasons that have nothing to do with the commit. So this compares
instead: whatever three.js the bundle was built with is left alone, and the
four things that come from this tree must match it byte for byte.

    python3 tools/check_standalone.py

Exits non-zero, naming the stale payload, with the command that fixes it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VIEWER = ROOT / "viewer"
BUNDLE = VIEWER / "instrument-standalone.html"
SOURCE = VIEWER / "instrument.html"

REBUILD = "python3 tools/build_single_file_viewer.py"


def payload(bundle: str, ident: str) -> str | None:
    """One <script type="text/plain"> block, with the builder's escaping undone."""
    m = re.search(r'<script type="text/plain" id="%s">(.*?)</script>' % ident,
                  bundle, re.S)
    if not m:
        return None
    # build_single_file_viewer.py rewrites '</script' so an inline block cannot
    # be ended early by a string or a comment in the payload itself.
    return m.group(1).replace("<\\/script", "</script")


def main() -> int:
    if not BUNDLE.exists():
        sys.exit(f"{BUNDLE} is missing. Run: {REBUILD}")
    bundle = BUNDLE.read_text(encoding="utf-8")
    page = SOURCE.read_text(encoding="utf-8")

    problems: list[str] = []

    for ident, src in (("p-model", VIEWER / "model.js"),
                       ("p-stage", VIEWER / "three-d-stage.js")):
        got = payload(bundle, ident)
        want = src.read_text(encoding="utf-8")
        if got is None:
            problems.append(f"{src.relative_to(ROOT)}: no '{ident}' payload in the bundle")
        elif got != want:
            problems.append(
                f"{src.relative_to(ROOT)}: bundle carries a different copy "
                f"({len(got)} bytes inlined, {len(want)} bytes in the tree)")

    # The <style> and the .wrap markup are lifted out of instrument.html rather
    # than duplicated in the builder, so both must appear in the bundle verbatim.
    style = re.search(r"<style>(.*?)</style>", page, re.S)
    if not style:
        sys.exit(f"no <style> block in {SOURCE.relative_to(ROOT)}")
    if style.group(1) not in bundle:
        problems.append("viewer/instrument.html: the page's <style> is not in the bundle")

    body = re.search(r'<div class="wrap">(?:.*?)\n</div>', page, re.S)
    if not body:
        sys.exit(f'no <div class="wrap"> block in {SOURCE.relative_to(ROOT)}')
    if body.group(0) not in bundle:
        problems.append("viewer/instrument.html: the page's .wrap markup is not in the bundle")

    if problems:
        print("viewer/instrument-standalone.html is out of date:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(f"\nRun: {REBUILD}", file=sys.stderr)
        print("Then redeploy — the bundle in the repository is not the page "
              "that is live until it is pushed to the host.", file=sys.stderr)
        return 1

    print("viewer/instrument-standalone.html carries this tree's model.js, "
          "three-d-stage.js, style and markup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
