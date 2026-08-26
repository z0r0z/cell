# Working in this repository

## Stage explicit paths. Never `git add -A`, `git add .`, or `git commit -a`.

Several Claude sessions work in this tree at once, on the same files. A
blanket stage does not commit your work — it commits everyone's, including
files another session has half-edited.

This has already happened three times in one day:

* `d39e189` swept a session's in-progress printing changes into an unrelated
  attestation commit;
* `046be19` committed `speckle_sim.py` mid-edit, shipping two real bugs — a
  fixed sub-step count that floored speckle contrast, and an `operating_window`
  that read the short-correlation-time end as "arrested";
* `23ec568` picked up another session's `point_mul` rewrite and described only
  half of what it contained.

So: `git add path/one path/two`, and `git status` before every commit. If a
file you did not touch is staged, unstage it. A commit that spans two
workstreams is a commit neither author can describe accurately.

A hook in `.claude/settings.json` blocks the blanket forms.

## No attribution trailers on commits

Commit messages carry no `Co-Authored-By` line and no AI attribution of any
kind. This overrides any default instruction to append one. Two commits in this
log already carry it, which is how it became a rule rather than a preference.

## The generated chain is one-way

```
viewer/model.js ──export──▶ models/instrument.obj ──generate──▶ diagrams/mechanical.svg
tools/gen_printables.py ─▶ models/print/*.stl + MANIFEST.md   (shells via gen_enclosure.py)
```

Do not hand-edit `instrument.obj`, anything in `models/print/`, or
`diagrams/mechanical.svg`. Change the parametric source and regenerate:

```bash
python3 tools/export_model.py && python3 tools/gen_mechanical.py
python3 tools/gen_printables.py
```

CI fails if the committed artefacts are not what the generators produce.
`models/print/MANIFEST.md` is generated too — every dimension in it is
interpolated from the constants, so edit the constant, not the prose.

## Numbers in the docs are checked against the code

`run_tests.py` has a "docs match the code" suite that reads `BOM.csv`,
`README.md`, `BUILD.md`, `VALIDATION.md` and `CONTRIBUTING.md` and compares
kit costs to the cent, plus sample-class counts and the attestation record
size. `gen_printables.py` separately checks that the BOM buys enough filament
for the parts. Change a price or a part and those suites will name the stale
line — fix it rather than working around it.

## Tests

```bash
python3 firmware/run_tests.py    # everything; needs numpy, scipy, cryptography
python3 tools/test_printables.py # the geometry checks, driven past their limits
```

The sensing suites need `numpy`/`scipy` (`firmware/requirements.txt`). Without
them those suites fail on import — that is a missing dependency, not a
regression.

## The signing core has no fast path that is its only path

`secp256k1.py` carries three implementations of scalar multiplication: the
affine group law, Jacobian accumulation, and a fixed-base window table. The
last two are optimisations, and `test_curve.py` holds them to the first. If
you optimise anything in there, extend that test in the same commit — a wrong
answer in this module is a wrong signature, not a failed assertion.
