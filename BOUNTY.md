# Bounty: build one and sign with it

Nobody has built CELL. The design is complete and public. This bounty is to
prove someone can take it and produce working hardware.

**Build the device. Sign with your pulse. Sign with your blood. Post pictures.**

On [poidh](https://poidh.xyz), topped up over time.

## Cost

**~$94 in hardware, ~$31 in consumables.** `BOM.csv` lists every part with
sourcing. A weekend for the reader half, a second for the wallet half.

## Build it

`BUILD.md` §15, milestones 1 to 12. Wiring in `diagrams/wiring.svg`, optical
head in `diagrams/build-sheet.svg`, printables in `models/print/`.

## Claim it

Post pictures or video of:

1. The assembled device, running
2. A signature authorised by your pulse
3. A signature authorised by your blood
4. The transaction on chain — testnet is fine

And say what you had to change to make it work. Every build finds something.

## Partial claims count

**Reader only** (milestone 7 — spoof panel run, `thresholds.json` and
`captures/` posted) is a real claim. It's the half that decides whether the
rest is worth building.

**A failure is a claim too.** If dye passes a gate or real blood fails on your
optics, post it. That answer is worth paying for.

## Before you start

Read `SAFETY.md` — two minutes. One device one person, sterile lancets, sharps
container. If you take anticoagulants the blood tier will reject you every
time; it measures clotting.

Two things that will cost you an evening otherwise:

- `firmware/hardware.py` has never touched hardware. Treat it as a wiring
  diagram in Python; it has a bring-up checklist.
- Run `atecc_config.py verify --behaviour` **before** `lock-data`. Locking the
  chip is permanent.

`VALIDATION.md` lists everything else that's written but unverified.
