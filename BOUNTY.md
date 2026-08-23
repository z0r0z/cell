# Bounty: build one and sign with it

Everything you need to build one is in this repo.

**Build the device. Sign with a pulse. Sign with fresh blood. Post pictures.**

On [poidh](https://poidh.xyz), topped up over time.

## Cost

**~$98 in hardware, ~$31 in consumables.** `BOM.csv` lists every part with
sourcing. (Obviously the bounty will be for more than this amount.)

## Build it

`BUILD.md` §15, milestones 1 to 12. Wiring in `diagrams/wiring.svg`, optical
head in `diagrams/build-sheet.svg`, printables in `models/print/`.

## Claim it

Post pictures or video of:

1. The assembled device, running
2. A signature authorised by a pulse
3. A signature authorised by a fresh blood sample
4. The transaction on chain — testnet is fine

And say what you had to change to make it work (if anything).

## Partial claims count

**Reader only** — milestone 7, spoof panel run, `thresholds.json` and
`captures/` posted — is a real claim. It's the half that carries the novel
physics, and the cheaper one to reach at $62.

**A failure is a claim too.** If dye passes a gate or real blood fails on your
optics, post it. That answer is worth paying for.

## Before you start

Read `SAFETY.md` — two minutes. Use common sense.

The gate wants a fresh sample, not a
particular donor. Anyone on anticoagulants will be rejected every time, since
clotting is the thing being measured.

Two things worth knowing before you start:

- `firmware/hardware.py` has never touched hardware. Treat it as a wiring
  diagram in Python; it has a bring-up checklist.
- Locking the chip is permanent. `lock-data` refuses a chip that fails its own
  policy or does not enforce it, so the tool covers you — but run
  `atecc_config.py verify --behaviour` first and read it anyway.

`VALIDATION.md` tracks what's been verified and what's waiting on a first
build. You're the one who moves rows from the second list to the first.
