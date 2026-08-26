# Bounty: build one and sign with it

Everything you need to build one is in this repo.

**Build the device. Sign with a pulse. Sign with fresh blood. Post pictures.**

**[Bounty 24 on poidh](https://poidh.xyz/mainnet/bounty/24)**, on mainnet. It
is topped up over time, so the listing carries the amount and this file
deliberately does not.

## Cost

**~$98 in hardware, ~$31 in consumables.** `BOM.csv` lists every part with
sourcing. The bounty is worth more than the build.

## Build it

`BUILD.md` §15, milestones 1 to 14. Wiring in `diagrams/wiring.svg`, optical
head in `diagrams/build-sheet.svg`, printables in `models/print/`.

Milestone 14 is the restore drill: wipe the device, restore from your paper
backup, spend again. Do it before you claim.

## Before you start

Read `SAFETY.md`. One device per person, one lancet per use, sharps container.

The gate wants a fresh sample from anybody. Anyone on anticoagulants will be
rejected every time, since clotting is the thing being measured.

Two things to know:

- `firmware/hardware.py` has never touched hardware. Treat it as a wiring
  diagram in Python. It has a bring-up checklist.
- Locking the chip is permanent. `lock-data` refuses a chip that fails its own
  policy or does not enforce it, so the tool covers you. Run
  `atecc_config.py verify --behaviour` first and read it anyway.

## Claim it

Submit the claim on [the bounty page](https://poidh.xyz/mainnet/bounty/24),
with pictures or video of:

1. The assembled device, running
2. A signature authorised by a pulse
3. A signature authorised by a fresh blood sample
4. The transaction on chain. Testnet is fine

And say what you had to change to make it work, if anything.

## Partial claims count

**Reader only.** Milestone 7, a spoof panel run, `thresholds.json` and
`captures/` posted. That is the half carrying the novel physics, and the
cheaper one to reach at $62. Open an issue here with the numbers as well as
claiming on poidh: `CONTRIBUTING.md` says what makes a panel run useful to
everybody else, and the captures are `.npz` so they can be replayed safely.

**A failure is a claim too.** If dye passes a gate, or real blood fails on your
optics, post it. That answer is worth paying for.

`VALIDATION.md` tracks what has been verified and what is waiting on a first
build. You're the one who moves rows from the second list to the first.
