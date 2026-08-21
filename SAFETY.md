# Safety

**Read this before the first build.** This device is deliberately a
blood-contact device. That carries real, well-understood risks, and they are
managed by procedure rather than by engineering.

This is not legal boilerplate and it is not a disclaimer. It is the operating
procedure.

---

## Do not use the blood tier if

- You take **anticoagulants** — warfarin, DOACs (apixaban, rivaroxaban),
  clopidogrel, or daily aspirin
- You have a **bleeding or clotting disorder**
- You are **immunocompromised**
- You have **poor peripheral circulation**

Note the irony on anticoagulants: your blood will not clot, so the coagulation
gate rejects every sample. **The device physically will not work for you.**
This is a real exclusion, not a hypothetical, and it rules out a meaningful
share of adults over 60. Use the touch tier, or use a different device.

## The five rules

1. **One device, one person. Never share.** Hepatitis B survives on dry
   surfaces for up to seven days and is far more infectious by blood exposure
   than HIV. A shared blood-contact device is a transmission vector. There is
   no cleaning procedure that makes sharing acceptable.

2. **Commercial sterile single-use lancets only.** Contact-activated, 28G /
   1.8 mm. Never reuse, never resharpen, never substitute a blade or needle. A
   used lancet tip is both dull and contaminated, and a dull tip hurts more and
   bleeds worse.

3. **One cartridge, one use, then a sharps container.** Used cartridges and
   lancets are biohazard, not household waste. A 1 L sharps container is on the
   BOM and is not optional.

4. **Alcohol before, pressure and a plaster after.** Rotate fingers. Use the
   sides of the pad, not the centre — the centre has the densest nerve supply
   and is what you type with.

5. **Rate limit: about two blood authorisations per day, sustained.** The blood
   tier is for cold storage and infrequent high-value operations. Routine
   signing uses the touch tier. If your usage pattern needs more than this,
   your policy floor is set wrong.

## During calibration

Calibration needs 30+ genuine captures, and `BUILD.md` §13 asks for 100 for a
meaningful bound. **Do not take 100 samples from one person in one day.**

- Use one larger venous draw to supply the negative classes (aged, EDTA,
  haemolysed, deoxygenated) rather than lancing repeatedly
- Spread genuine capillary trials over weeks
- Rotate fingers and sites throughout

## Stop and see a doctor

- Spreading redness, warmth or swelling around a puncture site
- Pus, or red streaking running up the finger
- Fever
- Bleeding that will not stop after 10 minutes of direct pressure

## Laser

The speckle path uses a 650 nm diode module at ≤5 mW (Class 3R). It is
interlocked to the cartridge switch and enclosed in a light-tight chamber
during normal operation. **During bring-up the chamber is open.** Do not look
into the beam, do not aim it at anyone, and remove reflective jewellery when
working near it.

## What this device does not do

It is not a medical device. It does not diagnose anything, it does not measure
your coagulation status, and a rejection tells you nothing about your health —
it usually means the optics need cleaning. Do not read a clinical result into a
gate failure.
