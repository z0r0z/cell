# Safety

CELL is a blood-contact instrument. The handling rules are the ones any
phlebotomy or home-glucose workflow uses. Followed, the risk is that of a
finger-prick glucose test, a routine procedure performed billions of times a
year.

Read this before your first build.

---

## Who the blood tier is for

The blood tier works by measuring clotting. If your blood does not clot on a
normal schedule the gate rejects you every time. That is an incompatibility,
not a safety warning.

**Use the touch tier if you:**

- take anticoagulants: warfarin, DOACs (apixaban, rivaroxaban), clopidogrel,
  or daily aspirin
- have a bleeding or clotting disorder
- are immunocompromised
- have poor peripheral circulation

The touch tier is the everyday default, needs no consumable, and defeats the
same remote-attacker class. Nothing about the device is closed to you.

## The five rules

1. **One device, one person.** Blood-contact equipment is personal, the way a
   lancing device or a toothbrush is. Do not share it and do not lend it.

2. **Commercial sterile single-use lancets.** Contact-activated, 28G / 1.8 mm,
   about $0.06 each from any pharmacy. One lancet, one use. They retract and
   lock, which is what you are paying for.

3. **One cartridge, one use, then the sharps container.** A 1 L container is on
   the BOM. Used cartridges and lancets go in it, never in household waste.

4. **Alcohol before, pressure and a plaster after.** Rotate fingers. Use the
   sides of the pad: less nerve density, and not the surface you type with.

5. **Two blood authorisations a day is the design point.** The blood tier is
   for cold storage and infrequent high-value operations. The touch tier
   handles everything else. Wanting more means your policy floor is set too
   aggressively, which is a settings change.

## During calibration

Calibration wants 30+ genuine captures, and 100 for a tighter bound. Spread
them out:

- Draw once, venously, to supply the negative classes (aged, EDTA, haemolysed,
  deoxygenated). Do not lance repeatedly for them
- Spread genuine capillary trials across several weeks
- Rotate fingers and sites

It is also better data. Samples taken across weeks, hydration states and
temperatures give thresholds that hold up in real use.

## Standard aftercare

Puncture sites heal in a day or two. See a doctor for spreading redness,
warmth, swelling, pus, red streaking up the finger, fever, or bleeding that
will not stop after 10 minutes of direct pressure. That is the guidance that
comes with any lancing device.

## Laser

650 nm diode at ≤5 mW. Class 3R, the same class as a lecture pointer. It is
interlocked to the cartridge switch and sealed inside a light-tight chamber in
normal operation.

The chamber is open during bring-up. Do not stare into the beam. Do not point
it at anyone. Take off reflective jewellery while you work.

## Scope

CELL is a security device. It is not a medical one. It measures clotting to
prove a sample is fresh, and it reports gate results. It says nothing about
your health. A rejection means the sample or the optics, and the usual cause
is a fingerprint on the window.
