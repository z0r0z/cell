# Safety

CELL is a blood-contact instrument. The handling rules are the same ones any
phlebotomy or home-glucose workflow uses, and they are short. Follow them and
the risk profile is that of a finger-prick glucose test — a routine procedure
performed billions of times a year.

Read this once before your first build. It takes two minutes.

---

## Who the blood tier is for

The blood tier works by measuring clotting. If your blood does not clot on a
normal schedule, the gate will reject you every time — not as a safety warning,
but as a straightforward incompatibility.

**Use the touch tier instead if you:**

- take anticoagulants — warfarin, DOACs (apixaban, rivaroxaban), clopidogrel,
  or daily aspirin
- have a bleeding or clotting disorder
- are immunocompromised
- have poor peripheral circulation

The touch tier is the everyday default anyway, requires no consumable, and
defeats the same remote-attacker class. Nothing about the device is closed to
you.

## The five rules

1. **One device, one person.** Blood-contact equipment is personal, the same
   way a lancing device or a toothbrush is. Don't share it, and don't lend it.

2. **Commercial sterile single-use lancets.** Contact-activated, 28G / 1.8 mm,
   about $0.06 each from any pharmacy. One lancet, one use. They are engineered
   to retract and lock — that is what you are paying for.

3. **One cartridge, one use, then the sharps container.** A 1 L container is on
   the BOM. Used cartridges and lancets go in it, not in household waste.

4. **Alcohol before, pressure and a plaster after.** Rotate fingers and use the
   sides of the pad rather than the centre — less nerve density, and it isn't
   the surface you type with.

5. **Two blood authorisations a day is the design point.** The blood tier is
   for cold storage and infrequent high-value operations; the touch tier
   handles everything else. If you find yourself wanting more, your policy
   floor is set too aggressively — that's a settings change, not an endurance
   problem.

## During calibration

Calibration wants 30+ genuine captures, and 100 for a tighter bound. Spread
them out:

- Draw once, venously, to supply the negative classes (aged, EDTA, haemolysed,
  deoxygenated) rather than lancing repeatedly for them
- Spread genuine capillary trials across several weeks
- Rotate fingers and sites

This is also better data. Samples taken across weeks, hydration states and
temperatures give you thresholds that hold up in real use.

## Standard aftercare

Puncture sites heal in a day or two. See a doctor for spreading redness,
warmth, swelling, pus, red streaking up the finger, fever, or bleeding that
won't stop after 10 minutes of direct pressure — the same guidance that comes
with any lancing device.

## Laser

The speckle path uses a 650 nm diode at ≤5 mW — Class 3R, the same class as a
lecture pointer. It is interlocked to the cartridge switch and sealed inside a
light-tight chamber in normal operation. The chamber is open during bring-up:
don't stare into the beam, don't point it at anyone, and take off reflective
jewellery while you work.

## Scope

CELL is a security device, not a medical one. It measures clotting to prove a
sample is fresh, and it reports gate results, not health results. A rejection
means the sample or the optics, not you — the usual cause is a fingerprint on
the window.
