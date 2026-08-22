# CELL — Build Specification

Rev 0.5. Single device, $90.50 in hardware plus $31.00 of consumables, Raspberry Pi Zero 2 W, 3D-printed shell over the Pi.

The enclosure comes from `viewer/model.js`, a parametric three.js model. `models/instrument.obj` is its export — 131 named objects with materials, 116.2 × 73.2 × 28.3 mm — and `diagrams/mechanical.svg` is generated from that by `tools/gen_mechanical.py`, so the drawing cannot drift from the model. See §10.

This specification is complete enough to build from. Sensing thresholds ship as physics-derived defaults and are calibrated to your hardware in §13 — the same step any instrument needs before it is trusted. `VALIDATION.md` is the engineering status record. Use testnet until you have run the calibration.

---

## 1. What you're building

An airgapped hardware wallet, 116 × 73 × 28 mm. Transactions enter and leave as QR codes; there is no wifi, bluetooth or USB data path. Signing requires a PIN and one of two liveness proofs.

```
   operation ──(QR)──▶  camera ─▶ parse ─▶ render as readable text ─▶ confirm
                                                  │
                                    PIN  +  PULSE or BLOOD
                                                  │
                        seed decrypted in RAM ─▶ sign ─▶ zeroise
                                                  │
   authorisation ◀──(QR)─────────────────────────┘
                    companion submits it and pays the fee
```

Four elements, kept separate:

| Element | Mechanism | Establishes |
|---|---|---|
| Touch tier | 7-gate photoplethysmography, 15 s | A living body is present |
| Blood tier | 6-gate optical and speckle liveness, 10 min | A living body bled, just now |
| PIN | ATECC608B with a monotonic attempt counter | Identity |
| Seed | BIP39, AES-256-GCM at rest, key held by the ATECC608B | The signing secret |

The seed is backed up on paper or steel as with any conventional hardware wallet.

---

## 2. Two kits, ordered separately

The blood reader is the novel component. The wallet layer is a solved problem that can be forked from an existing project, so you build and buy them as two separate kits.

**"Phase" here means a shopping list, not a schedule.** Every row in `BOM.csv` carries a `Kit` column that says which one it belongs to:

| Kit | What it is | Cost |
|---|---|---|
| `Reader` | The blood reader hardware — Pi, spectrometer, laser, camera, LEDs, filament | $60.10 |
| `Reader consumable` | Lancets, alcohol pads, PET window film, tape, sharps container. Needed to run the reader at all, and good for hundreds of runs | $31.00 |
| `Wallet` | The signing half — secure element, display, buttons, QR camera, fasteners | $30.40 |

Order the reader kit and its consumables together; they are one purchase and the reader is useless without both. The wallet kit is a second purchase you only make if the reader works.

### Kit 1 — the blood reader ($60.10 hardware + $31.00 consumables, one weekend)

| Item | ~USD |
|---|---|
| Raspberry Pi Zero 2 W | 15 |
| AS7341 spectrometer breakout | 16 |
| 2 × white LED, 1 × 940 nm IR LED | 1.30 |
| 650 nm laser diode module | 2.00 |
| Pi Camera + mini-CSI cable | 10.00 |
| 2 × 2N7002 + resistors | 1.30 |
| 16 GB microSD | 6 |
| Jumper wires, small breadboard | 5 |
| PETG white + black, ~40 g | 3.50 |

Plus the reader consumables ($31.00): 100 sterile lancets, 100 alcohol pads, PET window film, 3M 300LSE tape, and a 1 litre sharps container. Every one of them is needed to run the spoof panel in §13, so budget them with the hardware rather than after it. They cover hundreds of runs — 100 sheets of film is about 1600 windows.

The reader has no security requirements, because nothing is being signed. Leave wifi enabled, work over SSH, print results to the console. No display, secure element, enclosure or airgap is needed. The only printed parts are a light-tight optical chamber and a plate of cartridges.

It answers the question that determines whether the rest is worth building: does the gate separate real blood from every fake? Run the spoof panel in §13. If it does not, you never order the wallet kit.

### Kit 2 — the wallet (+$30.40)

| Item | ~USD |
|---|---|
| ST7789 1.3" 240×240 SPI display | 8 |
| USB webcam, for QR ingest | 8 |
| ATECC608B breakout | 6 |
| 4 × 12 mm tactile buttons | 3 |
| USB-C breakout, power only | 2 |
| M2.5 screws + heat-set inserts | 2.40 |

Fork SeedSigner, insert the gate before `sign()`, then do the airgap hardening: radios disabled, antenna trace cut, read-only rootfs.

**Full device: $90.50 of hardware,** plus $31.00 of consumables that last hundreds of uses. $121.50 all in.

---

## 3. Sensing architecture

| | Sensor | Asks |
|---|---|---|
| **Chemistry** | AS7341 spectrometer + 3 LEDs | Is it blood? |
| **Liveness** | 650 nm laser + camera, speckle | Is it alive? |

The split matters because the two questions have different physics and one sensor is bad at both.

**Chemistry.** Haemoglobin's Soret band at 415 nm is roughly an order of magnitude stronger than anything else in the visible spectrum, and nothing in a kitchen has one. Four gates off one $16 part.

**Liveness is not a reflectance measurement.** What changes during clotting is the *motion* of the scatterers — red cells go from free Brownian motion to being locked in a fibrin network. Bulk reflectance barely registers that. Coherent light does: a speckle pattern from a liquid suspension boils, and a speckle pattern from a clot is frozen. This is why every established low-cost optical coagulometer uses a laser and a camera rather than a photodiode.

The measurement is **frame-to-frame speckle decorrelation**:

```
D = 1 − (correlation between consecutive frames)

    liquid blood   D ≈ 1.0    speckle fully decorrelates between frames
    clotted blood  D ≈ 0.0    pattern is static
```

The signal is close to binary. This is why the liveness gate measures motion rather than reflectance.

### The liveness test assumes no curve shape

Published coagulation indices disagree about whether clotting is exponential, sigmoid, or something else. The test does not need to know. It asks three things:

The frames are spatially high-passed before they are correlated. That is not cosmetic: real lensless speckle rides on a strongly non-uniform beam envelope which is *identical* frame to frame, and correlating raw frames measures the envelope rather than the speckle — enough to hold the correlation above 0.5 while the speckle is fully boiling, which fails Gate 5 on genuine blood. Each frame is high-passed independently; subtracting a temporal mean instead would invert the gate, because a frozen field minus its own mean is pure noise and decorrelates perfectly.

1. **Did it start moving freely?** `D(early) ≥ 0.60`
2. **Did it stop?** `D(late) ≤ 0.25`
3. **Was the transition real and in the right direction?** drop `≥ 0.35`, Spearman ρ `≤ −0.70`

This restates the security argument in measurable terms:

> Fresh blood is the only sample that starts decorrelated and becomes correlated. Anticoagulated blood never stops moving. Already-clotted blood, syrup and gels never started. Dye has no speckle at all.

---

## 4. Two tiers

| | **Touch** | **Blood** |
|---|---|---|
| Proves | A living body **is** here | A living body **bled** here |
| Action | Fingertip on the ring | A drop in a cartridge |
| Time | 15 s | 10 min |
| Consumable | None | Cartridge + lancet |
| Added parts | **Zero** | — |
| Defeats | Malware, automation, remote signing | All of that, plus stored samples |

Touch mode is photoplethysmography. Arterial blood volume in the fingertip changes with each heartbeat, so light coming back through the ring bore carries a small pulsatile signal on a large steady one. The white LED gives a red channel, the 940 nm LED gives infrared, the AS7341 samples both at 50 Hz. **The ring bore is the sensor port in both modes** — a finger on it, or a cartridge under it.

### Seven gates, `firmware/touch_gate.py`

| # | Gate | Test | Catches |
|---|---|---|---|
| T0 | Capture rate | Achieved sample rate ≥ 20 Hz | A hardware timing fault. Not an anti-spoof gate — see below |
| T1 | Contact | DC level 8–85% of the empty bore | Nothing on the ring; or pressed so hard perfusion is occluded |
| T2 | Pulsatile | Perfusion index 0.3–10% | Static objects, printed photos — and, at the ceiling, motion |
| T3 | Rate | Dominant frequency 40–180 bpm | Anything not beating like a heart |
| T4 | Cardiac band | ≥45% of band power at the fundamental | Broadband noise, artefact |
| T5 | Variability | RMSSD 5–250 ms | **Mechanical pulsators.** A real heart is not a metronome |
| T6 | Haemoglobin ratio | Red/IR ratio-of-ratios 0.40–0.90 | **Dye-based fake fingers** |

T6 is the important one, and it is the same physics the blood mode uses at 415 nm applied to a living finger. A silicone finger with red dye pumped through it can produce a convincing pulse, but dye does not have haemoglobin's red-to-infrared absorption ratio. It also catches motion from the other side: a geometry change hits both wavelengths equally and drives the ratio toward 1.0, while real perfusion sits near 0.6.

**T0 exists because the sample rate is not a constant.** Every gate after it is computed in units of `fs`, so a capture taken at 8 Hz and analysed at a nominal 50 Hz reports a 68 bpm heart as ~11 bpm and fails T3. That sends the user hunting a heart problem that is really an I²C timing problem. `read_ppg` measures the rate it actually achieved and returns it; the analysis uses that number, and T0 refuses the capture outright if it is too low to analyse. The AS7341's chemistry integration time is 281 ms per channel and **cannot** produce a PPG waveform — touch mode switches to a short ATIME and back. See `hardware.py`.

Two of the thresholds are physiology, not tuning. **Perfusion above 10%** cannot be blood volume in tissue — the sensor or the finger moved. **Respiratory sinus arrhythmia** puts a healthy resting adult's RMSSD in the tens of milliseconds; a pump produces single digits.

### Touch is the default. Blood is a mode you enter.

Everyday operations run on touch. Blood is deliberate — you choose it, the way you'd choose to swear to something.

That only holds if the choice runs one way:

> **You can always escalate. You can never de-escalate.**

If blood were purely opt-in, an attacker holding the device and the PIN would simply never opt in, and the top tier would be decorative. So policy sets a floor. You may enter blood mode for a trivial transfer because it feels significant — that is a valid act and the device permits it. You may not go under the floor, ever, and there is no override.

**Changing the policy is itself blood-locked.** This is the rule people leave out, and it is the only thing separating a two-tier device from a one-tier device with extra steps. Without it the attack isn't "defeat the blood gate", it's "lower the threshold, then use a finger" — which needs no blood at all.

Permanently blood-locked at provisioning, not configurable:

```
policy.change · key.export · device.wipe · device.reprovision · recipient.allowlist
```

Everything else is yours to set: an amount threshold, specific operation classes, or nothing at all.

### Escalation and the floor are different things

| | Scope | Persists? | Costs blood to change |
|---|---|---|---|
| **Escalation** | This one operation | No — the next one reverts to the floor | — |
| **The floor** | A standing rule | Yes, until changed | **Yes, in either direction** |

Choosing blood for a single transfer changes nothing permanently; you paid more for one signature. Changing the floor is a different act, and it is blood-locked **both ways**.

Loosening must cost blood or a thief lowers the bar and uses their own finger. Tightening must cost blood too, or someone locks you out by raising your floor to blood-for-everything while you are travelling without cartridges.

Changing the rules costs blood, in either direction.

Running permanently at blood tier is `blood_above = 0` — blood for any positive amount — with every operation class locked.

`blood_above = None` is how you turn amount-based escalation *off*, leaving only the operation classes. The sentinel is spelled `None` rather than `0` deliberately: "blood above zero" reads to everyone as "blood for everything", and a value that quietly means the opposite is the wrong thing to hand someone hardening their own device.

Implementation in `firmware/policy.py`. It returns a reason alongside the tier so the device can display why blood is being requested rather than simply demanding it.

**Why the asymmetry matters most for proof-of-human:** one drop of blood is one signature, rate-limited by your body. A pulse can be produced all day. You cannot rent bloodstreams, but a hand can sit on a sensor indefinitely.

### Attesting the tier

A signature carries no information about what gated the key, so "this was signed with blood" has to be a **separate claim signed by a different key**. Each device holds an attestation key, generated in the ATECC608B at provisioning and never rotated. You record its public half once, the way you record an xpub.

`firmware/attest.py`. 238 bytes, fits in a QR:

```
magic 4 · version 1 · tier 1 · counter 8 · sighash 32 · fw_hash 32 · cal_hash 32 · live_hash 32 · pubkey 32 · sig 64
```

Four fields carry the security, and leaving any of them out breaks it:

- **sighash** binds the claim to one transaction. Without it a blood attestation can be lifted onto any other signature.
- **counter** is the device's monotonic counter. Without it an old blood attestation can be replayed for a new transaction.
- **fw_hash** says which firmware made the claim, so a verifier can refuse builds it doesn't recognise.
- **live_hash** is the gate's own measurements, compressed by `signer.liveness_digest()`. Without it the record says a tier passed but not on what evidence, so nothing ties the claim to a specific capture.
- **cal_hash** says which *thresholds* it was comparing against. The firmware hash pins the code and nothing else; every limit the gate can reject on lives in a per-device JSON file, and two devices on identical firmware can hold calibrations a factor apart. `blood_gate.calibration_hash()` computes it over the threshold files actually in force, and hashes an `UNCALIBRATED` sentinel when there are none — so a device still on shipped defaults is distinguishable rather than unattestable, and a co-signer decides whether that is acceptable.

**No timestamp.** The device is airgapped with no battery-backed clock, so it cannot honestly attest to time. The counter orders events; the coordinator's clock does the rest.

### The quorum case

`verify_quorum()` answers "everyone in this multisig signed with blood." Each signer's attestation key goes in a roster at setup; after that it is a mechanical check against one sighash.

**A missing attestation is a failure, not an abstention.** Otherwise the claim degrades silently into "everyone who bothered signed with blood," which is worth nothing.

### Attestations do not go on chain

They travel beside the PSBT in a BIP-174 proprietary field (prefix `CELL`) and are stripped before broadcast. Publishing one fingerprints the address as a CELL device and discloses how it was authorised. On-chain publication is possible and is a deliberate choice, never a default.

### What the attestation is worth

A device holding this key **states** that it ran the blood gate for this sighash. It does not prove the gate passed — you are trusting the firmware and the tamper seal.

This is the same assumption as a TPM quote or a Secure Enclave receipt. It is a real guarantee against a remote or careless attacker and none at all against someone who has opened the case and reflashed the firmware. State this to co-signers explicitly, since the chain does not verify it.

### Limits of the touch tier

Prove *whose* finger. Neither does blood — that is the PIN's job. And a well-made artificial finger containing a genuine haemoglobin-like absorber, driven by a pump replaying recorded variability, would pass. That is a lab effort, not a lunch-break one, and it is beyond any remote attacker.

### Hardware note

The ring bore needs a **Ø10 × 0.5 mm clear window**, flush, sealing the optical chamber. It gives the finger a defined contact surface and keeps blood and dirt out. No anti-reflection treatment is needed: at 45° incidence the window's specular lobe exits at 45° and misses the 0° aperture, for the same reason the wet blood surface does.

---


## 5. Deployment model

This device is for **infrequent, high-consequence signing** — treasury moves, role authorizations, key ceremonies. Not trading. Everything below follows from that one fact.

### It holds spend authority and nothing else

| | Lives on | Blood |
|---|---|---|
| Spend key → your pubkey `P` | **Device** | Yes |
| Confidential note owner (same `P`) | **Device** — same key | Yes |
| Scan / view key | Companion | Never — it cannot spend |
| Gas account | Companion or relayer | Never — the device holds no gas |

No tiers, no spending thresholds. Every key on the device requires blood, because the only keys on the device are the ones that move value.

**The device never builds a transaction. It signs an authorization; the companion submits it and pays the fee.** So it holds no ETH, has no nonce, and never has to reason about calldata it can't read.

### The closed operation set

It signs exactly three things:

- A Bitcoin spend — amount, destination, fee, change ownership
- A confidential note spend — note, amount, recipient owner
- A direct transfer to a pubkey

**It refuses everything else**, including generic EVM calldata and bare hashes. If the device can't render an operation as a sentence a human can read, it doesn't sign it. A device that displays `0x9a3f…` and asks for blood is worse than one that refuses.

This is a scope decision, not a limitation. Make it deliberately.

### Dual chain is nearly free

Bitcoin and Ethereum both use secp256k1, so one signing core serves both — the difference is transaction encoding, not cryptography. The same spend pubkey can own value on either side, which means one identity and one blood-gated key rather than two devices.

If you're pairing this with a protocol that already derives a tree from one root: keep the spend key on the device, keep the scan key off it, and **make the root's origin exclusive at provisioning.** If a key born in this device can also be reached through a passkey or an exported seed on a laptop, an attacker never touches the device and the blood gate is decoration next to an open door. One path in, permanently, chosen once.

### Dormancy is the real failure mode

A device used twice a year spends 364 days in a drawer. That is where it fails — not under load.

- **No battery.** A LiPo left at partial charge for a year deep-discharges, swells, and occasionally catches fire. USB-C power only. You're at a desk when you use this.
- **No reagents.** Dried clotting accelerants drift with humidity, so cartridges that sit for a year drift with them. Native clotting instead, over a **600 s** window. Indefinite shelf life.
- **Two sealed test cartridges** (below). This is the part that matters most.

### Pre-flight

Per-cartridge references tell you the *cartridge* is fine. They tell you nothing about whether the LED has aged or the optics have fouled over a year in storage. Two sealed cartridges, made once and kept with the device, cover that:

| Cartridge | Contents | Must |
|---|---|---|
| **REFERENCE** | A stable, characterised spectral target, sealed under a bonded PET window | Read within tolerance of the value recorded at provisioning, and **fail the coagulation gate** — it can't clot |
| **NULL** | A red target with no absorption at 415 nm — a printed or painted swatch | **Fail Gate 1.** If a red target ever passes, stop using the device |

The reference cartridge is a **drift check, not a blood simulant.** It verifies the optical chain — LED output, sensor response, geometry — still reads a known target the way it did on day one. It is not trying to imitate blood.

Before any signing that matters:

```
1. Insert NULL       → must reject at Gate 1 (too bright)  ~40 s
2. Insert REFERENCE  → spectral gates within tolerance,
                       coagulation gate rejects     ~4 min
3. Proceed
```

Five minutes. That fits the ritual this device already is, and it's the check a role-based signer should have and a trading wallet never would.

### Write the PIN down

Not next to the device — **with the seed backup, in the other location.**

For a device used twice a year, forgetting the PIN is a more likely loss event than burglary of two separate locations. And the failure is asymmetric: a forgotten PIN with a working device is recoverable from the seed; a compromised seed is not recoverable at all. Different people will weigh this differently, but for this audience that's the right default.

---

## 6. Parts (~US$90 complete, ~US$60 for the reader alone)

| Item | Part | ~USD | Notes |
|---|---|---|---|
| Compute | Raspberry Pi Zero 2 W | 15 | Radios get disabled *and* the antenna trace cut |
| Gate chip | ATECC608B breakout (Adafruit 4314) | 6 | Wallet kit. PIN counter, AES key storage, KDF |
| Spectrometer | AMS AS7341 breakout (Adafruit 4698) | 16 | 8 colour channels + Clear + NIR. Drives an LED directly |
| Laser | 650 nm diode module, ≤5 mW | 2 | Liveness gate. Coherent source is mandatory — an LED will not produce speckle |
| Camera (speckle) | Pi Camera + **mini**-CSI cable | 10 | **Reader kit.** Lens removed. Fixed exposure/gain — see §8 |
| Display | ST7789 1.3" 240×240 SPI | 8 | Wallet kit |
| Camera (QR) | Cheap USB webcam | 8 | Wallet kit. **Not a second CSI camera** — the Pi Zero has one CSI port and the speckle path has it. QR decoding tolerates auto-exposure |
| Buttons | 12 mm tactile ×4 | 3 | Wallet kit. One is CONFIRM, on its own pin |
| LEDs | 5 mm white ×2, 940 nm IR ×1, 2N7002 ×2, resistors | 3 | |
| Power | USB-C breakout, power only | 2 | **No battery** — see §2. Desolder D+/D− or use a data blocker |
| Storage | 16 GB A2 microSD | 6 | |
| Test cartridges | Printed once, sealed, kept with the device | 0 | Wallet kit. REFERENCE + NULL, see §4 |
| Filament | PETG black ~90 g, white ~30 g | 4 | Not PLA |
| Fasteners | M2.5×8 + heat-set inserts ×8 | 3 | |
| Ring window | Ø10 × 0.5 mm clear acrylic or glass disc | 1 | Seals the chamber, contact surface for touch mode |

**Consumables:** contact-activated sterile lancets 28G/1.8 mm (~$0.06 ea, any pharmacy), alcohol prep pads, 0.1 mm PET film for cartridge windows (transparency or laminating pouch, ~$8/100 sheets ≈ 1,600 windows), a 1 L sharps container. No reagents — nothing here has a shelf life.

**Optional, later:** MLX90614-DCI infrared thermometer (~$15) adds a sixth gate. See §3 for why it isn't in the core build. It must be the DCI variant; the 90° version images the whole chamber rather than the sample.

### Cost reduction

| Target | Change | Cost |
|---|---|---|
| **~$70 today** | Original Pi Zero instead of the 2 W. It has no radios to disable — one less build step and one less thing to get wrong. Cheapest USB webcam for QR | −$20 |
| **~$60, worth testing on the reader** | Replace the AS7341 with four discrete LEDs (415, 525, 630, 940 nm) and one photodiode, flashed in sequence. Classic multi-wavelength colorimetry. You lose spectral resolution, but the speckle gate does the security work — the colour half only has to establish "this is blood" | −$12 |
| **~$40 at ~100 units** | One custom PCB with bare parts. The AS7341 die is ~$3 against $16 for the breakout; the ATECC608B ~$1 against $6 | −$30 |

Most of the current bill is the cost of breakout boards rather than the silicon on them.

**Deliberately not included:** no secure element beyond the ATECC608B (the seed is backed up anyway, so a $32 non-exportable-key chip buys little here), no fingerprint sensor (the PIN does identity), no impedance analyser, no battery.

---

## 7. How the sensing works

**Six gates, all must pass.** Full implementation in `firmware/blood_gate.py`; every threshold lives in one `Thresholds` dataclass.

| # | Gate | Test | Catches |
|---|---|---|---|
| 1 | **Return signal** | Clear channel in a **window**, 0.015–0.35 of the white patch | Too dark: empty dark well, any non-scattering liquid. Too bright: an empty white well, or a painted swatch — including the NULL cartridge |
| 2 | **Cellular scatter** | White-normalised NIR/Clear ≥ 2.2 | Dye solutions, haemolysed blood — a solution, not a suspension |
| 3 | **Haem Soret band** | (R630−R415)/(R630+R415) ≥ 0.75 | Every kitchen fake. No common red substance is a porphyrin |
| 4 | **Spectral shape** | SAM cosine ≥ 0.995 over the **unclamped** channels | Deoxygenated and met-haemoglobin — blood that is old, venous, or otherwise not a fresh capillary draw |
| 5 | **Free motion** ⭐ | `D(early) ≥ 0.60`, speckle contrast valid | Already-clotted blood, syrups, gels — anything that was never liquid |
| 6 | **Motion arrested** ⭐ | `D(late) ≤ 0.25`, drop ≥ 0.35, ρ ≤ −0.70 | **Anticoagulated blood.** This is the anti-replay gate |

Gates 1–4 are evaluated at t = 5 s **and the capture aborts there if any of them fail**, so an obvious spoof is rejected in seconds rather than ten minutes. Gates 5–6 need the full run. `calibrate.py` disables the abort, because calibration wants the whole speckle series even for samples that fail on chemistry.

### Gate 1 is a window, not a floor

A floor alone cannot reject a *bright* sample, and two of the things that must be rejected are bright: an empty white well reads ~0.97 of the white patch, and a red painted swatch ~0.58. Whole blood reads ~0.15. The NULL pre-flight cartridge is exactly a bright red swatch, so §5's "NULL must fail Gate 1" only holds with the ceiling in place.

### Gate 2 is normalised before the ratio is taken

Clear is read under the white LED and NIR under the 940 nm LED. A raw `nir/clear` ratio is therefore set largely by the two drive currents and drifts as they age — the exact effect the printed white patch exists to cancel. Both channels are normalised against the patch first, so what remains is a property of the sample.

### Gate 4 ignores the clamped channels

SAM is computed only over the channels not pinned at the absorbance clamp. A clamped channel holds the same value for every sample dark enough to reach it, so including it contributes a constant to every vector and drags all cosines toward 1. Measured against the shipped reference: with 415 nm included, deoxygenated blood scores 0.991 against a 0.985 threshold and is **accepted**. Excluding it, genuine sits at 0.99999 and deoxyHb at 0.98821 — a margin ten times larger relative to sensor noise. The mask is derived from the reference at import, so enrolling your own reference recomputes it.

### The 415 nm channel saturates

Whole blood is roughly **4,600 absorbance units per centimetre** at 415 nm. In an optically semi-infinite well the 415 channel sits at the ADC floor, and an absorbance computed from a floor reading is numerically meaningless — it is unbounded and unstable, and a very dark dye floors there too.

Gate 3 is therefore a **normalised difference index**, bounded in [−1, 1], which never divides by a floor value. Gate 1 has already established that the sample returns real signal, so the ratio is meaningful when it is computed. Absorbance is still used for Gate 4's shape comparison, but **clamped** at 2.5 — hitting that clamp on the 415 channel is the expected result for genuine blood, not an error.

### Timing

Native whole blood on a plastic surface clots far more slowly than on glass, which is a strong contact activator. The closest published work to this approach used finger-prick samples in glass microchannels and observed for 35 minutes. Ten minutes on PETG carries margin.

For a device used twice a year this costs nothing, and it removes any need for a clotting accelerant — which would carry a shelf life in a device that spends 364 days in a drawer.

---

## 8. The cartridge

**This is the part that needs care.** Everything else is ordinary electronics.

**45 × 14 × 2.4 mm, white PETG, 0.15 mm layers, 100% infill, top-surface ironing ON.**

The length is set by the machine, not by preference: the read spot sits 31.6 mm behind the front face (`models/instrument.obj`), so a 45 mm cartridge leaves 13.4 mm proud of the slot to grip. Shorten it and you are fishing a blood-contact part out of the slot with your fingernails.

| Feature | Dimension | Why |
|---|---|---|
| Sample well | Ø4.0 × 0.55 mm deep (≈7 µL) | See below |
| Overflow moat | Ø7.0 annulus, 0.4 mm deep | Accepts 8–15 µL without flooding the optics |
| White reference patch | 4 × 4 mm, ironed, coplanar with the well rim | Per-measurement normalisation |
| Lid | 0.1 mm PET film, taped along one edge | Optical window. **The tape is the hinge** — no printed living hinge to tune |
| Grip tab | 13.4 × 14 mm, proud of the slot | Keeps fingers off the optics |

Four features in total. Two of them matter more than their size suggests:

**The well is optically semi-infinite.** At ≥0.4 mm, essentially no light penetrates whole blood and returns from the floor. Reflectance becomes independent of fill volume *and* of the backing — which is why 8–15 µL is an acceptable tolerance instead of a pipetting requirement, and why the well floor's print finish is irrelevant. Only the *white patch* needs a good surface. **Don't "improve" this by making the well thinner.**

**Every cartridge carries its own white and black references.** LED aging, sensor drift, and print variation are all first-order effects that would walk your thresholds out of spec within weeks — silently. Normalising against a patch printed in the same layer, on the same part, from the same filament cancels nearly all of it. This one choice is the difference between a device that works for a year and one that works for a week.

**No black reference feature.** The dark reading is taken at the *same position as the white patch with the LEDs off* — dark current plus any ambient leak, for free. That removes a printed feature from every cartridge, and the light-tightness test in §8 is what validates the assumption.

### Printing them

```bash
python3 tools/gen_printables.py     # -> models/print/*.stl
```

Every printed part except the two enclosure shells comes out of that generator, dimensioned from the constants in this section: the cartridge, the pre-flight REFERENCE and NULL bodies, the aperture tube, the optical head, the slot baffle, and a jig for cutting the PET windows. It validates each mesh before writing it — every shell closed, consistently wound, positive in volume — and exits non-zero rather than hand a slicer something it would have to guess at. `models/print/MANIFEST.md` lists orientation, settings and the dimensions it had to derive. The shells still come from the viewer export; that stays the one source for anything with an outside surface.

**Length: 45 mm gives 7.4 mm of grip, not 13.4.** The three numbers above do not all hold at once. The well needs clearance ahead of it — 6.0 mm from the tip to the moat wall — so a cartridge whose well reaches the read spot has gone 37.6 mm in, and 7.4 mm is what is left to hold. For the full 13.4 mm, set `CART_L = 51.0` in the generator and regenerate. Either works; they are not interchangeable in the slot, so pick one before printing a batch.

**Windows:** cut 12 × 10 mm rectangles from 0.1 mm transparency film. Tape one edge to the cartridge body with 3M 300LSE so it flips up to load and down to close. Handle by the edges — a fingerprint on the window is a calibration error.

---

## 9. Optical head

```
                    AS7341
                      │  ← 9.0 mm standoff
                 ┌────┴────┐
                 │ Ø3 × 6  │  aperture tube, matte black inside
    white LED    └────┬────┘    white LED
        ╲             │             ╱
         ╲ 45°        │ 0°     45° ╱      ← 12 mm from spot centre
          ╲           │           ╱
    ══════════════════▼══════════════════   PET window
              [   whole blood   ]           well, 0.55 deep
    ─────────────────────────────────────   white PETG cartridge body
```

- **45°/0° is not decorative.** Wet blood is glossy. A normal-incidence lamp would swamp the sensor with surface reflection carrying zero chemical information. At 45° the specular lobe exits at 45° and misses the aperture entirely.
- Two opposed LEDs cancel directional shading from droplet asymmetry.
- The aperture tube defines a 3 mm spot inside the 4 mm well, so the sensor never sees the meniscus at the edge.
- White LED #1 runs off the AS7341's own `LDR` driver pin — you get synchronised flash/measure timing free. LED #2 and the IR LED gate via 2N7002.

### The speckle path

A second, independent optical path in the same chamber.

```
   laser diode 650 nm            camera, LENS REMOVED
        ╲  ~30° off normal            │  ~20 mm from the spot
         ╲                            │  off the specular axis
          ╲                           │
    ═══════▼═══════════════════════════════════   PET window
              [   whole blood   ]
```

| Item | Spec | Why |
|---|---|---|
| Source | 650 nm diode module, ≤5 mW | Coherent light is mandatory. An LED's coherence length is microns — it produces no speckle |
| Interlock | Laser energised only when the cartridge switch is closed | The chamber is sealed, but wire the interlock anyway |
| Camera | Pi Camera, **lens unscrewed and removed** | Lensless speckle grain ≈ λz/D ≈ 4 µm at 20 mm — about 4 pixels on an IMX219, well sampled. With the lens fitted the grain is ~1.6 px and undersampled |
| Standoff | ~20 mm, off the specular axis | |
| Settings | **Fixed** exposure ≤2 ms, fixed gain, AWB off, denoise off | Any auto-adjustment between frames destroys the correlation measurement. This is the single most common way to get garbage out of this sensor |
| Capture | 128×128 ROI, 16 frames per burst, one burst every 20 s | |

**Verify before trusting it:** take the 2-D autocorrelation of a single frame. The central peak should span 3–5 pixels. Narrower means undersampled speckle; broader means you are imaging something other than speckle.

**The two paths must not run at once.** The laser contaminates the 630 nm channel and the white LEDs wash out the speckle. Interleave: LEDs on for the chemistry read at t = 5 s, laser only during bursts.

**Light-tightness test:** cartridge inserted, room at 10,000 lux, all LEDs off — the Clear channel must read under 0.5% of its LEDs-on value. Print the chamber in black PETG at ≥4 perimeters and paint the interior matte black. Thin PETG passes more light than you'd expect.

**Cartridge slot:** 34.0 × 3.0 mm on the front edge (model: `front_slot`), with a sprung silicone flap plus a 6 mm offset baffle behind it.

---

## 10. Enclosure

**Printing the shells:**

```bash
python3 tools/gen_enclosure.py      # -> models/print/shell_lower.stl, shell_upper.stl
```

The viewer model is an appearance model — solid extrusions, with the openings drawn as dark boxes rather than cut out of anything. Slice it and you get a brick. `tools/gen_enclosure.py` is the source for the inside: 2.4 mm wall, the part line at 11.4 with a tongue and groove, the four openings actually removed, six M2.5 insert bosses, rails the Pi slides in on, and the light-tight skirt around the optical chamber. It re-checks the envelope against the figures below on every run, and re-checks that the thing can still be assembled — cartridge path, blind vents, Pi bay, sensor port, part line. Both files are parametric; the checks are what keep them describing one instrument.

**`viewer/model.js` is the parametric source of the enclosure.** It builds the geometry; `models/instrument.obj` is an export from it, and `diagrams/mechanical.svg` is generated from that export by `tools/gen_mechanical.py`. The chain is one-way:

```
viewer/model.js  ──export──▶  models/instrument.obj  ──generate──▶  diagrams/mechanical.svg
```

Edit the model, re-export, re-run the generator. CI fails if the drawing and the OBJ disagree. Do not hand-edit the OBJ — it is 56 MB of triangles and nothing downstream of it can be reconciled with a parametric change.

**Envelope: 116.2 × 73.2 × 28.3 mm.** Two shells parted at 11.4 mm from the base, with the seam picked out in oxblood. The Pi enters from the rear like a cartridge; the sample cartridge from the front, on the same centreline as the dish.

| Feature | Dimension | Notes |
|---|---|---|
| Sample dish | Ø47.2, 2.0 deep | Recessed into the deck. The optical head sits above it |
| Ring | Ø14.4 OD / Ø9.8 ID, 1.5 proud | Oxblood, smooth bezel. **A marker for the measurement spot, not a control — nothing rotates** |
| Index ticks | 60 @ R21.2, every 5th in steel | Around the dish |
| Display | 49.7 × 37.7 | Flush glass, oxblood bezel |
| Buttons | 3 × Ø5.8 + 1 × Ø8.6 | The Ø8.6 is CONFIRM, with its own collar |
| Pad | 24.0 × 12.0 | Printed marking. **Reserved — see below** |
| Sample slot | 34.0 × 3.0, 4.2 deep | Front face |
| Compute bay | 72 × 16, 3.2 deep | Rear face |
| USB-C | 9.0 × 3.2 | Right face, power only |
| Vents | 15 slots, 3.0 deep | Front face. **Must be blind — see below** |
| Fasteners | 2 × Ø4.0 slotted | Front face, lower shell |

### Constraints not expressed in the model

**1. The vents must be blind pockets.** They're 3.0 mm deep into a 73 mm body, so they're pockets in the model — keep them that way. If any becomes a through-hole, ambient light reaches the optical chamber and the 415 nm gate stops working. Verify with the light-tightness test in §8, not by eye.

**2. The pad is reserved, not fitted.** It is a flat printed marking sized for the optional fingerprint sensor, which the base build doesn't use — the PIN does identity (§4). It is deliberately not a recess: an unpopulated pocket on the deck is a place for blood to collect.

**3. The dish is a reader, not a dial.** The ring and the 60 index ticks are decorative. Nothing rotates. The cartridge enters through the front slot and sits under the dish, and the ring frames the measurement spot and serves as the contact surface for the touch tier.

### Print settings

| Part | Material | Layer | Perimeters | Infill | Special |
|---|---|---|---|---|---|
| Shells | PETG black | 0.16 | 4 | 25% | Part line down, no supports |
| Optical chamber | PETG black | 0.12 | 6 | 40% | Paint interior matte black |
| Aperture tube | PETG black | 0.12 | 4 | 100% | Paint interior matte black |
| Cartridge | PETG **white** | 0.15 | 3 | 100% | **Ironing ON** — only the white patch surface matters |

`tools/gen_printables.py` emits every part in this table except the shells, already at these settings — see `models/print/MANIFEST.md`.

PETG, not PLA — PLA creeps under screw preload and softens in a hot car. The oxblood elements (seam, ring, bezel, ticks) are a second filament or a paint fill; the model separates them as distinct objects with their own materials, so a multi-material printer can take them straight.

**Note:** `instrument.mtl` is referenced by the OBJ but wasn't supplied. Material names are carried on the objects (`shell`, `oxblood`, `trim_oxblood`, `glass`, `pad`, `etch_floor`, `steel`, `cavity`), so you can assign your own without losing the separation.

---

## 11. Wiring

Everything on I²C1 at 400 kHz plus SPI0 for the display. BCM numbering.

| Pin | Function |
|---|---|
| GPIO2/3 | I²C1 — AS7341 (0x39), ATECC608B (0x60) |
| GPIO5, 13, 19 | UP / DOWN / BACK |
| **GPIO26** | **CONFIRM** — dedicated, RC-debounced (10 kΩ + 100 nF), shares no bus |
| GPIO8–11 | SPI0 → display |
| GPIO25 / 27 / 24 | Display D/C, RESET, backlight |
| GPIO12 | White LED #2 gate (2N7002, 68 Ω) |
| GPIO6 | Laser gate (2N7002) — interlocked to the cartridge switch |
| GPIO23 | 940 nm IR LED gate (2N7002, 47 Ω) |
| GPIO22 | Cartridge-present microswitch |
| CSI | Camera |

**Two common first-build failures:**

1. **Both I²C breakouts ship with pull-ups fitted.** Remove one pair (2.2 kΩ) or the bus may not enumerate. This is the #1 first-build failure.
2. **CONFIRM is on its own pin for a reason.** An attacker who owns the SPI bus still can't assert it.

### Radio removal — non-negotiable

```ini
# /boot/firmware/config.txt
dtoverlay=disable-wifi
dtoverlay=disable-bt
```
```
# /etc/modprobe.d/blacklist-radio.conf
blacklist brcmfmac
blacklist brcmutil
blacklist hci_uart
blacklist btbcm
blacklist bluetooth
```

Then **cut the antenna feed trace** at the board edge with a scalpel. Firmware disabling is reversible by anyone who touches the SD card; a cut trace is not.

Verify: `iw dev` empty, `hciconfig` empty. Desolder USB D+/D− or use a data-blocker — power only.

---

## 12. Firmware

### Wallet layer

Fork [SeedSigner](https://github.com/SeedSigner/seedsigner). It's a mature airgapped Pi Zero signer that already solves animated-QR PSBT in/out, the ST7789 UI, camera handling, `embit` Bitcoin logic, and a hardened read-only image build. You're adding a gate, not building a wallet. Writing your own PSBT parser is how you lose money to a change-address bug.

You diverge in one place: SeedSigner is stateless and re-derives from a seed you type each time. You store an encrypted seed and gate its decryption.

### Stack

```
Raspberry Pi OS Lite 64-bit
  ├─ read-only rootfs (raspi-config → Performance → Overlay FS)
  ├─ purge wpa_supplicant, dhcpcd, avahi, ssh
  └─ python3
       ├─ embit                                  (PSBT, descriptors, taproot)
       ├─ adafruit-circuitpython-as7341
       ├─ adafruit-circuitpython-mlx90614
       ├─ cryptoauthlib                          (ATECC608B)
       ├─ numpy, scipy                           (curve fitting, gates 5–6)
       └─ blood_gate.py
```

### Unlock chain

Implemented in `firmware/signer.py`, with the step order asserted in the tests against `signer.EXPECTED_ORDER`.

```
1. render        refuse anything unrenderable, before anything else
2. policy        the DEVICE picks the tier; the operation never does
3. confirm       CONFIRM on GPIO26, showing this exact transaction
4. PIN           ATECC608B CheckMac. Counter increments BEFORE verify,
                 so power-cycling mid-attempt doesn't refund an attempt.
                 10 failures → wipe.
5. gate          touch_gate or blood_gate, at the tier policy chose
6. unwrap        KDF(slot_secret, H(pin)) → AES key
7. sign          seed into mlock()ed pages → derive → sign → zeroise
8. attest        the attestation key signs the tier, the sighash, the
                 firmware, the calibration and the gate measurements
```

Three orderings carry the security, and reordering them breaks it even though the signature still verifies:

- **Render before anything.** An operation the owner cannot read is refused before they spend a lancet on it.
- **Confirm before PIN.** The owner approves *this* transaction, not "a transaction". Taking the PIN first teaches them to authenticate and then read, which is how people sign the wrong thing.
- **Gate before unwrap.** No sample, no seed: the chain refuses above step 6, and `EXPECTED_ORDER` is asserted in the tests rather than described in prose, so a reordering fails loudly.
- **Measurements into the record.** The attestation commits to the gate's actual numbers via `liveness_digest()`, so "signed at blood tier" is checkable by a co-signer against one specific capture instead of being a boolean the device asserts about itself.

**Configure the wrapping slot to require prior authorisation.** This is the single most important line of ATECC608B configuration in the build, and it is config rather than code: the slot holding the wrapping secret must require a successful CheckMac before it will derive, so the derive is physically unreachable without an attempt the counter already debited. Skip it and the PIN counter does nothing — an attacker never calls `verify_pin` at all, they call the derive once per candidate PIN and test each result against the encrypted seed, where AES-GCM's tag tells them when they are right. A six-digit PIN is 10⁶ tries with nothing debited and no wipe. `SoftSE` models the rule so the unlock chain is tested against it: one PIN verification authorises exactly one derive.

**The wrapping key uses stable inputs only — the PIN and the on-chip secret.** This is what makes the seed recoverable: a key must open tomorrow the seed it wrapped today. Liveness measurements are a fresh physical event with no reproducibility, and the sighash changes every transaction, so mixing either into the KDF yields a key that can never reopen anything. Both are still bound tight, in the place where binding them is worth something: the signed attestation, which a third party can verify. The signature already commits to the sighash cryptographically, so nothing is lost by taking it out of the KDF.

On a Pi Zero 2 W the gate ordering is enforced by firmware, on the same footing as the firmware hash and the tamper seal the attestation already declares. A CM4 with verified boot raises that floor when a build calls for it.

`Signer` takes the display, the gate, the seed unwrap and the signing primitive as injected collaborators, so the SeedSigner fork supplies them without touching the chain.

The seed is exposed in RAM for milliseconds. This is the cost of using a $6 gate chip rather than a secure element that signs internally, and of having a conventional backup path.

### Nonce generation

Never derive a signing nonce from a biometric measurement. A structured or predictable nonce leaks the private key.

- **Schnorr (BIP-340):** `aux_rand32 = SHA256(pi_hwrng ‖ atecc_trng ‖ blood_noise_residual)`. BIP-340 hashes `aux_rand` in such a way that even fully attacker-controlled input degrades gracefully to the deterministic case. This is the only safe way to mix in field entropy.
- **ECDSA:** RFC-6979 deterministic. Don't add entropy here at all.

`blood_noise_residual` is the high-frequency residual after the fitted models are subtracted — the genuinely unpredictable part, with all structure removed. It contributes; it never determines.

---

## 13. Calibration

**Calibrate before you trust the device with anything.** The shipped thresholds are derived from physics; these steps replace them with numbers measured on your optics, your printer and your samples.

### The spoof panel

Minimum 30 trials per class. Anything not `genuine` must reject.

| Class | Sample |
|---|---|
| **genuine** | Your own capillary blood, ≤20 s from drop to lid |
| dye | Red food colouring in water |
| ketchup | Thinned |
| beet | Beet juice |
| stage_blood | Corn syrup + red dye + cocoa |
| commercial_fx | Theatrical blood, 2 brands |
| aged_10m / 30m / 60m | Your blood, room temp |
| rewarmed | Aged blood warmed to 37 °C before application |
| **edta** | **EDTA anticoagulated tube blood — the most important negative class** |
| citrate | Citrate tube blood, loaded as drawn (not recalcified — see §16) |
| animal | Pig or beef from a butcher |
| hemolyzed | Your blood, frozen and thawed |
| empty | No sample |

Mammalian haemoglobin is spectrally near-identical to human, so pig blood **will** pass Gates 1–2. That's expected. Gates 3, 5 and 6 reject it, and those are the gates that matter. If you want species discrimination you're asking for DNA sequencing, and that's a different project.

### Procedure

```bash
python calibrate.py capture --label genuine       # ×30+
python calibrate.py capture --label edta          # ×30+   ... etc
python calibrate.py enroll-reference              # builds your own reference spectrum
python calibrate.py roc                           # sets EVERY threshold, writes thresholds.json
```

`roc` sets **every** threshold in `blood_gate.Thresholds`, not just two, from the distribution of your genuine captures — then measures the false-accept rate against the whole panel through the conjunction of all six gates. A threshold is set from the genuine distribution and not from a gap to the spoofs, because each gate owns its own physics and no more: dye is rejected on return signal, EDTA blood on arrested motion, deoxyHb on spectral shape. Demanding that every threshold separate every class is incoherent, and is why the gates are an AND rather than a score.

Target **FRR ≤ 5%** — a false reject costs one cartridge and one lancet. Bias hard toward rejecting; `--drift` exists to loosen the thresholds and defaults to 0.

### Calibrating the touch tier

The touch tier is the everyday default and authorises far more signatures than the blood tier ever will, so it gets the same treatment. Sessions are 15 seconds rather than 600, so the whole panel is minutes:

```bash
python calibrate.py touch-capture --label genuine        # ×30+, hold still
python calibrate.py touch-capture --label pump_fake      # ×30+   ... etc
python calibrate.py touch-roc                            # writes touch_thresholds.json
```

The panel is your fingertip, nothing on the ring, a static object, a mechanical pulsator, a dyed silicone finger, a moving finger, and out-of-range rates high and low. `touch_gate.TouchThresholds.load()` reads the file the sweep writes — put it beside `touch_gate.py` on the device, or the tier you use every day keeps running on shipped defaults.

`fs`, `fs_min` and `duration_s` are deliberately not swept. They describe the capture rather than the finger, and fitting a validity floor to the very sessions it is meant to validate is circular. For the same reason the beat detector spaces peaks by a fixed physiological ceiling (`PEAK_MAX_BPM`) rather than by `bpm_max`: a number that is both an accept threshold and an analysis parameter gets fitted under one detector and judged under another, which puts FRR at 100%.

**The FRR that `roc` prints is in-sample.** The thresholds were fitted to those same genuine captures, so it is optimistic by construction. The honest number comes from captures taken *after* calibration.

### Then put the file on the device

```
firmware/thresholds.json    →   blood_gate.Thresholds.load()
```

`Thresholds.load()` reads it, falling back to the shipped defaults if it is absent. **The device build calls `Thresholds.load()`, not `Thresholds()`** — that is what puts the numbers you measured into force. `Thresholds.provenance()` returns one line for the About screen naming the threshold set in use and the confidence bound behind it.

**State the bound your sample size supports.** By the rule of three, zero spoof acceptances in *n* trials bounds the false-accept rate at 3/*n* with 95% confidence: n=100 gives FAR ≤ 3%, n=300 gives ≤ 1%. A 0.1% claim needs ~3,000 trials. `calibrate.py` computes the bound and prints it with your results, so the number you publish is the number you measured.

### Ongoing

Monthly, run one dye cartridge. It must fail. If a red-dye sample ever passes, the optics are fouled or something has drifted — stop using the device until you know which.

---

## 14. Safety

**Not boilerplate.**

1. **One device, one person. Never share.** Hepatitis B survives on dry surfaces up to 7 days and is far more infectious by blood exposure than HIV. A shared blood-contact device is a transmission vector.
2. **Commercial sterile single-use lancets only.** Never reuse, never resharpen, never substitute a blade or needle. A used lancet tip is dull and contaminated.
3. **One cartridge, one use, then a sharps container.** Not household trash.
4. **Alcohol before, pressure and a plaster after.** Rotate fingers; use the sides of the pad, not the centre.
5. **Rate limit.** Roughly two blood authorisations per day, sustained. The blood tier is intended for cold storage and infrequent high-value operations. Routine signing should use the touch tier.

**Don't use this device if** you take anticoagulants (warfarin, DOACs, clopidogrel, daily aspirin), have a bleeding or clotting disorder, are immunocompromised, or have poor peripheral circulation. Note the irony on anticoagulants: your blood won't clot, so the coagulation gate rejects you every time. **The device physically will not work for you** — a real exclusion, not a hypothetical, and it rules out a meaningful share of adults over 60.

**Stop and see a doctor** for spreading redness, warmth, swelling, pus, red streaking up the finger, fever, or bleeding that won't stop in 10 minutes.

For calibration, don't run 100 samples on one person in one day. Use one larger draw for the negative classes and spread genuine trials over weeks.

---

## 15. Build order

A sequence of checks, not a schedule — with the parts in front of you this is a weekend. Each milestone is independently testable and each will find something you didn't expect.

| # | Milestone | Gate to proceed |
|---|---|---|
| 1 | Pi boots, radios dead | `iw dev` and `hciconfig` both empty, trace cut |
| 2 | AS7341 reading a white card on a breadboard | <1% RSD over 100 reads |
| — | *— end of what the reader kit needs —* | |
| 3 | Print 20 cartridges, measure white patches | <3% spread after normalisation. **Fix your printer here if not** |
| 4 | Optical chamber light-tight | Clear channel <0.5% of LEDs-on at 10,000 lux |
| 5 | **Spectrum of dye vs. your blood** | 415 nm separates them cleanly. This is the "it works" moment |
| 6 | 600 s time series, both classes | Blood starts decorrelated and arrests; dye never had speckle. Judge on what G5/G6 measure — early D, late D, the drop and its direction — not on a curve fit |
| 7 | **Spoof panel** — the reader is done | ROC generated, thresholds set, documented. **This is the result the whole design rests on** |
| 8 | ATECC608B PIN counter | Increments on failure, survives power loss mid-attempt |
| 9 | SeedSigner fork, testnet round trip | Coins move |
| 10 | Blood gate in front of `sign()` | Testnet tx signed only after a real sample |
| 11 | Seal the REFERENCE and NULL cartridges, record baselines | Both behave per §2 |
| 12 | Restore drill | Wipe the device, restore the seed from your paper backup, spend again |


Milestone 12 is not optional. A backup you've never restored from is not a backup.

---

## 16. Threat model and design limits

Stated so co-signers and reviewers can reason about them directly.

**Liveness is not identity.** The gate proves a living human is present; the PIN proves which one. Both are required at both tiers, and the ATECC608B's monotonic attempt counter backs the PIN — it increments before verify, so power-cycling mid-attempt does not reset it, and ten failures wipe.

**The gate proves fresh mammalian blood.** Mammalian haemoglobin is spectrally near-identical to human and clots on the same schedule. Butcher blood fails — it is anticoagulated or already clotted — but the device is not a species assay, and it does not need to be: the PIN is what makes the key yours. Species discrimination means DNA sequencing, which is a different instrument.

**Citrate is reversible, and G6 does not catch a recalcified sample.** Citrate anticoagulates by chelating calcium; adding calcium back restores clotting, which is exactly how a recalcified PT/aPTT assay works. A citrated sample recalcified immediately before loading starts liquid and arrests, so it passes the motion gates as well as the chemistry ones. EDTA chelates far more avidly and is not practically reversible outside a lab, so EDTA tube blood remains rejected — and it is EDTA that a stolen tube of clinical blood is most likely to contain. What G6 defeats is the opportunistic replay of a stored sample. It does not defeat a prepared attacker who holds the owner's blood, the device and the PIN together; nothing optical at this price does, and the quorum in §4 is the answer to that threat rather than a better gate.

**Physical possession of both device and PIN is the boundary.** As with every hardware wallet, hold what you would not be attacked for, and use the multisig quorum in §4 when the amount justifies it. `verify_quorum()` makes "everyone signed with blood" a mechanical check.

**Attestation trusts the firmware and the tamper seal.** Same assumption as a TPM quote or a Secure Enclave receipt. Co-signers register firmware and calibration hashes alongside attestation keys, and `verify()` refuses builds and threshold sets it does not recognise. The Pi Zero 2 W has no secure boot; move to a CM4 if your threat model needs one.

**The seed touches RAM during signing.** Milliseconds, in `mlock()`ed pages, zeroised after. This is the tradeoff for a $6 gate chip and a conventional paper backup path, and it is what makes restore-to-a-Trezor possible.

**The coagulation gate varies with the person.** Clotting time moves with hydration, temperature and medication. Expect more false rejects when cold or dehydrated — warm your hands. Anticoagulant users cannot use the blood tier at all; see `SAFETY.md`.

**Cartridge supply is a dependency.** Keep 200 cartridges and 200 lancets with the device, plus the two sealed test cartridges.

**Review status.** The cryptography is standard construction verified against published test vectors. The sensing is calibrated per device in §13. Independent review of both is welcome and tracked in `CONTRIBUTING.md`. Testnet, then a small amount, then scale.
