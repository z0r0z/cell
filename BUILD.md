# CELL Build Specification

Single device, $97.55 in hardware plus $31.00 of consumables, Raspberry Pi Zero 2 W, 3D-printed shell over the Pi.

The enclosure comes from `viewer/model.js`, a parametric three.js model. `models/instrument.obj` is its export, 131 named objects with materials, 116.2 × 73.2 × 28.3 mm, and `diagrams/mechanical.svg` is generated from that by `tools/gen_mechanical.py`, so the drawing cannot drift from the model. See §10.

This specification is complete enough to build from. Sensing thresholds ship as physics-derived defaults and are calibrated to your hardware in §13. The same step any instrument needs before it is trusted. `VALIDATION.md` is the engineering status record. Use testnet until you have run the calibration.

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
| `Reader` | The blood reader hardware, Pi, spectrometer, laser, camera, LEDs, filament | $62.25 |
| `Reader consumable` | Lancets, alcohol pads, PET window film, tape, sharps container. Needed to run the reader at all. About 100 blood readings, limited by the lancet and pad counts | $31.00 |
| `Wallet` | The signing half, secure element, display, buttons, QR camera, ring window, fasteners | $35.30 |

Order the reader kit and its consumables together; they are one purchase and the reader is useless without both. The wallet kit is a second purchase you only make if the reader works.

### Kit 1. The blood reader ($62.25 hardware + $31.00 consumables, one weekend)

| Item | ~USD |
|---|---|
| Raspberry Pi Zero 2 W | 15 |
| AS7341 spectrometer breakout | 16 |
| 2 × white LED, 1 × 940 nm IR LED | 1.30 |
| 650 nm laser diode module | 2.00 |
| Pi Camera + mini-CSI cable | 10.00 |
| 3 × 2N7002 + resistors | 1.45 |
| Cartridge-present microswitch | 0.50 |
| 16 GB microSD | 6 |
| Jumper wires, small breadboard | 5 |
| PETG white + black, ~90 g black + 60 g white | 5.00 |

Plus the reader consumables ($31.00): 100 sterile lancets, 100 alcohol pads, PET window film, 3M 300LSE tape, and a 1 litre sharps container. Every one of them is needed to run the spoof panel in §13, so budget them with the hardware. That is a starter pack, not a device lifetime: the lancets and pads run out first at 100 each, while 100 sheets of film cut about 1,600 windows. Restock the lancets from any pharmacy.

The reader has no security requirements, because nothing is being signed. Leave wifi enabled, work over SSH, print results to the console. No display, secure element, enclosure or airgap is needed. The only printed parts are a light-tight optical chamber and a plate of cartridges.

It answers the question that determines whether the rest is worth building: does the gate separate real blood from every fake? Run the spoof panel in §13. If it does not, you never order the wallet kit.

### Kit 2, the wallet (+$35.30)

| Item | ~USD |
|---|---|
| ST7789 1.3" 240×240 SPI display | 8 |
| USB webcam, for QR ingest | 8 |
| micro-USB OTG adapter, for that webcam | 2 |
| ATECC608B breakout | 6 |
| 4 × 12 mm tactile buttons | 3 |
| USB-C breakout, power only | 2 |
| M2.5 screws + heat-set inserts, M2 display screws | 2.80 |
| Ø6 mm ground-glass diffuser + 5-minute epoxy | 2.50 |
| Ø10 × 0.5 mm ring window, clear acrylic or glass | 1.00 |

The signing firmware is in this repository, see §12. Build it, provision a seed, then do the airgap hardening: radios disabled, antenna trace cut, read-only rootfs.

**Full device: $97.55 of hardware,** plus $31.00 of consumables. $128.55 all in.

**What a signature costs.** A touch-tier signature costs nothing, no
cartridge, no lancet, and touch is the everyday default. A blood-tier
signature spends one lancet ($0.06), one alcohol pad ($0.02), one PET window
(~$0.005) and one printed cartridge (~2.4 g of PETG, ~$0.12): call it **twenty
cents**. The device is not consumed by either, and nothing here has a shelf
life, there are no reagents, which is why §5 chose native clotting over dried
accelerants.

The hardware is not consumed. The $31.00 covers about 100 blood-tier readings. The lancets and alcohol pads run out first at 100 each, while 100 sheets of film cut roughly 1,600 cartridge windows. Touch-tier signatures cost nothing, and cartridges are printed filament rather than a purchase.

---

## 3. Sensing architecture

| | Sensor | Asks |
|---|---|---|
| **Chemistry** | AS7341 spectrometer + 3 LEDs | Is it blood? |
| **Liveness** | 650 nm laser + camera, speckle | Is it alive? |

The split matters because the two questions have different physics and one sensor is bad at both.

**Chemistry.** Haemoglobin's Soret band at 415 nm is roughly an order of magnitude stronger than anything else in the visible spectrum, and nothing in a kitchen has one. Four gates off one $16 part.

**Liveness is not a reflectance measurement.** What changes during clotting is the *motion* of the scatterers, red cells go from free Brownian motion to being locked in a fibrin network. Bulk reflectance barely registers that. Coherent light does: a speckle pattern from a liquid suspension boils, and a speckle pattern from a clot is frozen. This is why every established low-cost optical coagulometer uses a laser and a camera rather than a photodiode.

The measurement is **frame-to-frame speckle decorrelation**:

```
D = 1 − (correlation between consecutive frames)

    liquid blood   D ≈ 1.0    speckle fully decorrelates between frames
    clotted blood  D ≈ 0.0    pattern is static
```

The signal is close to binary. This is why the liveness gate measures motion rather than reflectance.

### The liveness test assumes no curve shape

Published coagulation indices disagree about whether clotting is exponential, sigmoid, or something else. The test does not need to know. It asks three things:

The frames are spatially high-passed before they are correlated. Real lensless speckle rides on a strongly non-uniform beam envelope which is *identical* frame to frame, and correlating raw frames measures the envelope instead of the speckle, enough to hold the correlation above 0.5 while the speckle is fully boiling, which fails Gate 5 on genuine blood. Each frame is high-passed independently; subtracting a temporal mean instead would invert the gate, because a frozen field minus its own mean is pure noise and decorrelates perfectly.

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
| Added parts | **Zero** |, |
| Defeats | Malware, automation, remote signing | All of that, plus stored samples |

Touch mode is photoplethysmography. Arterial blood volume in the fingertip changes with each heartbeat, so light coming back through the ring bore carries a small pulsatile signal on a large steady one. The white LED gives a red channel, the 940 nm LED gives infrared, the AS7341 samples both at 50 Hz. **The ring bore is the sensor port in both modes**. A finger on it, or a cartridge under it.

### Seven gates, `firmware/touch_gate.py`

| # | Gate | Test | Catches |
|---|---|---|---|
| T0 | Capture rate | Achieved sample rate ≥ 20 Hz | A hardware timing fault. Not an anti-spoof gate, see below |
| T1 | Contact | DC level 8–85% of the empty bore | Nothing on the ring; or pressed so hard perfusion is occluded |
| T2 | Pulsatile | Perfusion index 0.3–10% | Static objects, printed photos, and, at the ceiling, motion |
| T3 | Rate | Dominant frequency 40–180 bpm | Anything not beating like a heart |
| T4 | Cardiac band | ≥45% of band power at the fundamental | Broadband noise, artefact |
| T5 | Variability | RMSSD 5–250 ms | **Mechanical pulsators.** A real heart is not a metronome |
| T6 | Haemoglobin ratio | Red/IR ratio-of-ratios 0.40–0.90 | **Dye-based fake fingers** |

T6 is the important one, and it is the same physics the blood mode uses at 415 nm applied to a living finger. A silicone finger with red dye pumped through it can produce a convincing pulse, but dye does not have haemoglobin's red-to-infrared absorption ratio. It also catches motion from the other side: a geometry change hits both wavelengths equally and drives the ratio toward 1.0, while real perfusion sits near 0.6.

**T0 exists because the sample rate is not a constant.** Every gate after it is computed in units of `fs`, so a capture taken at 8 Hz and analysed at a nominal 50 Hz reports a 68 bpm heart as ~11 bpm and fails T3. That sends the user hunting a heart problem that is really an I²C timing problem. `read_ppg` measures the rate it actually achieved and returns it; the analysis uses that number, and T0 refuses the capture outright if it is too low to analyse. The AS7341's chemistry integration time is 281 ms per channel and **cannot** produce a PPG waveform, touch mode switches to a short ATIME and back. See `hardware.py`.

Two of the thresholds are physiology, not tuning. **Perfusion above 10%** cannot be blood volume in tissue. The sensor or the finger moved. **Respiratory sinus arrhythmia** puts a healthy resting adult's RMSSD in the tens of milliseconds; a pump produces single digits.

### Touch is the default. Blood is a mode you enter.

Everyday operations run on touch. Blood is deliberate. You choose it, the way you'd choose to swear to something.

That only holds if the choice runs one way:

> **You can always escalate. You can never de-escalate.**

If blood were purely opt-in, an attacker holding the device and the PIN would simply never opt in, and the top tier would be decorative. So policy sets a floor. You may enter blood mode for a trivial transfer because it feels significant. That is a valid act and the device permits it. You may not go under the floor, ever, and there is no override.

**Changing the policy is itself blood-locked.** This is the rule people leave out, and it is the only thing separating a two-tier device from a one-tier device with extra steps. Without it the attack isn't "defeat the blood gate", it's "lower the threshold, then use a finger", which needs no blood at all.

Permanently blood-locked at provisioning, not configurable:

```
policy.change · key.export · device.wipe · device.reprovision · recipient.allowlist
```

Everything else is yours to set: an amount threshold, specific operation classes, or nothing at all.

### Escalation and the floor are different things

| | Scope | Persists? | Costs blood to change |
|---|---|---|---|
| **Escalation** | This one operation | No. The next one reverts to the floor |, |
| **The floor** | A standing rule | Yes, until changed | **Yes, in either direction** |

Choosing blood for a single transfer changes nothing permanently; you paid more for one signature. Changing the floor is a different act, and it is blood-locked **both ways**.

Loosening must cost blood or a thief lowers the bar and uses their own finger. Tightening must cost blood too, or someone locks you out by raising your floor to blood-for-everything while you are travelling without cartridges.

Changing the rules costs blood, in either direction.

Running permanently at blood tier is `blood_above = 0`, blood for any positive amount, with every operation class locked.

`blood_above = None` is how you turn amount-based escalation *off*, leaving only the operation classes. The sentinel is spelled `None` and never `0`, deliberately: "blood above zero" reads to everyone as "blood for everything", and a value that quietly means the opposite is the wrong thing to hand someone hardening their own device.

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
- **cal_hash** says which *thresholds* it was comparing against. The firmware hash pins the code and nothing else; every limit the gate can reject on lives in a per-device JSON file, and two devices on identical firmware can hold calibrations a factor apart. `blood_gate.calibration_hash()` computes it over the threshold files actually in force, and hashes an `UNCALIBRATED` sentinel when there are none, so a device still on shipped defaults is distinguishable rather than unattestable, and a co-signer decides whether that is acceptable.

**No timestamp.** The device is airgapped with no battery-backed clock, so it cannot honestly attest to time. The counter orders events; the coordinator's clock does the rest.

### The quorum case

`verify_quorum()` answers "everyone in this multisig signed with blood." Each signer's attestation key goes in a roster at setup; after that it is a mechanical check against one sighash.

**A missing attestation is a failure, not an abstention.** Otherwise the claim degrades silently into "everyone who bothered signed with blood," which is worth nothing.

### Attestations do not go on chain

They travel beside the PSBT in a BIP-174 proprietary field (prefix `CELL`) and are stripped before broadcast. Publishing one fingerprints the address as a CELL device and discloses how it was authorised. On-chain publication is possible and is a deliberate choice, never a default.

### What the attestation is worth

A device holding this key **states** that it ran the blood gate for this sighash. It does not prove the gate passed. You are trusting the firmware and the tamper seal.

This is the same assumption as a TPM quote or a Secure Enclave receipt. It is a real guarantee against a remote or careless attacker and none at all against someone who has opened the case and reflashed the firmware. State this to co-signers explicitly, since the chain does not verify it.

### Limits of the touch tier

Prove *whose* finger. Neither does blood. That is the PIN's job. And a well-made artificial finger containing a genuine haemoglobin-like absorber, driven by a pump replaying recorded variability, would pass. That is a lab effort, not a lunch-break one, and it is beyond any remote attacker.

### Hardware note

The ring bore needs a **Ø10 × 0.5 mm clear window**, flush, sealing the optical chamber. It gives the finger a defined contact surface and keeps blood and dirt out. No anti-reflection treatment is needed: at 45° incidence the window's specular lobe exits at 45° and misses the 0° aperture, for the same reason the wet blood surface does.

---


## 5. Deployment model

This device is for **infrequent, high-consequence signing**, treasury moves, role authorizations, key ceremonies. Not trading. Everything below follows from that one fact.

### It holds spend authority and nothing else

| | Lives on | Blood |
|---|---|---|
| Spend key → your pubkey `P` | **Device** | Yes |
| Confidential note owner (same `P`) | **Device**, same key | Yes |
| Scan / view key | Companion | Never, it cannot spend |
| Gas account | Companion or relayer | Never. The device holds no gas |

No tiers, no spending thresholds. Every key on the device requires blood, because the only keys on the device are the ones that move value.

**The device never builds a transaction. It signs an authorization; the companion submits it and pays the fee.** So it holds no ETH, has no nonce, and never has to reason about calldata it can't read.

### The closed operation set

It signs exactly five things:

- A Bitcoin spend, amount, destination, fee, change ownership
- An Ethereum transfer, amount, destination, chain, nonce, worst-case fee
- A confidential note spend, note, amount, recipient owner
- A direct transfer to a pubkey
- A transfer out of a registered smart account, as EIP-712 typed data, with
  the amount, the destination, the account, the chain and the account's nonce

And one thing that moves no value and is blood-locked anyway: an EIP-7702
delegation. See "The smart-account path" below.

**It refuses everything else**, including generic EVM calldata and bare hashes. If the device can't render an operation as a sentence a human can read, it doesn't sign it. A device that displays `0x9a3f…` and asks for blood is worse than one that refuses.

Two consequences of that rule are worth stating outright, because both look like missing features and neither is:

**One destination per Bitcoin transaction.** A PSBT paying several recipients is refused. The device shows one destination in full, on a screen the owner can check character by character; a batch would be a total they cannot. Split the payment, or batch at a layer above the signer.

**Every Ethereum field is displayed.** The chain id, the nonce and `gas_limit × max_fee_per_gas` are on the confirmation screen next to the amount. They are what the signature commits to, so they are what the owner is asked to approve. An unrecognised chain id is refused, because nobody can evaluate a bare number. A signature that does not pin the chain replays on every other EVM network the owner holds funds on. The device ships knowing two chains and is taught the rest by its owner; see §12.

Make this scope decision deliberately.

### The smart-account path

The first four operations are the EOA path. The device builds a whole EIP-1559
transaction, holds the account's nonce and prices `gas_limit × max_fee_per_gas`,
because an EOA has no other way to move value. That contradicts the rule two
paragraphs up: the device is supposed to sign an authorisation and let the
companion submit it.

A smart account is the shape that rule describes. The authorisation is an
EIP-712 `Execute` message, the account's own contract holds the nonce, and
whoever relays it pays the gas. So the device signs three fields and a domain,
holds no gas, and never reasons about a fee it cannot bound.

`chainId` and `verifyingContract` sit inside the EIP-712 domain separator, so
the signature is pinned to one chain and one deployment. That is strictly more
than the EOA path pins, and it is why the account is registered in advance:

```bash
python3 tools/provision.py chain --dir /boot/cell \
    --id 11155111 --name "Sepolia (test)" --ticker ETH
python3 tools/provision.py smart-account --dir /boot/cell \
    --label treasury --chain-id 11155111 \
    --address 0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC \
    --implementation 0xD54cb65224410F3Ff97a8E72f363f224419f4FB0 \
    --threshold 2 --owners 0xCD2a...,0xbBbB...
```

An attacker who can choose `verifyingContract` chooses which account the owner
is spending from, so the device takes it from its own record and refuses every
account it was not told about. Same rule as a registered quorum, for the same
reason.

`data` must be empty. That keeps the operation renderable, and it means the
account's own governance calls are refused: changing owners, changing the
threshold, cancelling a queued transaction all travel as `execute(target=self,
data=...)`. Those are renderable in principle, from a fixed table of selectors
decoded on the device, and they are deliberately not implemented yet. A
self-call is refused.

**EIP-7702 delegation is blood-locked, unconditionally.** The authorisation is
`keccak(0x05 || rlp([chain_id, address, nonce]))`. Three fields, all
displayable, and it moves nothing. It also decides what every later signature
from that address means, which makes it reprovisioning under another name, so
`policy.ALWAYS_BLOOD` holds `account.delegate` and no policy can unlock it.

Two rules the device enforces on a delegation. Chain id 0 is refused: it is
legal, and it means the authorisation is valid on every chain that exists and
every chain that ever will. And the implementation must be registered first,
because the signature commits to an address and to nothing whatever about what
that address contains.

**What delegation costs you, and it is not small.** A 7702 delegation leaves
the EOA key a superuser. That key can still send ordinary transactions and can
revoke the delegation, so a timelock or a guard on a delegated account bounds a
relayer and does not bound the key holder. For a device whose whole argument is
that one path in is chosen once, that matters: use the factory-deployed account
when the timelock has to be a security property, and the delegated EOA when the
point is to add guards and recovery to an address that already holds funds.
`provision.py smart-account --delegated-eoa` records which one this is.

**One gap that signing cannot close.** A 7702 authorisation does not commit to
the initialisation call that has to run in the same transaction, so a relayer
can delegate to the implementation the owner approved and initialise it with
their own owners. That is security consideration 2 of the EIP itself. Check the
account's state against an explorer after a delegation lands and before you
fund it. `VALIDATION.md` carries it open.

### Dual chain is nearly free

Bitcoin and Ethereum both use secp256k1, so one signing core serves both. The difference is transaction encoding, not cryptography. The same spend pubkey can own value on either side, which means one identity and one blood-gated key rather than two devices.

If you're pairing this with a protocol that already derives a tree from one root: keep the spend key on the device, keep the scan key off it, and **make the root's origin exclusive at provisioning.** If a key born in this device can also be reached through a passkey or an exported seed on a laptop, an attacker never touches the device and the blood gate is decoration next to an open door. One path in, permanently, chosen once.

### Dormancy is the real failure mode

A device used twice a year spends 364 days in a drawer. That is where it fails, not under load.

- **No battery.** A LiPo left at partial charge for a year deep-discharges, swells, and occasionally catches fire. USB-C power only. You're at a desk when you use this.
- **No reagents.** Dried clotting accelerants drift with humidity, so cartridges that sit for a year drift with them. Native clotting instead, over a **600 s** window. Indefinite shelf life.
- **Two sealed test cartridges** (below). This is the part that matters most.

### Pre-flight

Per-cartridge references tell you the *cartridge* is fine. They tell you nothing about whether the LED has aged or the optics have fouled over a year in storage. Two sealed cartridges, made once and kept with the device, cover that:

| Cartridge | Contents | Must |
|---|---|---|
| **REFERENCE** | A stable, characterised spectral target, sealed under a bonded PET window | Read within tolerance of the value recorded at provisioning, and **fail the coagulation gate**: it can't clot |
| **NULL** | A red target with no absorption at 415 nm. A printed or painted swatch | **Fail Gate 1.** If a red target ever passes, stop using the device |

The reference cartridge is a **drift check, not a blood simulant.** It verifies the optical chain, LED output, sensor response, geometry, still reads a known target the way it did on day one. It is not trying to imitate blood.

Before any signing that matters:

```
1. Insert NULL       → must reject at Gate 1 (too bright)  ~40 s
2. Insert REFERENCE  → spectral gates within tolerance,
                       coagulation gate rejects     ~4 min
3. Proceed
```

Five minutes. That fits the ritual this device already is, and it's the check a role-based signer should have and a trading wallet never would.

### Write the PIN down

Not next to the device, **with the seed backup, in the other location.**

For a device used twice a year, forgetting the PIN is a more likely loss event than burglary of two separate locations. And the failure is asymmetric: a forgotten PIN with a working device is recoverable from the seed; a compromised seed is not recoverable at all. Different people will weigh this differently, but for this audience that's the right default.

---

## 6. Parts (~US$98 complete, ~US$62 for the reader alone)

| Item | Part | ~USD | Notes |
|---|---|---|---|
| Compute | Raspberry Pi Zero 2 W | 15 | Radios get disabled *and* the antenna trace cut |
| Gate chip | ATECC608B breakout (Adafruit 4314) | 6 | Wallet kit. PIN counter, AES key storage, KDF |
| Spectrometer | AMS AS7341 breakout (Adafruit 4698) | 16 | 8 colour channels + Clear + NIR. Drives an LED directly |
| Laser | 650 nm diode module, ≤5 mW | 2 | Liveness gate. Coherent source is mandatory. An LED will not produce speckle |
| Camera (speckle) | Pi Camera + **mini**-CSI cable | 10 | **Reader kit.** Lens removed. Fixed exposure/gain, see §8 |
| Display | ST7789 1.3" 240×240 SPI | 8 | Wallet kit |
| Camera (QR) | Cheap USB webcam | 8 | Wallet kit. **Not a second CSI camera**. The Pi Zero has one CSI port and the speckle path has it. QR decoding tolerates auto-exposure |
| USB OTG adapter | micro-USB male → USB-A female | 2 | Wallet kit. The Zero's ports are micro-USB. Without this the webcam does not physically connect |
| Buttons | 12 mm tactile ×4 | 3 | Wallet kit. One is CONFIRM, on its own pin |
| LEDs | 5 mm white ×2, 940 nm IR ×1, 2N7002 ×3, resistors | 3 | One MOSFET each for LED #2, the IR LED and the laser, see §11 for the rails |
| Cartridge switch | SPDT snap-action microswitch, lever | 0.50 | Reader kit. GPIO22, and the laser interlock (§9) |
| Power | USB-C breakout, power only | 2 | **No battery**, see §2. Desolder D+/D− or use a data blocker. **Confirm it carries 5.1 kΩ CC pulldowns**, see §11 |
| Storage | 16 GB A2 microSD | 6 | |
| Test cartridges | Printed once, sealed, kept with the device | 0 | Wallet kit. REFERENCE + NULL, see §4 |
| Filament | PETG black ~90 g, white ~60 g | 5 | Not PLA |
| Fasteners | M2.5×8 + heat-set inserts ×8 | 3 | |
| Ring window | Ø10 × 0.5 mm clear acrylic or glass disc | 1 | Seals the chamber, contact surface for touch mode |

**Consumables:** contact-activated sterile lancets 28G/1.8 mm (~$0.06 ea, any pharmacy), alcohol prep pads, 0.1 mm PET film for cartridge windows (transparency or laminating pouch, ~$8/100 sheets ≈ 1,600 windows), a 1 L sharps container. No reagents. Nothing here has a shelf life.

**Optional, later:** MLX90614-DCI infrared thermometer (~$15) adds a sixth gate. See §3 for why it isn't in the core build. It must be the DCI variant; the 90° version images the whole chamber rather than the sample.

### Buying it

Most of this is generic and any supplier will do. Five items are not, and
picking the wrong one costs a rebuild rather than a return.

| Item | What to insist on | What goes wrong otherwise |
|---|---|---|
| **ATECC608B** | The **608B**, on a breakout with I²C pulled out. Adafruit 4314 or the SparkFun equivalent | The 508A and 608A are different parts; 608A is end-of-life. Footprints and libraries look identical |
| **AS7341** | Adafruit 4698, or a clone that brings out the **LDR/LED driver pin** | Boards that omit that pin cannot drive LED #1 directly and §9's wiring does not apply |
| **ST7789 240×240** | A module with a **CS pin broken out** | Many 1.3" 240×240 boards hard-wire chip select. §11 puts the display on SPI0 CE0; without CS you cannot share the bus and the pinout in §11 is wrong for your board |
| **Pi camera** | An **OV5647 (v1-style)** module, plus the **narrow 22-pin "Zero" CSI cable** | The lens has to come off (§9). v1 modules unscrew; v3 does not come apart the same way. And the Zero's connector is narrower than a full-size Pi's. The standard cable will not fit |
| **650 nm laser** | A **module with a driver board**, 3–5 V in, ≤5 mW, with a lens you can defocus | A bare laser diode without current limiting dies the first time you power it |

The **USB webcam** only has to resolve a QR code at roughly a hand's distance.
Fixed-focus units often cannot focus that close. One with a manual focus ring
is the safer buy, and it is the cheapest part in the wallet kit to get wrong.

Lancets, alcohol pads and the sharps container come from any pharmacy. PET
window film is laser-printer transparency or laminating pouch stock. The 3M
300LSE tape is worth buying by name: it is 0.05 mm, and thicker double-sided
tape changes the optical path length the cartridge was dimensioned around.

### Tools

Assumed, and not in the bill: a 3D printer (see `PRINTING.md` for what it has
to be able to do), a soldering iron, **with a heat-set insert tip**, which is
the one tool people do not already own, digital calipers, a small screwdriver
set, and a craft knife with fresh blades for the antenna trace and the PET
windows. A multimeter is not required but you will want one the first time a
bus does not answer.

Also assumed: a **5 V supply good for 2 A** and a USB-C cable. The Pi Zero 2 W
peaks near 0.5 A on its own, and the QR webcam, the laser and the LEDs are all
drawing at the same moment during a blood run. A 1 A phone charger will brown
the Pi out mid-capture, which looks like a sensor fault rather than a power one.

### Cost reduction

| Target | Change | Cost |
|---|---|---|
| **~$70 today** | Original Pi Zero instead of the 2 W. It has no radios to disable. One less build step and one less thing to get wrong. Cheapest USB webcam for QR | −$20 |
| **~$60, worth testing on the reader** | Replace the AS7341 with four discrete LEDs (415, 525, 630, 940 nm) and one photodiode, flashed in sequence. Classic multi-wavelength colorimetry. You lose spectral resolution, but the speckle gate does the security work. The colour half only has to establish "this is blood" | −$12 |
| **~$40 at ~100 units** | One custom PCB with bare parts. The AS7341 die is ~$3 against $16 for the breakout; the ATECC608B ~$1 against $6 | −$30 |

Most of the current bill is the cost of breakout boards rather than the silicon on them.

**Deliberately not included:** no secure element beyond the ATECC608B (the seed is backed up anyway, so a $32 non-exportable-key chip buys little here), no fingerprint sensor (the PIN does identity), no impedance analyser, no battery.

---

## 7. How the sensing works

**Six gates, all must pass.** Full implementation in `firmware/blood_gate.py`; every threshold lives in one `Thresholds` dataclass.

| # | Gate | Test | Catches |
|---|---|---|---|
| 1 | **Return signal** | Clear channel in a **window**, 0.015–0.35 of the white patch | Too dark: empty dark well, any non-scattering liquid. Too bright: an empty white well, or a painted swatch, including the NULL cartridge |
| 2 | **Cellular scatter** | White-normalised NIR/Clear ≥ 2.2 | Dye solutions, haemolysed blood. A solution, not a suspension |
| 3 | **Haem Soret band** | (R630−R415)/(R630+R415) ≥ 0.75 | Every kitchen fake. No common red substance is a porphyrin |
| 4 | **Spectral shape** | SAM cosine ≥ 0.995 over the **unclamped** channels | Deoxygenated and met-haemoglobin, blood that is old, venous, or otherwise not a fresh capillary draw |
| 5 | **Free motion** ⭐ | `D(early) ≥ 0.60`, speckle contrast valid | Already-clotted blood, syrups, gels, anything that was never liquid |
| 6 | **Motion arrested** ⭐ | `D(late) ≤ 0.25`, drop ≥ 0.35, ρ ≤ −0.70 | **Anticoagulated blood.** This is the anti-replay gate |

Gates 1–4 are evaluated at t = 5 s **and the capture aborts there if any of them fail**, so an obvious spoof is rejected in seconds rather than ten minutes. Gates 5–6 need the full run. `calibrate.py` disables the abort, because calibration wants the whole speckle series even for samples that fail on chemistry.

### Gate 1 is a window, not a floor

A floor alone cannot reject a *bright* sample, and two of the things that must be rejected are bright: an empty white well reads ~0.97 of the white patch, and a red painted swatch ~0.58. Whole blood reads ~0.15. The NULL pre-flight cartridge is exactly a bright red swatch, so §5's "NULL must fail Gate 1" only holds with the ceiling in place.

### Gate 2 is normalised before the ratio is taken

Clear is read under the white LED and NIR under the 940 nm LED. A raw `nir/clear` ratio is therefore set largely by the two drive currents and drifts as they age. The exact effect the printed white patch exists to cancel. Both channels are normalised against the patch first, so what remains is a property of the sample.

### Gate 4 ignores the clamped channels

SAM is computed only over the channels not pinned at the absorbance clamp. A clamped channel holds the same value for every sample dark enough to reach it, so including it contributes a constant to every vector and drags all cosines toward 1. Measured against the shipped reference: with 415 nm included, deoxygenated blood scores 0.991 against a 0.985 threshold and is **accepted**. Excluding it, genuine sits at 0.99999 and deoxyHb at 0.98821. A margin ten times larger relative to sensor noise. The mask is derived from the reference at import, so enrolling your own reference recomputes it.

### The 415 nm channel saturates

Whole blood is roughly **4,600 absorbance units per centimetre** at 415 nm. In an optically semi-infinite well the 415 channel sits at the ADC floor, and an absorbance computed from a floor reading is numerically meaningless. It is unbounded and unstable, and a very dark dye floors there too.

Gate 3 is therefore a **normalised difference index**, bounded in [−1, 1], which never divides by a floor value. Gate 1 has already established that the sample returns real signal, so the ratio is meaningful when it is computed. Absorbance is still used for Gate 4's shape comparison, but **clamped** at 2.5, hitting that clamp on the 415 channel is the expected result for genuine blood, not an error.

### Timing

Native whole blood on a plastic surface clots far more slowly than on glass, which is a strong contact activator. The closest published work to this approach used finger-prick samples in glass microchannels and observed for 35 minutes. Ten minutes on PETG carries margin.

For a device used twice a year this costs nothing, and it removes any need for a clotting accelerant, which would carry a shelf life in a device that spends 364 days in a drawer.

---

## 8. The cartridge

**This is the part that needs care.** Everything else is ordinary electronics.

**51 × 14 × 2.4 mm, white PETG, 0.15 mm layers, 100% infill, top-surface ironing ON.**

**It reads at two stops.** There is one aperture and one read spot, 31.6 mm behind the front face, so the patch and the well cannot both be under it at once. They take turns:

| Stop | Insert to | Under the aperture | What the device reads |
|---|---|---|---|
| 1 | 34.6 mm, the first click | the white patch, centred 3.0 mm from the tip | white reference, then dark with the LEDs off |
| 2 | 42.1 mm, pushed past the detent | the well, centred 10.5 mm from the tip | the sample, then 600 s of speckle |

A low detent ridge across the top at 34.6 mm meets the slot lip and gives you the first stop by feel. It stands 0.35 mm proud into 0.6 mm of slot clearance, so a deliberate push rides over it. It is a tactile stop, not a lock.

**The order is load-bearing.** Every gate is normalised against the patch, so a white reference taken at the second stop is a reading of the sample against itself: absorbance collapses to zero and the device rejects genuine blood at G1 while reporting "far too bright to be whole blood". `hardware.py` refuses both mistakes instead of measuring through them. It will not read white with the cartridge seated, and it will not read the sample without the seating switch closed.

The length follows from the geometry: the well must reach the read spot, which puts 42.1 mm of the cartridge inside, leaving 8.9 mm proud of the slot to grip. Shorten it and you are fishing a blood-contact part out of the slot with your fingernails.

| Feature | Dimension | Why |
|---|---|---|
| Sample well | Ø4.0 × 0.55 mm deep (≈7 µL) | See below |
| Overflow moat | Ø7.0 annulus, 0.4 mm deep | Accepts 8–15 µL without flooding the optics |
| White reference patch | 4 × 4 mm, ironed, coplanar with the well rim | Per-measurement normalisation |
| Lid | 0.1 mm PET film, taped along one edge | Optical window. **The tape is the hinge**. No printed living hinge to tune |
| Grip tab | 13.4 × 14 mm, proud of the slot | Keeps fingers off the optics |

Four features in total. Two of them matter more than their size suggests:

**The well is optically semi-infinite.** At ≥0.4 mm, essentially no light penetrates whole blood and returns from the floor. Reflectance becomes independent of fill volume *and* of the backing, which is why 8–15 µL is an acceptable tolerance instead of a pipetting requirement, and why the well floor's print finish is irrelevant. Only the *white patch* needs a good surface. **Don't "improve" this by making the well thinner.**

**Every cartridge carries its own white and black references.** LED aging, sensor drift, and print variation are all first-order effects that would walk your thresholds out of spec within weeks, silently. Normalising against a patch printed in the same layer, on the same part, from the same filament cancels nearly all of it. This one choice is the difference between a device that works for a year and one that works for a week.

**No black reference feature.** The dark reading is taken at the *same position as the white patch with the LEDs off*, dark current plus any ambient leak, for free. That removes a printed feature from every cartridge, and the light-tightness test in §8 is what validates the assumption.

### Printing them

```bash
python3 tools/gen_printables.py     # -> models/print/*.stl
```

That one command builds everything printable. The shells included, via `tools/gen_enclosure.py`, dimensioned from the constants in this section: the cartridge, the pre-flight REFERENCE and NULL bodies, the aperture tube, the optical head, the slot baffle, the display bezel, a jig for cutting the PET windows, and the two shells. It validates each mesh before writing it. Every shell closed, consistently wound, positive in volume, and exits non-zero instead of handing a slicer something it would have to guess at. It also re-checks the cartridge geometry, the bezel, and the filament the BOM buys against what the parts actually weigh. `models/print/MANIFEST.md` is regenerated in the same pass and lists quantities, orientation, settings and every dimension the generator had to derive. It is interpolated from those constants, so it cannot drift from the STLs beside it. `PRINTING.md` walks the whole print through in order.

**Why the well sits 10.5 mm back.** It has to leave room for a 4 mm patch *ahead* of it. Features nearer the tip cross the read spot first, so a patch ahead of the well is read before the sample; a patch behind it would only be reachable after the sample had already been read, which is no use for normalising that same reading. At the original 6.0 mm the moat wall was 2.5 mm from the tip and there was nowhere to put the patch at all, which is exactly how this shipped with a white patch that no optical path could reach. `tools/gen_printables.py` re-checks all six distances on every run and refuses to write a cartridge that breaks any of them.

**Windows:** cut 12 × 10 mm rectangles from 0.1 mm transparency film. Tape one edge to the cartridge body with 3M 300LSE so it flips up to load and down to close. Handle by the edges. A fingerprint on the window is a calibration error.

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

**The 2 ms exposure has 2.5x of margin, and the failure is not the obvious one.** `firmware/speckle_sim.py` models the scattered field as an Ornstein-Uhlenbeck process and integrates it over the exposure, which is the only way to see this: a frame that averages many independent speckle patterns loses contrast AND looks like the frame before it, so liquid blood reads as arrested. Swept against the shipped thresholds at a 0.3 ms correlation time, liquid still reads liquid at 2 ms and fails G5 by 5 ms. It fails toward a false REJECT rather than a false accept, and only because G5 runs first, without the free-motion check the same blur would satisfy G6 and be read as a clot.

**The camera rate sets how still a clot has to be.** At 30 fps the same model reads liquid up to a 31 ms correlation time and arrest from 269 ms, so clotting has to raise tau_c about ninefold, through a band where the sample reads as neither and is rejected. A faster camera narrows that band: 120 fps moves it to 7.4 ms and 64 ms. Recording tau_c against time for one genuine clot is the first measurement the speckle path needs.

- **45°/0° is not decorative.** Wet blood is glossy. A normal-incidence lamp would swamp the sensor with surface reflection carrying zero chemical information. At 45° the specular lobe exits at 45° and misses the aperture entirely.
- Two opposed LEDs cancel directional shading from droplet asymmetry.
- The aperture tube defines a 3 mm spot inside the 4 mm well, so the sensor never sees the meniscus at the edge.
- White LED #1 runs off the AS7341's own `LDR` driver pin, which gives synchronised flash/measure timing for free. LED #2, the IR LED and the laser each gate through their own 2N7002, **three** of them, on two different rails. See §11.

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
| Source | 650 nm diode module, ≤5 mW | Coherent light is mandatory. An LED's coherence length is microns. It produces no speckle |
| Interlock | Laser energised only when the cartridge switch is closed | The chamber is sealed, but wire the interlock anyway. Put the switch contacts in **series with the laser module's supply**, not in the GPIO6 gate line. An interlock the firmware can talk its way past is not an interlock. GPIO6 then gates a laser that is already dead with the chamber open |
| Camera | Pi Camera, **lens unscrewed and removed** | Lensless speckle grain ≈ λz/D ≈ 4.3 µm at 20 mm over a 3 mm spot, about 3.1 pixels on the OV5647's 1.4 µm pitch, inside the 3–5 px check below. (On an IMX219's 1.12 µm pitch the same grain is 3.9 px; §6 specifies the OV5647 because its lens unscrews.) With a lens fitted the grain falls to ~1.6 px and is undersampled |
| Standoff | ~20 mm, off the specular axis | |
| Settings | **Fixed** exposure ≤2 ms, fixed gain, AWB off, denoise off | Any auto-adjustment between frames destroys the correlation measurement. This is the single most common way to get garbage out of this sensor |
| Capture | 128×128 ROI, 16 frames per burst, one burst every 20 s | |

**Verify before trusting it:** take the 2-D autocorrelation of a single frame. The central peak should span 3–5 pixels. Narrower means undersampled speckle; broader means you are imaging something other than speckle.

**The two paths must not run at once.** The laser contaminates the 630 nm channel and the white LEDs wash out the speckle. Interleave: LEDs on for the chemistry read at t = 5 s, laser only during bursts.

**Light-tightness test:** cartridge inserted, room at 10,000 lux, all LEDs off. The Clear channel must read under 0.5% of its LEDs-on value. Print the chamber in black PETG at ≥4 perimeters and paint the interior matte black. Thin PETG passes more light than you'd expect.

**Cartridge slot:** 34.0 × 3.0 mm on the front edge (model: `front_slot`), with a sprung silicone flap plus a 6 mm offset baffle behind it.

### The chamber diffuser

A Ø6 mm ground-glass disc, epoxied into the chamber wall. It is what makes the
enclosure part of the key: `firmware/optical_puf.py` reads its speckle at every
unlock and mixes the result into the seed-wrapping KDF, so a case that has been
opened derives a different key and the seed does not unwrap. Skip it and the
device still works. The KDF term is simply absent, but the tamper binding is
what you are skipping.

| | |
|---|---|
| Position | Chamber wall, lit by the same 650 nm diode, imaged by the same camera. **Clear of the cartridge's optical window** |
| Standoff | ~20 mm, as for the blood path, so the grain lands at the same 3–5 px |
| Bond | Two-part epoxy, opaque black, filling the void behind the disc |
| Capture | 768×768 ROI, 16 frames, averaged |

**Clear of the cartridge window** is the constraint that matters. If a seated
cartridge is in the diffuser's optical path, then changing cartridges changes
the reading and every cartridge change looks like tampering. The laser
interlock still applies, so the bay must be closed for the read, the cartridge
closes the bay, it must not be part of the measurement.

**The mount matters as much as the bond.** A speckle grain is about 4 px, so
the pattern only has to slide one grain for the raw features to be destroyed —
and PETG over the 20 mm standoff moves roughly a pixel per kelvin, which makes
a cold morning enough on its own. `optical_puf` registers every read against
two published fiducial patches before it reads anything: ±24 px of slide and
about 3° of twist come out, and both are reported rather than merely absorbed,
so a chamber that is drifting can be told from one that has been opened. Keep
the standoff rigid and the whole assembly moving together, the budget is there
for thermal creep, not for a camera free to wander.

**Not hot glue, and not tape.** Both creep with temperature. The diffuser has
to be in the same place in six months as it is today, because "the same place"
is what the key is. Epoxy it once and leave it.

**768×768, not the 128×128 the blood path uses.** The PUF spends grains on key
material, on the margin filter that discards the unreliable ones, and on a rule
that no two key bits come from touching grains, neighbouring grains share the
tail of one speckle lobe and are not independent. Same sensor, same optics, a
larger crop; `hardware.read_chamber_burst` switches the mode and switches back.

**Averaged, unlike the blood burst.** There the frames carry the signal and
averaging would destroy it. Here the pattern is meant to be static, so the
frames are repeated looks at one thing and averaging buys shot-noise margin.

**Keep something in the slot.** This is the part that surprises people, so it
is worth stating on its own. The chamber is read at EVERY unlock, because its
answer is a term in the key that opens the seed, and the laser interlock is
wired through the cartridge switch, in series with the diode's supply, where
firmware cannot reach it. So on a chamber-enrolled device the bay has to be
closed for a **touch** signature too, not only for a blood one, even though
touch consumes nothing and involves no cartridge.

Leave a cartridge seated between spends. A spent one does, and so does
`cartridge_null`, which has no well and is already on the print list. Swap in a
fresh cartridge when you are actually bleeding into it. The diffuser sits clear
of the cartridge window either way, so which one is in there changes nothing
about the reading.

A device that has NOT enrolled a chamber never reads it, and none of this
applies.

---

## 10. Enclosure

**Printing the shells:**

```bash
python3 tools/gen_enclosure.py      # -> models/print/shell_lower.stl, shell_upper.stl
```

The viewer model is an appearance model, solid extrusions, with the openings drawn as dark boxes and nothing cut out. Slice it and you get a brick. `tools/gen_enclosure.py` is the source for the inside: 2.4 mm wall, the part line at 11.4 with a tongue and groove, the four openings actually removed, six M2.5 insert bosses, rails the Pi slides in on, and the light-tight skirt around the optical chamber. It re-checks the envelope against the figures below on every run, and re-checks that the thing can still be assembled, cartridge path, blind vents, Pi bay, sensor port, part line. Both files are parametric; the checks are what keep them describing one instrument.

**`viewer/model.js` is the parametric source of the enclosure.** It builds the geometry; `models/instrument.obj` is an export from it, and `diagrams/mechanical.svg` is generated from that export by `tools/gen_mechanical.py`. The chain is one-way:

```
viewer/model.js  ──export──▶  models/instrument.obj  ──generate──▶  diagrams/mechanical.svg
```

Edit the model, re-export, re-run the generator. CI fails if the drawing and the OBJ disagree. Do not hand-edit the OBJ. It is 56 MB of triangles and nothing downstream of it can be reconciled with a parametric change.

**Envelope: 116.2 × 73.2 × 28.3 mm.** Two shells parted at 11.4 mm from the base, with the seam picked out in oxblood. The Pi enters from the rear like a cartridge; the sample cartridge from the front, on the same centreline as the dish.

| Feature | Dimension | Notes |
|---|---|---|
| Sample dish | Ø47.2, 2.0 deep | Recessed into the deck. The optical head sits above it |
| Ring | Ø14.4 OD / Ø9.8 ID, 1.5 proud | Oxblood, smooth bezel. **A marker for the measurement spot, not a control, nothing rotates** |
| Index ticks | 60 @ R21.2, every 5th in steel | Around the dish |
| Display | 49.7 × 37.7 | Flush glass, oxblood bezel |
| Buttons | 3 × Ø5.8 + 1 × Ø8.6 | The Ø8.6 is CONFIRM, with its own collar |
| Pad | 24.0 × 12.0 | Printed marking. **Reserved, see below** |
| Sample slot | 34.0 × 3.0, 4.2 deep | Front face |
| Compute bay | 72 × 16, 3.2 deep | Rear face |
| USB-C | 9.0 × 3.2 | Right face, power only |
| Vents | 15 slots, 3.0 deep | Front face. **Must be blind, see below** |
| Fasteners | 2 × Ø4.0 slotted | Front face, lower shell |

### Constraints not expressed in the model

**1. The vents must be blind pockets.** They're 3.0 mm deep into a 73 mm body, so they are pockets in the model. Keep them that way. If any becomes a through-hole, ambient light reaches the optical chamber and the 415 nm gate stops working. Verify with the light-tightness test in §8, not by eye.

**2. The pad is reserved, not fitted.** It is a flat printed marking sized for the optional fingerprint sensor, which the base build doesn't use. The PIN does identity (§4). It is deliberately not a recess: an unpopulated pocket on the deck is a place for blood to collect.

**3. The dish is a reader, not a dial.** The ring and the 60 index ticks are decorative. Nothing rotates. The cartridge enters through the front slot and sits under the dish, and the ring frames the measurement spot and serves as the contact surface for the touch tier.

**4. The display window is bigger than any 1.3 in module.** 49.7 × 37.7 comes from the viewer model; a 1.3" 240×240 panel has a ~23 mm active area. `models/print/display_bezel.stl` masks the window down to the screen and is the one printed part fitted to a component this specification does not pin down, **measure the module you bought** and set `SCREEN_W`, `SCREEN_H` and `SCREEN_OFFSET_Y` at the top of `tools/gen_printables.py` before printing it. The module hangs below the deck on the four Ø4 posts, M2 self-tappers into their Ø1.8 pilots; the bezel drops into the window from outside, flush with the deck, counterbored over those screw heads.

### Print settings

| Part | Material | Layer | Perimeters | Infill | Special |
|---|---|---|---|---|---|
| Shells | PETG black | 0.16 | 4 | 25% | Part line down, no supports |
| Optical chamber | PETG black | 0.12 | 6 | 40% | Paint interior matte black |
| Aperture tube | PETG black | 0.12 | 4 | 100% | Paint interior matte black |
| Cartridge | PETG **white** | 0.15 | 3 | 100% | **Ironing ON**, only the white patch surface matters |
| Display bezel | PETG black | 0.12 | 4 | 100% | Front face down. Fitted to your screen, see below |

`tools/gen_printables.py` emits every part in this table except the shells, already at these settings, see `models/print/MANIFEST.md`, which is generated alongside the STLs and carries orientation, quantities and every derived dimension. `PRINTING.md` is the runbook: plate order, what to check off each part, and the post-processing that is not optional.

PETG, not PLA, PLA creeps under screw preload and softens in a hot car. The oxblood elements (seam, ring, bezel, ticks) are a second filament or a paint fill; the model separates them as distinct objects with their own materials, so a multi-material printer can take them straight.

**Note:** `models/instrument.mtl` is exported alongside the OBJ by `tools/export_model.py` and carries the viewer's own colours. Material names also ride on the objects themselves (`shell`, `oxblood`, `trim_oxblood`, `glass`, `pad`, `etch_floor`, `steel`, `cavity`), so you can substitute your own filament colours without losing the separation.

---

## 11. Wiring

Everything on I²C1 at **100 kHz** plus SPI0 for the display. BCM numbering.

**Leave the bus at 100 kHz. This is the ATECC608B's constraint, not the AS7341's.**
The chip sleeps between commands and is woken by holding SDA low for ≥60 µs,
which `cryptoauthlib` does by writing `0x00` at the bus speed. That byte is low
for ~90 µs at 100 kHz and only ~2.5 µs at 400 kHz, so at 400 kHz the part never
wakes and every call returns a timeout that reads exactly like a chip you have
mis-soldered. The Linux `i2c-dev` API cannot drop the speed for a single
transfer, so the bus rate is the fix. `raspi-config` leaves `i2c_arm_baudrate`
at 100 kHz. The correct value here is the default, so simply do not raise it.

The AS7341 has room for this: touch mode's 20 ms budget per PPG sample spends
~5.6 ms integrating (§4) and ~2 ms on the register reads at 100 kHz. If gate T0
still reports a rate below `fs_min` on your build, give the ATECC its own
`dtoverlay=i2c-gpio` bus and put the AS7341 back on hardware I²C1 at 400 kHz —
do not raise the shared bus and hope.

`diagrams/wiring.svg` draws the Phase 1 half of this table. The reader, which is what you build first. It is generated from the table below by `tools/gen_wiring.py`, so the sheet you solder from cannot drift from the spec. Change the table, re-run the generator, commit both.

| Pin | Function |
|---|---|
| GPIO2/3 | I²C1, AS7341 (0x39), ATECC608B (0x60) |
| GPIO5, 13, 19 | UP / DOWN / BACK |
| **GPIO26** | **CONFIRM**, dedicated, RC-debounced (10 kΩ + 100 nF), shares no bus |
| GPIO8–11 | SPI0 → display |
| GPIO25 / 27 / 24 | Display D/C, RESET, backlight |
| GPIO12 | White LED #2 gate (2N7002 low-side, 68 Ω to **+5 V**) |
| GPIO6 | Laser gate (2N7002), interlocked to the cartridge switch |
| GPIO23 | 940 nm IR LED gate (2N7002 low-side, 47 Ω to **+3V3**) |
| GPIO22 | Cartridge-present microswitch, internal pull-up, LOW when seated |
| CSI | Camera |

**Two common first-build failures:**

1. **Both I²C breakouts ship with pull-ups fitted.** Remove one pair (2.2 kΩ) or the bus may not enumerate. This is the #1 first-build failure.
2. **CONFIRM is on its own pin for a reason.** An attacker who owns the SPI bus still can't assert it.

3. **The two LED rails are not the same rail**, and this is derived from the
   resistor values rather than stated anywhere, so check it against the parts you
   actually bought. 68 Ω suits a white LED (Vf ≈ 3.1 V) on +5 V, giving ~28 mA; on
   +3V3 the same resistor yields ~3 mA and the LED barely lights. 47 Ω suits the
   940 nm LED (Vf ≈ 1.35 V) on +3V3, giving ~41 mA; on +5 V it passes ~78 mA and
   cooks a 5 mm part. Only one assignment makes both values sensible, which is why
   the table reads the way it does. The rule, if your LEDs differ: size R for
   ~20–30 mA at your Vf, then pick the rail that value implies. The MOSFETs switch
   the low side either way, so 3V3 gate drive is fine for both.

4. **A USB-C breakout with no CC pulldowns delivers nothing.** A compliant source
   reads the absent 5.1 kΩ on CC1/CC2 as "nothing plugged in" and never turns on.
   Most power-only breakouts fit them; some do not. Measure CC1–GND before you
   conclude the Pi is dead. Budget 5 V at 2 A: the Zero 2 W peaks near 0.5 A, and a
   blood run has the webcam, laser and LEDs live at once.

### Radio removal, non-negotiable

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

Verify: `iw dev` empty, `hciconfig` empty. Desolder USB D+/D− or use a data-blocker, power only.

---

## 12. Firmware

### From a blank SD card to a running device

Do this on the bench, with the case open, before the seed exists. Every step
has a check, because a step that silently half-worked is worse than one that
failed.

**1. Flash the card.** Raspberry Pi Imager, *Raspberry Pi OS Lite (64-bit)*.
In the gear menu set a hostname, enable SSH with a password, set a user, and
**do not configure wifi**. You will remove networking entirely later; you only
need it long enough to install packages.

**2. Enable the buses.** `sudo raspi-config` → Interface Options → enable
**I2C**, **SPI** and **Legacy Camera**/**Camera** as your image offers. Reboot.

```bash
ls /dev/i2c-1 /dev/spidev0.0        # both must exist
i2cdetect -y 1                      # 0x39 AS7341, 0x60 ATECC608B once wired
```

**3. Install what the firmware needs.**

```bash
sudo apt update && sudo apt install -y python3-numpy python3-scipy \
     python3-cryptography python3-opencv python3-gpiozero python3-pil \
     i2c-tools git
sudo pip3 install --break-system-packages cryptoauthlib qrcode \
     adafruit-circuitpython-as7341 adafruit-circuitpython-rgb-display
```

`picamera2` ships with Raspberry Pi OS. Nothing else is needed: the signing
stack has no third-party dependency.

**4. Put the firmware on the device and prove it runs there.**

```bash
git clone <your fork> ~/cell && cd ~/cell
python3 firmware/run_tests.py
```

All suites must pass **on the Pi**, not only on your laptop. This takes a few
minutes on a Zero 2 W. It is the cheapest possible check that the card, the
Python and the install are sound, and it runs before any key exists.

**5. Check the hardware answers.** With the sensor head and the gate chip
wired per §11, run the bench checks. Each takes about a minute and each
settles something no amount of testing on a laptop can:

```bash
tools/bench.py display                      # is the panel's origin the driver's?
tools/bench.py buttons                      # do your switches settle in 30 ms?
tools/bench.py atecc --i-can-wipe-this-chip # does the PIN counter actually gate the key?
tools/bench.py thermal --load 4             # what a sealed case does over a 10 min run
```

The ATECC608B check wipes the chip, which is the point: a counter that
survives being tested was never tested. Run it before there is a seed to lose,
and re-provision afterwards. If "the wrapping key CANNOT be derived without a
PIN" fails, stop, slot 0 is not bound to the PIN slot, the attempt counter is
decoration, and an eight-digit PIN is a hundred million offline guesses
against the encrypted seed, with nothing debited for any of them.

Then:

```bash
python3 firmware/se_atecc.py --probe     # after the zones are locked
python3 firmware/app.py --dir /boot/cell --console
```

The console runner drives the real loop against stub hardware, so you can walk
the screens before trusting the panel.

**6. Calibrate.** §13, in full. Do not skip to provisioning, the thresholds
the device ships with are physics-derived starting points, not your optics.

**7. Provision.** §12, *Provisioning*, below. Write the words on paper, and do
the restore drill in the build order before you fund anything.

**8. Harden, then seal.** §11's radio removal and antenna cut, the read-only
rootfs, `cell.service`, and only then the tamper seal. In that order: a sealed
case you have to reopen because a package was missing is a seal that no longer
means anything.

### Wallet layer

The signing stack is in `firmware/`, not delegated. That was a reversal: the earlier plan was to fork [SeedSigner](https://github.com/SeedSigner/seedsigner) and add a gate to it, on the reasoning that writing your own PSBT parser is how you lose money to a change-address bug. That reasoning is still correct, and it is exactly why the parser here is written the way it is, but the gate turned out not to be separable. The tier decision needs the amount. The confirmation screen needs the change ownership. The attestation binds to the sighash. All three want the transaction already parsed, and a signer that hands those out through a plugin boundary is a signer whose security properties live on both sides of that boundary.

So the stack is here, and the mitigation for writing it ourselves is that none of it is trusted on its own authority:

| Module | Checked against |
|---|---|
| `secp256k1.py` | RFC 6979 vectors, BIP-340 vectors, OpenSSL for ECDSA verification |
| `bip39.py` | The official Trezor vectors; the wordlist's SHA-256 is verified on load |
| `bip32.py` | BIP-32 vectors 1, 2 and 5 |
| `addresses.py` | BIP-173 and BIP-350 valid *and* invalid vectors; EIP-55 vectors |
| `tx.py` | BIP-143 P2WPKH and P2SH-P2WPKH vectors; a real mainnet transaction |
| `eth.py` | Yellow-paper RLP vectors; EIP-1559 encoding |
| `hashes.py` | ISO RIPEMD-160 vectors; Keccak-256 vectors |

During development every signature was also compared byte for byte against `embit` (Bitcoin, all four script types) and `eth-account` (Ethereum, across six chain ids). They match exactly, including Bitcoin Core's low-R grinding convention, which is why our DER encodings are the same length as everyone else's. Neither package is a dependency; the vectors they confirmed are in the suites.

SeedSigner remains the reference worth reading for the parts this repo does not solve: the ST7789 UI, camera handling, and the hardened read-only image build.

### What the device recomputes rather than believes

A PSBT is a document written by software the device does not trust. `firmware/psbt.py` treats every number in it as an assertion until it is rederived:

- **Input amounts.** A segwit v0 signature commits to its own input's amount and not the others', so a host that understates one turns the difference into fee. Every non-taproot input must carry its full parent transaction, whose txid is recomputed and compared to the outpoint. Taproot commits to every amount at once, so there, and only there. A witness UTXO alone is enough.
- **Which output is change.** The host labels an output as change by attaching a derivation path. The device derives the key at that path from its own seed, rebuilds the scriptPubKey, and compares it byte for byte. An output that fails is shown as an unverified destination, in full, with a warning, never folded into "change".
- **The script type**, read from the scriptPubKey itself, because it selects the sighash algorithm.
- **The sighash flag.** SIGHASH_ALL only. Every other flag lets someone change part of the transaction after the owner approved it.

`firmware/test_wallet.py` runs each of these as an attack and requires a refusal.

### Multisig has to be registered first

The device refuses a multisig input belonging to a quorum it has not been told about, and will not call a multisig output change unless the whole quorum rebuilds it. Register the co-signers once, on every device in the quorum:

```bash
python3 tools/provision.py show --dir /boot/cell        # your line, to send out
python3 tools/provision.py multisig --dir /boot/cell \
    --label family --threshold 2 --cosigners cosigners.txt
```

The file is one co-signer per line, `label fingerprint path xpub`, and it must include this device. BIP-48 paths (`m/48'/coin'/account'/2'` native, `.../1'` p2sh-wrapped) are derived at provisioning whether or not you ever use them, so getting your own xpub does not mean re-opening a sealed case.

**Why the ceremony.** Without the co-signers on file, the only question the device can answer is "does this script contain a key of mine?". A coordinator under an attacker's control can build a script holding exactly one key of yours and n-1 of theirs: it hashes correctly, the wallet calls it change, and the balance moves to an address you cannot spend without them. With the quorum registered the question becomes "does this equal the script my co-signers produce at the path it claims?", which is arithmetic. BIP-67 key ordering is recorded rather than guessed, because the wrong choice produces a different address instead of an error.

### EVM chains have to be registered too

The device ships knowing Ethereum and Sepolia. Every other chain id is refused
until you register it, with the name and the native-token ticker it should be
displayed under:

```bash
python3 tools/provision.py chain --dir /boot/cell \
    --id 42161 --name "Arbitrum One" --ticker ETH
python3 tools/provision.py chain --dir /boot/cell \
    --id 137 --name "Polygon" --ticker POL
```

**Why this is not just a shorter list.** The signature commits to the chain id,
but nobody reads a chain id. The name and the ticker are what the owner
actually reads to know which network and which denomination they are approving.
If those two strings could arrive with the transaction, an attacker who labels
chain 1 "Sepolia (test)" collects a blood-gated signature on real money from an
owner who believed it was play money. Registering them yourself makes the label
your own claim, exactly as registering a quorum makes the script your own claim.

So check the chain id against a source you trust before you type it, and read
back the confirmation the command prints. Nothing downstream can catch a
registration that names the wrong network. It is wrong on every transaction
you will ever approve on that chain.

Registrations are refused if they would rename a chain already registered, or
relabel one of the two built in. Names are capped at 24 characters and tickers
at 8, both printable ASCII only: a name carrying a direction override or a
zero-width joiner renders as something other than what was registered.

### Proving it against a node

`tools/regtest_e2e.py` runs the whole thing against Bitcoin Core on a private regtest chain: Core funds an address the firmware derived, the firmware signs a PSBT spending it, and Core finalises, accepts and mines the result. Every script type, taproot and 2-of-3 included.

```bash
tools/regtest_e2e.py --bitcoin-dir /path/to/bitcoin-28.0/bin
```

It starts a private regtest node, runs every script type through it, and stops
the node again. Pass `--datadir` to keep the chain around, or `--no-start` to
drive one you started yourself.

Worth doing before you fund anything, and worth doing again after any change to `psbt.py`, `tx.py` or `addresses.py`. It is the only check in this repo that answers on its own authority rather than by comparison, and it earned its place the first time it ran by finding a malformed BIP-174 proprietary key that made every PSBT this device produced unreadable to Core.

### Both PSBT dialects

The device reads BIP-174 version 0 and BIP-370 version 2, and hands back whichever it was given. A v2 PSBT that came back as v0 is one a coordinator may not be able to finalise. Version 2 is rebuilt into the transaction its scattered fields describe and then verified by exactly the same code, so there is one set of rules about amounts, change and sighashes rather than two that could drift apart.

### What it still will not sign

- **Taproot script-path spends.** The device holds no leaf scripts and could not render one, so an input whose output key is not the tweak of a key it derives is refused. Key-path spends are fully supported.
- **More than one destination per Bitcoin transaction**, for the reason in section 5.
- **Any calldata on Ethereum.**

### Starting on boot

`tools/cell.service` is the systemd unit. It runs the loop as an unprivileged `cell` user with access to exactly four device nodes, because the QR parser is the one part of this device that reads bytes an attacker chose, and a bug there should cost one process rather than the machine.

```bash
sudo useradd -r -s /usr/sbin/nologin -G spi,i2c,gpio,video cell
sudo mkdir -p /opt/cell && sudo cp -r firmware /opt/cell/
sudo chown -R cell:cell /boot/cell && sudo chmod 700 /boot/cell
sudo cp tools/cell.service /etc/systemd/system/ && sudo systemctl enable --now cell
```

The unit has no `After=network.target` and wants no network. If a later edit adds one, that is a change to the threat model rather than a convenience.

The rootfs is read-only (`raspi-config` → Performance → Overlay FS), and `/boot/cell` is the only writable path the service is given. That directory holds the encrypted seed blob, the watch-only accounts, the registered quorums and `thresholds.json`, everything that must survive a power cut, and nothing that must stay secret from someone holding the card.

### The screen and the buttons

`app.py` is the loop the owner actually meets, and it is written against protocols, `Display`, `Buttons`, `Camera`, so the whole thing can be driven on a laptop with fakes. `test_app.py` does that, and asserts the ordering the design rests on: the transaction is shown before the PIN is asked for, the PIN before the gate, the gate before anything is unwrapped.

| Part | Driver | Notes |
|---|---|---|
| ST7789 240×240 | `display.py` | 40 columns × 20 rows at 6×12. The layout limits are enforced again at paint time, on the exact lines being painted |
| Four buttons | `buttons.py` | CONFIRM on GPIO26, its own RC debounce, sharing no bus. A press that arrives faster than a screen can be read is ignored, and the queue is drained before consent is asked for |
| USB webcam | `camera.py` | The CSI port belongs to the speckle path. QR decoding tolerates auto-exposure; the correlation measurement does not |

Run it dry, without any of that hardware:

```bash
python3 firmware/app.py --dir /boot/cell --console
```

### Wiring the gates to the signer

`app.run_gate_on_hardware` is the seam between the two halves of this device. Both tiers share one AS7341 and one bore, so the touch sensor is handed the blood head instead of opening I2C a second time; thresholds come from `thresholds.json` if it is there, and from the physics-derived defaults if it is not.

`app.gate_result` adapts what the gates return. Every gate's score, the features behind them, and a message naming the specific failure, into the `(passed, attestation)` the unlock chain consumes. The attestation dict is what `signer.liveness_digest` hashes into the record, which is why the measurements travel and not just a verdict: a co-signer can then pin a claim to one capture instead of to somebody's assertion that a gate ran.

Note that the two tiers name their measurements differently, blood reports `gate_scores`, touch reports `features`, and the digest reads both. Adding a tier means checking it appears under one of those names, or its attestation degrades to a signed boolean without anything failing.

### Provisioning

Once, with the case open, on the device:

```bash
python3 tools/provision.py new    --out /boot/cell --pin ******   # or `import`
python3 tools/provision.py show   --dir /boot/cell                # the public half
```

`new` draws entropy from the kernel CSPRNG XORed with the ATECC608B's hardware RNG, not because the kernel is suspect, but so that a flaw in either source alone is survivable. It prints the words once, then asks you for three of them back before it writes anything. There is no command that reprints them: a device that will show its seed on demand will show it to whoever is holding it.

It writes two files:

| File | Contents |
|---|---|
| `seed.blob` | **Two** wrapped mnemonics, AES-256-GCM, each under a key derived inside the ATECC608B from a PIN and a secret that never leaves the chip. Mode 0600 |
| `accounts.json` | Master fingerprints and the account xpubs, for both wallets. Watch-only, public, safe to copy to a coordinator |

Two seeds, always, whether or not you asked for a duress PIN. See §12's duress note and `firmware/duress.py`. With one, the second seed is the decoy. Without one, it is a real 24-word mnemonic wrapped under a key nobody can derive, and it is unreachable forever. One file of a fixed size either way: a card carrying one blob would announce that this device has no decoy, and a card carrying two would announce that it has one.

Before it reports success it re-reads the store through the same path signing uses, verify_pin, then the chip's KDF, then decrypt, and refuses to declare the device provisioned unless the words come back byte for byte. With a duress PIN it does this twice, and checks that the duress PIN opens the *decoy* rather than the real wallet. A device that cannot reopen its own seed is the worst outcome available here, and it costs nothing to rule out.

### Configuring the ATECC608B

**This is the step that used to be missing, and it is the one that is permanent.** The slot map below is not something to transcribe by hand from the datasheet; `tools/atecc_config.py` builds it, shows it to you, writes it, reads it back and only then locks.

| Slot | Holds | Configured |
|---|---|---|
| 0 | Wrapping secret | Secret, HMAC use only, **ReqAuth → slot 2**, metered by Counter0 |
| 1 | Attestation secret | Secret, HMAC use only, no authorisation. The idle screen must be able to show the pubkey |
| 2 | Normal PIN key | Secret. Holds `SHA-256("CELL/pin/v1" ‖ serial ‖ PIN)` |
| 3 | Normal PIN baseline | Clear read, **encrypted write under slot 2** |
| 4 | Duress PIN key | Secret. Identical configuration to slot 2 |
| 5 | Decoy wrapping secret | Secret, HMAC use only, **ReqAuth → slot 4** |
| 6 | Duress PIN baseline | Clear read, encrypted write under slot 4 |
| 7–15 | Nothing | Secret and unwritable, so nothing else can use them as scratch |

The procedure, in this order:

```bash
python3 tools/atecc_config.py plan            # read the AFTER table. Actually read it.
python3 tools/atecc_config.py write --i-have-read-the-plan
python3 tools/atecc_config.py lock-config --permanent
python3 tools/provision.py new --pin ... --out /boot/cell    # writes the slot secrets
python3 tools/atecc_config.py verify --behaviour             # BEFORE the last lock
python3 tools/atecc_config.py lock-data --permanent
```

The secrets go in between the two locks, because data slots stay writable until the *data* zone locks and the slot policy only takes effect once the *config* zone has.

`verify --behaviour` is the step that matters and the only one that proves anything. Reading the config zone back tells you the bytes are there; it does not tell you the chip enforces them. So it asks the chip to misbehave, read a secret slot, derive with no CheckMac, write a baseline in the clear, and every one must be refused. Run it yourself and read the output, while a wrong answer is still recoverable. `lock-data` also runs it and refuses a chip that fails, so the last irreversible step does not depend on you having remembered; `--skip-behaviour` overrides that if you know why a particular chip answers differently.

**Two things about `atecc_config.py` you should know before trusting it.** It never invents a byte it does not understand: it reads your chip's own config, replaces only the SlotConfig and KeyConfig entries, and passes the serial number, both counters and every reserved field through untouched. And the bit positions in it were *transcribed from the datasheet*, but they are no longer only that.

**Install `cryptoauthlib` before you run any of this.** With it present, `run_tests.py` checks two things it otherwise skips, and both are worth the install on their own:

* every config-zone offset and both bitfields against `cryptoauthlib.device.Atecc608Config`, which is Microchip's own definition of the same 128 bytes;
* `se_atecc.checkmac_response()` against `atcah_check_mac()` in cryptoauthlib's bundled shared object, which is Microchip's C implementation of the same digest.

Both agree exactly today. That retires most of the transcription risk. Two independent readings of one datasheet page giving the same answer, but it does **not** tell you the chip enforces what those bytes describe. Only `verify --behaviour` does. Run it.

**ReqAuth is the line to get right.** Slot 0 must refuse to derive until a CheckMac against slot 2 has just succeeded. Skip it and the PIN counter does nothing: an attacker never calls `verify_pin` at all, they call the derive once per candidate PIN and let AES-GCM's tag tell them when they are right.

**What the chip enforces, and what it does not.** There is no silicon retry counter on this part. The ten-attempt limit is firmware arithmetic over a monotonic counter and an encrypted baseline, and firmware is what an attacker with the case open replaces. What the chip *does* enforce is that Counter0 stops at 2,097,151 uses, permanently. That is the real ceiling on how many PIN guesses any firmware can ever make, and it is why the PIN is **eight digits, not six**. 10⁶ fits inside that budget; 10⁸ does not, so the chip bricks before the keyspace is exhausted. `firmware/se_atecc.py`'s module docstring is the long version.

One design difference is worth naming, because it is where the gate lives. SeedSigner is stateless: it re-derives from a seed you type in each time, so there is nothing on the device to gate. CELL stores the seed encrypted and gates its decryption, which is what lets a liveness proof stand between an attacker and a key that is already there.

### Stack

```
Raspberry Pi OS Lite 64-bit
  ├─ read-only rootfs (raspi-config → Performance → Overlay FS)
  ├─ purge wpa_supplicant, dhcpcd, avahi, ssh
  └─ python3
       ├─ cryptography                           (AES-256-GCM, seed at rest)
       ├─ numpy, scipy                           (gates 5–6)
       ├─ adafruit-circuitpython-as7341          (spectrometer)
       ├─ picamera2                              (speckle capture)
       ├─ cryptoauthlib                          (ATECC608B; also cross-checks
       │                                           the config map and the
       │                                           CheckMac digest in the tests)
       ├─ adafruit-circuitpython-rgb-display,
       │  pillow, qrcode, gpiozero, opencv       (screen, buttons, QR)
       └─ firmware/                              (the signing stack itself:
                                                  secp256k1, BIP-32/39, PSBT,
                                                  RLP — no third party)
```

The signing stack has no third-party dependency at all. `cryptography` is used
for one thing, AES-GCM on the seed blob, because hand-rolling AES is the wrong
thing to be clever about. Everything else in `firmware/` is pure Python
checked against published test vectors.

### Unlock chain

Implemented in `firmware/signer.py`, with the step order asserted in the tests against `signer.EXPECTED_ORDER`.

```
1. render        refuse anything unrenderable, before anything else
2. policy        the DEVICE picks the tier; the operation never does
3. confirm       CONFIRM on GPIO26, showing this exact transaction
4. PIN           ATECC608B HMAC against a verifier written at provisioning.
                 Counter increments BEFORE the compare, so power-cycling
                 mid-attempt doesn't refund an attempt. 10 failures → wipe.
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

**Configure the wrapping slot to require prior authorisation.** This is the single most important line of ATECC608B configuration in the build, and it is config rather than code: the slot holding the wrapping secret must require a successful CheckMac before it will derive, so the derive is physically unreachable without an attempt the counter already debited. Skip it and the PIN counter does nothing. An attacker never calls `verify_pin` at all, they call the derive once per candidate PIN and test each result against the encrypted seed, where AES-GCM's tag tells them when they are right. An eight-digit PIN is 10⁸ tries with nothing debited and no wipe. `SoftSE` models the rule so the unlock chain is tested against it: one PIN verification authorises exactly one derive.

`tools/atecc_config.py` writes that binding, see "Configuring the ATECC608B" above, and `firmware/se_atecc.py` performs the CheckMac it demands. The two are one change: a driver that skips the CheckMac cannot open its own seed on a chip configured this way, which is how the previous version of this firmware would have failed on a bench.

**The wrapping key uses stable inputs only. The PIN and the on-chip secret.** This is what makes the seed recoverable: a key must open tomorrow the seed it wrapped today. Liveness measurements are a fresh physical event with no reproducibility, and the sighash changes every transaction, so mixing either into the KDF yields a key that can never reopen anything. Both are still bound tight, in the place where binding them is worth something: the signed attestation, which a third party can verify. The signature already commits to the sighash cryptographically, so nothing is lost by taking it out of the KDF.

On a Pi Zero 2 W the gate ordering is enforced by firmware, on the same footing as the firmware hash and the tamper seal the attestation already declares. A CM4 with verified boot raises that floor when a build calls for it.

`Signer` takes the display, the gate, the seed unwrap and the signing primitive as injected collaborators. `firmware/wallet.py` supplies them for real and `firmware/app.py` drives the whole loop, neither touching the order of the chain.

The seed is exposed in RAM for milliseconds. This is the cost of using a $6 gate chip instead of a secure element that signs internally, and of having a conventional backup path.

### Nonce generation

Never derive a signing nonce from a biometric measurement. A structured or predictable nonce leaks the private key.

- **Schnorr (BIP-340):** `aux_rand32 = SHA256(pi_hwrng ‖ atecc_trng ‖ blood_noise_residual)`. BIP-340 hashes `aux_rand` in such a way that even fully attacker-controlled input degrades gracefully to the deterministic case. This is the only safe way to mix in field entropy.
- **ECDSA:** RFC-6979 deterministic. Don't add entropy here at all.

`blood_noise_residual` is the high-frequency residual after the fitted models are subtracted. The genuinely unpredictable part, with all structure removed. It contributes; it never determines.

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
| **edta** | **EDTA anticoagulated tube blood. The most important negative class** |
| citrate | Citrate tube blood, loaded as drawn (not recalcified, see §16) |
| animal | Pig or beef from a butcher |
| hemolyzed | Your blood, frozen and thawed |
| empty | No sample |

Mammalian haemoglobin is spectrally near-identical to human, so pig blood **will** pass Gates 1–2. That's expected. Gates 3, 5 and 6 reject it, and those are the gates that matter. If you want species discrimination you're asking for DNA sequencing, and that's a different project.

### Procedure

```bash
python calibrate.py capture --label genuine       # ×30+
python calibrate.py capture --label edta          # ×30+   ... etc
python calibrate.py enroll-reference              # your own reference, into thresholds.json
python calibrate.py roc                           # sets EVERY threshold, writes thresholds.json
```

`roc` sets **every** threshold in `blood_gate.Thresholds`, not just two, from the distribution of your genuine captures, then measures the false-accept rate against the whole panel through the conjunction of all six gates. A threshold is set from the genuine distribution and not from a gap to the spoofs, because each gate owns its own physics and no more: dye is rejected on return signal, EDTA blood on arrested motion, deoxyHb on spectral shape. Demanding that every threshold separate every class is incoherent, and is why the gates are an AND rather than a score.

Target **FRR ≤ 5%**. A false reject costs one cartridge and one lancet. Bias hard toward rejecting; `--drift` exists to loosen the thresholds and defaults to 0.

### Calibrating the touch tier

The touch tier is the everyday default and authorises far more signatures than the blood tier ever will, so it gets the same treatment. Sessions are 15 seconds rather than 600, so the whole panel is minutes:

```bash
python calibrate.py touch-capture --label genuine        # ×30+, hold still
python calibrate.py touch-capture --label pump_fake      # ×30+   ... etc
python calibrate.py touch-roc                            # writes touch_thresholds.json
```

The panel is your fingertip, nothing on the ring, a static object, a mechanical pulsator, a dyed silicone finger, a moving finger, and out-of-range rates high and low. `touch_gate.TouchThresholds.load()` reads the file the sweep writes, put it in the provisioned directory (see below), or the tier you use every day keeps running on shipped defaults.

`touch-capture` asks you twice. The first prompt takes the **empty-bore reference** with nothing on the ring; the second starts the capture. That order is not politeness. The contact gate is `mean(red) / bore_red`, so a reference measured through the finger is a reading of the finger against itself, and both the calibration and the device would then be fitting and judging a number that means nothing. The device follows the same order and shows a "keep the ring clear" screen before it asks for your finger.

`fs`, `fs_min` and `duration_s` are deliberately not swept. They describe the capture rather than the finger, and fitting a validity floor to the very sessions it is meant to validate is circular. For the same reason the beat detector spaces peaks by a fixed physiological ceiling (`PEAK_MAX_BPM`) rather than by `bpm_max`: a number that is both an accept threshold and an analysis parameter gets fitted under one detector and judged under another, which puts FRR at 100%.

**The FRR that `roc` prints is in-sample.** The thresholds were fitted to those same genuine captures, so it is optimistic by construction. The honest number comes from captures taken *after* calibration.

### Then put the files on the device

Two files, one per tier. They live in the provisioned directory, beside the seed store, and the device reads each with its own loader:

```
thresholds.json          →   blood_gate.Thresholds.load()
touch_thresholds.json    →   touch_gate.TouchThresholds.load()
```

**Copy both.** They are not interchangeable and neither is optional: the two dataclasses share exactly one field name, so handing blood's file to the touch loader drops every touch threshold in it and silently substitutes blood's 600-second capture length for touch's 15. `app.run_gate_on_hardware` reads each tier from its own file, and `blood_gate.calibration_hash()` hashes both into the `cal_hash` the attestation carries, so a co-signer sees the numbers behind whichever tier signed.

`Thresholds.load()` reads it, falling back to the shipped defaults if it is absent. **The device build calls `Thresholds.load()`, not `Thresholds()`**. That is what puts the numbers you measured into force. `Thresholds.provenance()` returns one line for the About screen naming the threshold set in use and the confidence bound behind it.

**State the bound your sample size supports.** By the rule of three, zero spoof acceptances in *n* trials bounds the false-accept rate at 3/*n* with 95% confidence: n=100 gives FAR ≤ 3%, n=300 gives ≤ 1%. A 0.1% claim needs ~3,000 trials. `calibrate.py` computes the bound and prints it with your results, so the number you publish is the number you measured.

### Ongoing

Monthly, run one dye cartridge. It must fail. If a red-dye sample ever passes, the optics are fouled or something has drifted, stop using the device until you know which.

---

## 14. Safety

**Not boilerplate.**

1. **One device, one person. Never share.** Hepatitis B survives on dry surfaces up to 7 days and is far more infectious by blood exposure than HIV. A shared blood-contact device is a transmission vector.
2. **Commercial sterile single-use lancets only.** Never reuse, never resharpen, never substitute a blade or needle. A used lancet tip is dull and contaminated.
3. **One cartridge, one use, then a sharps container.** Not household trash.
4. **Alcohol before, pressure and a plaster after.** Rotate fingers; use the sides of the pad, not the centre.
5. **Rate limit.** Roughly two blood authorisations per day, sustained. The blood tier is intended for cold storage and infrequent high-value operations. Routine signing should use the touch tier.

**Don't use this device if** you take anticoagulants (warfarin, DOACs, clopidogrel, daily aspirin), have a bleeding or clotting disorder, are immunocompromised, or have poor peripheral circulation. Note the irony on anticoagulants: your blood won't clot, so the coagulation gate rejects you every time. **The device physically will not work for you**. A real exclusion, not a hypothetical, and it rules out a meaningful share of adults over 60.

**Stop and see a doctor** for spreading redness, warmth, swelling, pus, red streaking up the finger, fever, or bleeding that won't stop in 10 minutes.

For calibration, don't run 100 samples on one person in one day. Use one larger draw for the negative classes and spread genuine trials over weeks.

---

## 15. Build order

A sequence of checks, not a schedule, with the parts in front of you this is a weekend. Each milestone is independently testable and each will find something you didn't expect.

| # | Milestone | Gate to proceed |
|---|---|---|
| 1 | Pi boots, radios dead | `iw dev` and `hciconfig` both empty, trace cut |
| 2 | AS7341 reading a white card on a breadboard | <1% RSD over 100 reads |
| — | *— end of what the reader kit needs —* | |
| 3 | Print 20 cartridges, measure white patches | <3% spread after normalisation. **Fix your printer here if not** |
| 4 | Optical chamber light-tight | Clear channel <0.5% of LEDs-on at 10,000 lux |
| 5 | **Spectrum of dye vs. your blood** | 415 nm separates them cleanly. This is the "it works" moment |
| 6 | 600 s time series, both classes | Blood starts decorrelated and arrests; dye never had speckle. Judge on what G5/G6 measure, early D, late D, the drop and its direction, not on a curve fit |
| 7 | **Spoof panel**, the reader is done | ROC generated, thresholds set, documented. **This is the result the whole design rests on** |
| 8 | ATECC608B configured, zones locked, PIN counter live | `atecc_config.py verify --behaviour` passes every line BEFORE `lock-data`; `se_atecc.py --probe` answers; eleven wrong PINs wipe a device you can afford to wipe |
| 9 | Firmware installed, `run_tests.py` green on the Pi | 43 suites pass on the device itself, not just your laptop |
| 10 | Provisioned, and the backup written down | `provision.py` re-reads its own seed; you have the words on paper |
| 10a | Chamber enrolled (optional) | `provision.py enroll-chamber`. The seed re-wraps and still reopens. Back up `chamber.npz` beside the words |
| 11 | Regtest round trip | `tools/regtest_e2e.py`. Core accepts and mines what the device signed |
| 12 | Testnet round trip, gate in the loop | Coins move, and only after a real sample |
| 13 | Seal the REFERENCE and NULL cartridges, record baselines | Both behave per §2 |
| 14 | Restore drill | Wipe the device, restore the seed from your paper backup, spend again |


Milestone 14 is not optional. A backup you've never restored from is not a backup.

---

## 16. Threat model and design limits

Stated so co-signers and reviewers can reason about them directly.

**Liveness is not identity.** The gate proves a living human is present; the PIN proves which one. Both are required at both tiers, and the ATECC608B's monotonic attempt counter backs the PIN. It increments before verify, so power-cycling mid-attempt does not reset it, and ten failures wipe.

**The gate proves fresh mammalian blood.** Mammalian haemoglobin is spectrally near-identical to human and clots on the same schedule. Butcher blood fails. It is anticoagulated or already clotted, but the device is not a species assay, and it does not need to be: the PIN is what makes the key yours. Species discrimination means DNA sequencing, which is a different instrument.

**Citrate is reversible, and G6 does not catch a recalcified sample.** Citrate anticoagulates by chelating calcium; adding calcium back restores clotting, which is exactly how a recalcified PT/aPTT assay works. A citrated sample recalcified immediately before loading starts liquid and arrests, so it passes the motion gates as well as the chemistry ones. EDTA chelates far more avidly and is not practically reversible outside a lab, so EDTA tube blood remains rejected, and it is EDTA that a stolen tube of clinical blood is most likely to contain. What G6 defeats is the opportunistic replay of a stored sample. It does not defeat a prepared attacker who holds the owner's blood, the device and the PIN together; nothing optical at this price does, and the quorum in §4 is the answer to that threat rather than a better gate.

**Physical possession of both device and PIN is the boundary.** As with every hardware wallet, hold what you would not be attacked for, and use the multisig quorum in §4 when the amount justifies it. `verify_quorum()` makes "everyone signed with blood" a mechanical check.

**No secure boot, and what stands in for it.** An attacker who opens the case can replace the firmware, return the device, and let the owner type the PIN into it. The ATECC608B bounds a blind guesser. Its counter never decreases and stops permanently at 2,097,151, against a 10⁸ keyspace, but a counter cannot help when the owner supplies the PIN willingly. What answers this is the chamber diffuser in §9: its speckle is an input to the seed-wrapping KDF, not a check, so opening the case does not fail a comparison, it derives a different key. Firmware can skip a boolean; it cannot skip a term in a derivation. For that to bind, the microSD must sit inside the sealed volume, otherwise the card comes out without the optics being disturbed. Enrolment is optional and a device without it behaves exactly as before. Move to a CM4 if you want a verified boot chain rather than a tamper-responsive one; the Pi Zero 2 W has no secure boot.

**Attestation trusts the firmware and the tamper seal.** Same assumption as a TPM quote or a Secure Enclave receipt. Co-signers register firmware and calibration hashes alongside attestation keys, and `verify()` refuses builds and threshold sets it does not recognise. The Pi Zero 2 W has no secure boot; move to a CM4 if your threat model needs one.

**The seed touches RAM during signing.** Milliseconds, in `mlock()`ed pages, zeroised after. This is the tradeoff for a $6 gate chip and a conventional paper backup path, and it is what makes restore-to-a-Trezor possible.

**The coagulation gate varies with the person.** Clotting time moves with hydration, temperature and medication. Expect more false rejects when cold or dehydrated. Warm your hands. Anticoagulant users cannot use the blood tier at all; see `SAFETY.md`.

**Cartridge supply is a dependency.** Keep 200 cartridges and 200 lancets with the device, plus the two sealed test cartridges.

**Review status.** The cryptography is standard construction verified against published test vectors. The sensing is calibrated per device in §13. Independent review of both is welcome and tracked in `CONTRIBUTING.md`. Testnet, then a small amount, then scale.
