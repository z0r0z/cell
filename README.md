# CELL

A hardware wallet that requires a live pulse, or a drop of fresh blood, to authorise a transaction.

Airgapped signer for Bitcoin and Ethereum. Raspberry Pi, 3D-printed enclosure, $97.55 of hardware. Public domain.

<img src="diagrams/turntable.gif" alt="CELL enclosure, 116 x 73 x 28 mm" width="100%">

<sup>The ring is the sensor port. A fingertip on it, or a cartridge under it. It is a bezel, not a control; nothing rotates.</sup>

**Spin it yourself.** The enclosure is a parametric three.js model, not a static render:

```bash
python3 -m http.server -d viewer 8000     # then open localhost:8000/instrument.html
```

Orbit it, and export OBJ or glTF straight from the viewer. `diagrams/turntable.mp4` is the same render as h.264, which holds more detail on a dark subject than the GIF does. The turntable above is rendered from that same model by `tools/render_turntable.py`, so it cannot show something the geometry does not. `models/README.md` documents the pipeline and the coordinate convention.

## Status

The design is complete and the firmware self-tests on every commit: 45 suites covering the signing stack against published test vectors, both liveness gates, the whole device loop, and the documented build sequence driven end to end. Bitcoin Core accepts and mines what it signs.

Nothing has been built on a bench yet. The sensor head, the panel, the buttons and the gate chip are written but unverified against hardware, `VALIDATION.md` lists each one and what closes it. Start with the reader kit: $62 of hardware plus $31 of consumables, and a weekend proves the sensing before you spend anything on the wallet half. **There's a [bounty](https://poidh.xyz/mainnet/bounty/24) for building one and signing with it. `BOUNTY.md` says what a claim looks like, and a reader-only run counts.**

Sensing thresholds ship as physics-derived defaults and are calibrated to your hardware on first build. `calibrate.py` runs the spoof panel for both tiers, sets every threshold from your own samples, and writes a file the device loads. Touch sessions are 15 seconds each, so that half of the calibration is minutes of work. `BUILD.md` §13 is the procedure. `VALIDATION.md` tracks exactly what has been measured.

Read `SAFETY.md` before the first build.

## What it does

<img src="diagrams/how-it-works.svg" alt="How the two liveness tiers gate the signing key" width="100%">

Transactions arrive as a QR code read by the camera and leave as a QR code on the display. There is no wifi, no bluetooth and no USB data path.

Authorisation requires a PIN plus one of two liveness proofs.

| | Touch | Blood |
|---|---|---|
| Action | Fingertip on the ring | A drop in a disposable cartridge |
| Duration | 15 seconds | 10 minutes |
| Consumable | None | Cartridge and lancet |
| Proves | A living body is present | A living body bled, just now |

Touch is the everyday default. Blood is a mode the user enters deliberately.

## Why a physical act

A button press costs nothing, so malware, an automated script and a deliberate human decision all produce an identical signal. A physical act that is rate-limited by the body separates them: one drop of blood is one signature, and no amount of capital compresses that.

Sealing an agreement in blood recurs across cultures that had no contact with each other, for the same reason each time. A mark anyone can make proves nothing; a mark that costs something proves intent.

## The blood gate

Six gates, all of which must pass. Implementation in `firmware/blood_gate.py`, with every threshold in a single dataclass.

### Chemistry: is it blood

Haemoglobin absorbs strongly at 415 nm, the Soret band produced by the iron-bearing porphyrin ring at the centre of the molecule. The absorption is roughly an order of magnitude stronger than anything else in the visible spectrum, and no common red substance produces it. Ketchup, food dye, beet juice and theatrical blood all fail this test immediately.

Three further gates confirm that the sample returns light at all, that it scatters in the near infrared the way a suspension of cells does rather than a dye solution, and that the full eight-channel spectrum matches oxygenated whole blood.

### Motion: is it alive

A stored sample fails on an asymmetry in how blood can be kept. Blood that can be stored has been anticoagulated and does not clot in the chamber. Blood that was not anticoagulated has already clotted and cannot be poured into a well. `BUILD.md` §16 gives the one exception to that asymmetry, and how far it reaches.

The device tests for this by measuring motion instead of colour. Under laser illumination, a liquid suspension of red cells produces a speckle pattern that changes continuously as the cells move. As fibrin forms it locks the cells in place and the pattern becomes static. A camera samples the pattern for ten minutes and measures the frame-to-frame correlation.

Fresh blood is the only sample that starts decorrelated and becomes correlated. Anticoagulated blood never arrests. Clotted blood, corn syrup and gels never moved in the first place. Dye produces no speckle at all.

The test assumes no particular curve shape. It asks three things: whether the sample started moving freely, whether it stopped, and whether the transition was large enough and in the right direction.

## The touch tier

Photoplethysmography through the same ring bore the cartridge sits under. Arterial blood volume in the fingertip changes with each heartbeat, so the light returning from it carries a small pulsatile signal on a large steady one. The white LED provides a red channel and the 940 nm LED provides infrared, both sampled at 50 Hz by the existing spectrometer. No additional hardware is required.

Seven gates check that the capture rate was high enough to analyse at all, that a finger is in contact, that the signal is pulsatile at a physiological depth, that the rate falls between 40 and 180 bpm, that the cardiac band dominates, that beat-to-beat variability is present, and that the red-to-infrared ratio matches haemoglobin.

The last two carry most of the anti-spoof weight. A silicone finger with dye pumped through it can produce a convincing pulse, but dye does not share haemoglobin's absorption ratio across the two wavelengths. And respiratory sinus arrhythmia puts a resting adult's beat-to-beat variability in the tens of milliseconds, where a mechanical pulsator produces single digits.

Implementation in `firmware/touch_gate.py`.

## Tier policy

The user may always escalate to a higher tier than policy requires. The user may never proceed at a lower one.

Policy sets a floor, and changing that floor is itself blood-locked in both directions. Without this rule the attack is not defeating the blood gate but lowering the threshold and using a finger. Loosening must cost blood for that reason; tightening must cost blood so that an attacker cannot lock the owner out by raising the floor.

Escalation applies to a single operation and does not persist. Running permanently at blood tier is not a separate mode, only a policy with the amount threshold set to zero and every operation class locked.

Five operations are blood-locked at provisioning and cannot be unlocked: policy changes, key export, device wipe, reprovisioning, and changes to the recipient allowlist.

Implementation in `firmware/policy.py`.

## Attestation

A signature carries no information about what gated the key, so the tier is asserted separately. Each device holds an attestation key generated at provisioning, and signs a 238-byte record binding the tier to a specific sighash, a monotonic counter, a firmware hash, the calibration in force and the gate measurements the claim rests on.

Co-signers register each other's attestation keys once, alongside the firmware and calibration hashes they will accept. After that, verifying that every member of a quorum signed at blood tier is a mechanical check, and a missing attestation counts as a failure and never an abstention.

The record travels beside the PSBT in a BIP-174 proprietary field and is stripped before broadcast, so it does not appear on chain.

The record attests that a device holding this key ran the blood gate for this transaction, and commits to the measurements it got.

### Putting it on chain

Stripping it is the default because publishing it says "this address is a CELL device, and this spend was authorised with blood." For a treasury that is a leak.

For an allowlist it is the whole point, so the option is there.

A contract can check the record itself. `contracts/src/CellAttestation.sol` verifies the signature; `CellRegistry.sol` holds the three things the record cannot carry: whose key it is, the highest counter seen from that key, and which firmware and calibration you accept.

The signature is BIP-340 Schnorr, which the EVM has no precompile for. It is rearranged into one `ecrecover` call plus a `modexp` to lift the point, so verification costs about 41k gas and a full `redeem` about 81k.

The digest the device signs commits to the chain, the contract and the claimant, so a record cannot be replayed on a fork, against another deployment, or by someone else.

What that buys is a signature nobody can farm. A script can produce a million of them. A body produces about two a day, and each one costs a lancet and ten minutes. For allowlists, mints, quorum votes and anything else where one-human-one-action matters, that is a rate limit denominated in something an attacker cannot buy more of.

The limit is the one every hardware attestation has. As with a TPM quote or a Secure Enclave receipt, the claim rests on the firmware and the tamper seal: someone who opens the case and extracts the key can sign records without bleeding. So treat it as raising the cost of faking a human, not as proof of a unique one. Co-signers register firmware hashes alongside keys, and `verify()` refuses builds it does not recognise.

Implementation in `firmware/attest.py`.

## Proof of life

Every dead-man switch in self-custody keys off signing activity, which answers
the wrong question. "This key moved" is not "this person is alive": a stolen
key resets the clock, and an owner who simply does not spend for a year looks
dead. The touch gate measures a body, so CELL can separate them.

A beacon is the attestation with no transaction under it. Fifteen seconds, no
consumable, nothing signed with the seed. `CellRegistry.heartbeat` writes down
when a living human was last proven present, and anything that needs to know
can read it: an inheritance path, a recovery quorum, a multisig that wants a
co-signer's pulse before treating them as present.

Nothing new is signed. `actionDigest` already commits to the chain, the
contract and the claimant, and takes a purpose word. The beacon is that
function with a purpose carrying a period index, so it is the same record
format, the same key and the same curve.

**The date on the screen is the security control.** The device has no clock and
does not pretend to. The period comes from the companion and is displayed as a
date range, so the owner is the clock, and `heartbeat` accepts a beacon only
while its period is the current one. A record harvested for a future period
cannot be spent early and cannot be spent late. What remains is that a
companion which tricks the owner into approving N future periods can keep a
dead owner alive for N periods, at one gate and one wrong date each.

`CellDormancy.sol` is the switch that reads it, in two phases on purpose. A
claim releases nothing; it opens a challenge window, and one beacon during that
window cancels it. A device that spent six months in a drawer is the ordinary
case, not the attack, and fifteen seconds of a fingertip undoes it.

## What it protects against

The device defeats remote malware, automated signing, signing at scale, and signing without the owner's knowledge. A compromised host cannot produce a pulse or a clotting sample, and there is no batch mode. Every signature costs a physical act, and at blood tier the rate is set by your body and not by the attacker's budget.

The gate asks whether someone alive is here. The PIN asks who. It is eight digits, required at both tiers, and the secure element's attempt counter increments before it checks, so cutting power mid-guess costs an attempt instead of refunding one. Ten wrong and the device wipes.

Ten is a firmware rule. This chip has no retry counter in silicon, and firmware is what someone who opens the case replaces. What the chip does enforce is a counter that never decreases and stops permanently at 2,097,151, which is why the PIN is eight digits and not six: 10⁸ guesses is more than the part will ever answer. `firmware/se_atecc.py` states exactly which half of this is silicon and which is arithmetic.

### If the case comes open

Opening the case is how firmware gets replaced, so the chamber answers for itself. A ground-glass diffuser is epoxied into the optical chamber, and the laser and camera that watch blood clot read its speckle at every unlock. A pattern fixed by microstructure below a micron, which cannot be manufactured to a copy.

That reading is an input to the key that unwraps the seed, not a check the firmware performs. A case that has been opened does not fail a comparison; it derives a different key, and the seed stays shut. Firmware can skip a boolean. It cannot skip a term in a derivation.

Drift is told from tampering rather than both being read as attack: every read is registered against two published reference patches, so a mount that moves with temperature is measured and taken out, and the angle and offset are reported alongside the result. Enrolment is optional, and a device that skips it behaves exactly as it did before. `firmware/optical_puf.py`; `BUILD.md` §9 places the disc.

It costs one habit. The laser is interlocked to the cartridge switch in hardware, so a chamber-enrolled device needs the bay closed at every unlock, including a touch signature, which otherwise involves no cartridge at all. Leave a spent cartridge in the slot between spends. A device that never enrolled a chamber never reads it and never asks.

### Under coercion

Sensing cannot help here. No measurement tells willing blood from coerced blood. A second PIN can. Set one and the device carries two wrapped seeds and two wallets; the duress PIN unlocks, signs and behaves identically, and opens the other one. Both seeds are written whether or not you configure a duress PIN, so the card never says which kind of device this is.

It protects what you sign, not what your device shows: the receive and identity screens are watch-only and still display the primary wallet. `firmware/duress.py` is honest about that, and `VALIDATION.md` carries it as open. Fund the decoy plausibly. An empty one tells the coercer they were given the wrong PIN.

`BUILD.md` §16 carries the full threat model.

## The signing stack

The wallet half is implemented here rather than delegated, because the gate has to reach inside it: the tier decision, the confirmation screen and the attestation all depend on what the transaction actually says. It is pure Python with one dependency, `cryptography`, used only for AES-GCM.

| | |
|---|---|
| `secp256k1.py` | ECDSA with RFC 6979 nonces, low-S, low-R grinding, BIP-340 Schnorr, BIP-341 tweaks |
| `bip39.py` / `bip32.py` | Mnemonic and HD derivation, with the wordlist's SHA-256 checked on load |
| `psbt.py` / `tx.py` | BIP-174 and BIP-370 parsing, and all three sighash algorithms |
| `addresses.py` | bech32 and bech32m, every script type, EIP-55 |
| `eth.py` | RLP and EIP-1559, built on the device from fields it displays |
| `eip712.py` | EIP-712 typed data for smart accounts, and the EIP-7702 delegation |
| `beacon.py` | The beacon digest, and the period the owner reads |
| `seedstore.py` | The seed at rest |
| `qr.py` | The airgap: animated frames, and reassembly that refuses substitution |
| `display.py` / `buttons.py` / `camera.py` | The screen, the four buttons, and the only way data gets in |
| `app.py` | The loop: scan, show, confirm, PIN, gate, sign, emit |

Every one of them is checked against the vectors published in the BIPs, RFC 6979 and the EIPs, not against its own output. The signatures are also compared byte for byte with `embit` and `eth-account` across every script type and six chain ids, and then handed to independent code that has to be *satisfied* rather than merely agree: `python-bitcointx`'s script interpreter runs p2pkh, bare multisig, p2wpkh, p2sh-p2wpkh and p2wsh under the flags a node applies, and libsecp256k1. The implementation Bitcoin Core signs with, checks the taproot key and signature. None of those packages is a dependency; `firmware/test_consensus.py` skips without them.

Multisig has to be registered before it can be signed. Without the co-signers on file, "is this output mine?" can only be answered as "does it contain a key of mine?", and an attacker who controls the coordinator can build a script holding one key of yours and the rest theirs. It hashes correctly, the wallet calls it change, and the balance moves somewhere you cannot spend alone. With the quorum registered the device rebuilds the exact script your co-signers produce and compares it byte for byte. `tools/provision.py multisig` does the registering.

Ethereum can also be signed the way the deployment model actually describes. A transfer out of a registered smart account is an EIP-712 `Execute` message: the account holds the nonce, whoever relays it pays the gas, and the device signs three fields and a domain. `chainId` and `verifyingContract` live in the domain separator, so one signature is pinned to one chain and one deployment, which is more than an EOA signature pins. The account is registered in advance for the same reason a quorum is. Calldata stays refused, so the account's own governance calls are refused with it.

EIP-7702 delegation is supported and blood-locked in every configuration. It moves no value, and it decides what every later signature from that address means. Note what it costs: a delegated EOA keeps its key as a superuser, so a timelock on such an account bounds a relayer and not the key holder. `BUILD.md` §5 draws the line between that and a factory-deployed account.

And `tools/regtest_e2e.py` asks the only question that settles anything on its own: Bitcoin Core funds an address this firmware derived, the firmware signs a PSBT spending it, and Core finalises, accepts and mines the result, p2wpkh, p2sh-p2wpkh, p2pkh, p2tr and p2wsh 2-of-3, on a private regtest chain. It found a real defect the first time it ran: the attestation was written into the PSBT with a malformed proprietary key, and Core rejected the whole document rather than skipping the field.

`firmware/test_wallet.py` and `firmware/test_app.py` are the other half of the argument. They are a list of the ways hardware wallets have actually lost people's money, fee inflation through a lying witness UTXO, change substitution, a co-signer swapped out of a quorum, a key quoted at a path that does not derive it, sighash downgrades, calldata smuggled into a transfer, chain-id replay. Each written as a hostile input, each of which must be refused.

## Where the seed comes from

Most hardware wallets draw the seed from one or two sources you are asked to
take on faith. This one draws from three, and the third can be measured.

The kernel CSPRNG and the ATECC608B's hardware RNG are both sound and both
opaque: a ring oscillator behind Linux's pool, and Microchip's behind a
datasheet paragraph. The laser and the lensless camera already in the device
are neither. `provision.py` takes a third term from them and prints the
min-entropy it measured on the sample it actually drew, using the two NIST SP
800-90B estimators and taking the smaller.

The easy way to get this wrong is instructive. A speckle image is the optical
PUF, reproducible by construction, so a seed drawn from one frame would be the
same on every power cycle of that device forever while passing every
statistical test. The randomness is not in the pattern. It is in what changes
between frames, so the source is the difference between disjoint pairs of
them, where the static field cancels and photon shot noise does not.

Nice symmetry, and it is load-bearing: the PUF keeps the cells that are stable
and discards the rest, and this wants exactly what it discarded.

All three are XORed. A chamber that is dark, blocked, overexposed or simply
absent contributes zeros and says so, and zeros XOR into nothing, so the seed
is never weaker for having asked.

## Keys and backup

The device holds a standard BIP39 seed, encrypted at rest and unwrapped only after the gate passes. The unwrapping key comes from your PIN and the secure element's own secret, so the encrypted seed is inert on any other machine and recoverable on this one. Back it up on paper or steel as with any hardware wallet. If the device fails, restore to a Ledger, a Trezor or a replacement build.

Both Bitcoin and Ethereum use secp256k1, so one key and one signing core serve both chains.

The device signs a closed set of operations that it can render as readable text and refuses everything else, including arbitrary EVM calldata.

## Quick start

The gate logic runs without hardware.

```bash
pip install -r firmware/requirements.txt
python firmware/run_tests.py           # everything below, in one run
```

Or individually:

```bash
cd firmware
python calibrate.py selftest --n 8     # blood tier, 6 gates, 18 sample classes
python touch_gate.py                   # touch tier, 7 gates
python policy.py                       # tier rules
python attest.py                       # attestation, quorum, malformed input
python secp256k1.py                    # RFC 6979, ECDSA, BIP-340, BIP-341
python bip32.py                        # BIP-32 vectors, hardened isolation
python tx.py                           # BIP-143 and BIP-341 sighash vectors
python eth.py                          # RLP, EIP-1559, recovery
python test_wallet.py                  # end to end, then every footgun
python test_app.py                     # the whole loop, driven with fakes
```

Each spoof class fails at the physically correct gate, and the self-test fails
if any gate stops being exercised by at least one class.

The `edta` row is the interesting one: anticoagulated tube blood is chemically identical to fresh blood and passes every colour test, then fails at motion arrested because it does not clot in the chamber. That is the claim the design rests on, and it turns replay from a tube in a fridge into an attack that needs your blood, your device and your PIN together. `BUILD.md` §16 draws the exact line.

## Repository layout

| Path | Contents |
|---|---|
| `BUILD.md` | Hardware specification: parts, wiring, optics, cartridge, firmware, calibration |
| `PRINTING.md` | Print runbook: order, checks, post-processing |
| `BOM.csv` | Bill of materials, by kit, with sourcing notes |
| `firmware/blood_gate.py` | Blood tier, six gates |
| `firmware/touch_gate.py` | Touch tier, seven gates |
| `firmware/ops.py` | The closed operation set and its renderer |
| `firmware/wallet.py` | Provisioning, and the two signing entry points |
| `firmware/psbt.py` | BIP-174: what the device recomputes rather than trusts |
| `firmware/tx.py` | Transactions and all three sighash algorithms |
| `firmware/eth.py` | RLP and EIP-1559, built from displayed fields |
| `firmware/eip712.py` | The smart-account path: typed data, and what a delegation costs |
| `firmware/beacon.py` | Proof of life: the attestation with no transaction under it |
| `firmware/chamber_trng.py` | Seed entropy from the chamber, and the health tests it has to pass |
| `firmware/secp256k1.py` | The curve both chains sign on |
| `firmware/hashes.py` | RIPEMD-160 and Keccak-256, because the standard library will not |
| `firmware/bip32.py` / `bip39.py` | HD derivation and the mnemonic |
| `firmware/addresses.py` | bech32/bech32m, script types, EIP-55 |
| `firmware/seedstore.py` | The seed at rest |
| `firmware/qr.py` | The airgap: framing and reassembly |
| `firmware/display.py` | The ST7789 panel, and the layout limits it must not undo |
| `firmware/buttons.py` | Four buttons, and the one that means consent |
| `firmware/camera.py` | QR capture, and the only way data gets in |
| `firmware/app.py` | The loop, as a person uses it |
| `firmware/test_app.py` | The whole device, driven end to end with fakes |
| `firmware/se_atecc.py` | ATECC608B driver. CheckMac PIN, duress slots. Unverified until probed on hardware |
| `tools/atecc_config.py` | Builds, shows, writes, verifies and locks the chip's config zone |
| `firmware/duress.py` | The second PIN, and why its use has to be unfalsifiable |
| `firmware/test_wallet.py` | End to end, and every footgun we could name |
| `firmware/test_se_atecc.py` | The chip driver's arithmetic, against a fake chip |
| `firmware/test_curve.py` | The fast scalar multiplies against the definition they replaced |
| `firmware/test_drivers.py` | Do we call the hardware libraries correctly |
| `firmware/test_consensus.py` | An independent interpreter runs our scripts |
| `firmware/signer.py` | The unlock chain: policy, confirm, PIN, gate, sign, attest |
| `firmware/se.py` | Secure element interface and a software stub for tests |
| `firmware/policy.py` | Tier selection and escalation rules |
| `firmware/attest.py` | Tier attestation and quorum verification |
| `firmware/calibrate.py` | Spoof-panel harness for both tiers, and the synthetic self-test |
| `firmware/hardware.py` | Sensor drivers. Untested; includes a bring-up checklist |
| `firmware/run_tests.py` | Every self-test in one run. What CI runs |
| `tools/provision.py` | Choose a seed, wrap it, record the watch-only accounts |
| `tools/cell.service` | The systemd unit that starts the loop at boot |
| `tools/bench.py` | The checks only the built device can answer |
| `tools/regtest_e2e.py` | Sign with the firmware, make Bitcoin Core accept it |
| `tools/export_model.py` | Re-exports `instrument.obj` from `viewer/model.js` |
| `tools/render_turntable.py` | Renders the turntable GIF/MP4 from the same model |
| `tools/gen_wiring.py` | Draws the Phase 1 wiring sheet from BUILD.md §11 |
| `tools/gen_mechanical.py` | Regenerates `diagrams/mechanical.svg` from the mesh |
| `tools/gen_printables.py` | Generates every printable part, checks it, writes the manifest |
| `tools/gen_enclosure.py` | The inside of the two shells, and the fit checks |
| `contracts/` | On-chain verification of the attestation record, and the registry |
| `models/` | Enclosure mesh, coordinate convention, regeneration |
| `models/print/` | The ten printable STLs and their generated manifest |
| `diagrams/` | Explainer, build sheet, dimensioned drawings |
| `viewer/` | Parametric three.js model. The source `instrument.obj` is exported from |
| `VALIDATION.md` | Verification status: what is tested, by what method |
| `SAFETY.md` | Blood-contact handling. Read it first |
| `CONTRIBUTING.md` | What this project actually needs |

## Building one

<img src="diagrams/build-sheet.svg" alt="Build sheet: parts, optical head, cartridge" width="100%">

`BUILD.md` §2 splits the build into two kits, and every row of `BOM.csv` says which kit it belongs to. The reader kit is $62 of hardware plus $31 of consumables: a Pi, a spectrometer, a laser, a camera, a printed chamber, cartridges, and the lancets and film to run them. It has no security requirements because it signs nothing, and it answers the only question that determines whether the rest is worth building. The wallet kit adds the signing half for a further $35.30.

A touch signature costs nothing to make. A blood signature spends a lancet, an alcohol pad, a PET window and a printed cartridge, about twenty cents, restocked from any pharmacy. Nothing in the device is consumed by either, and nothing on the bill of materials has a shelf life.

Ten parts are printed, all from `python3 tools/gen_printables.py`, all checked before they are written. `PRINTING.md` is the runbook. What to print in what order, what to check off each stage, and the post-processing the device does not work without.

## Safety

Read `SAFETY.md` before the first build. In summary: use commercial sterile single-use lancets, dispose of each cartridge and lancet in a sharps container, and never share a device between people. Anyone taking anticoagulants cannot use the blood tier, because their blood will not clot and the gate will reject every sample.

## Licence

CC0 1.0. See `LICENSE`.
