"""CELL blood liveness engine — reference implementation.

Two sensors, two questions.

    Is it blood?    AS7341 spectrometer + 3 LEDs.   Gates 1-4, evaluated at t=5s.
    Is it alive?    Laser + camera, speckle.        Gates 5-6, evaluated over 600s.

The liveness half measures MOTION, not reflectance. During clotting the
light-scattering particles enlarge and their motion becomes restricted; under
coherent illumination the speckle pattern goes from boiling to frozen. Speckle
decorrelation sees that directly. Broadband diffuse reflectance barely does,
which is why every established low-cost optical coagulometer uses coherent
light and a camera rather than a photodiode.

The liveness test is SHAPE-AGNOSTIC. Published coagulation indices disagree
about whether clotting is exponential, sigmoid or something else; the test does
not need to know. It asks three things: did the sample start moving freely, did
it stop, and was the transition real and in the right direction.

    Fresh blood is the only sample that starts decorrelated and becomes
    correlated. Anticoagulated blood never stops moving. Already-clotted
    blood, syrup and gels never started. Dye has no speckle at all.

Design rule: explicit named thresholds, no learned model. A reviewer who is
not the author must be able to read this file and see why a sample passed.

Dependencies: numpy, scipy.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict, fields, replace
from pathlib import Path
from typing import Optional

import numpy as np
from scipy.ndimage import uniform_filter
from scipy.stats import spearmanr

# AS7341 photodiode centre wavelengths, nm. Index order is fixed everywhere.
CHANNELS_NM = (415, 445, 480, 515, 555, 590, 630, 680)
IDX = {nm: i for i, nm in enumerate(CHANNELS_NM)}

# Whole blood is ~4600 absorbance units per cm at the 415 nm Soret band. In an
# optically semi-infinite well the 415 channel therefore sits at the ADC floor,
# and an absorbance computed from a floor reading is numerically meaningless.
# Two consequences, both handled below:
#   - absorbance is CLAMPED, so the vector stays finite and comparable;
#   - the Soret test is a bounded ratio that never divides by a floor value.
A_MAX = 2.5

# ABSORBANCE of fresh oxygenated whole blood over the eight AS7341 channels,
# clamped and normalised to unit length. Note the units: absorbance, not
# reflectance. Getting that backwards makes every genuine sample fail.
#
# CALIBRATE THIS. Physically-reasoned starting point, not a measurement from
# your hardware. Replace via `calibrate.py enroll-reference`.
REFERENCE_OXYHB = np.array(
    [2.500, 1.930, 1.320, 1.395, 1.650, 1.520, 0.375, 0.273], dtype=float
)

# Channels pinned at the clamp carry NO shape information — by construction
# they hold the same value for every sample dark enough to reach the clamp, so
# including them drags every cosine toward 1 and destroys the gate's dynamic
# range. Measured on the shipped reference: with 415 nm included, deoxygenated
# blood (a visibly different colour) scores 0.991 against a 0.985 threshold and
# is ACCEPTED. Excluding it, genuine sits at 0.99999 and deoxyHb at 0.98821 —
# a margin ten times larger relative to sensor noise.
SHAPE_CHANNELS = REFERENCE_OXYHB < A_MAX - 1e-9

REFERENCE_OXYHB /= np.linalg.norm(REFERENCE_OXYHB)
_REF_SHAPE = REFERENCE_OXYHB[SHAPE_CHANNELS]
_REF_SHAPE = _REF_SHAPE / np.linalg.norm(_REF_SHAPE)


@dataclass(frozen=True)
class Thresholds:
    """Every number the engine can reject on. Nothing is hardcoded elsewhere."""

    # --- chemistry, AS7341 -------------------------------------------------
    # G1 is a WINDOW, not a floor. Whole blood in an optically semi-infinite
    # well is very dark: it returns a small but non-zero fraction of the white
    # patch. Both ends reject:
    #   below return_min  nothing scattering — an empty dark well, or a clear
    #                     liquid that returns nothing from a deep well
    #   above return_max  far too bright to be whole blood — an empty WHITE
    #                     well (~0.97) or a red painted swatch (~0.58), which
    #                     is exactly what the NULL pre-flight cartridge is
    # A floor alone cannot reject a bright sample, and the NULL cartridge is
    # bright. CALIBRATE BOTH ENDS — see calibrate.py.
    return_min: float = 0.015
    return_max: float = 0.350
    # G2 intact cells in suspension, not a dye solution.
    # Both channels are normalised against the cartridge's own white patch
    # BEFORE the ratio is taken. Without that this gate compares the white LED
    # against the 940 nm LED and mostly measures their relative drive current,
    # so it would drift with LED aging — the exact effect the printed white
    # patch exists to cancel.
    nir_scatter_min: float = 2.2
    # G3 haem present. Bounded index (R630-R415)/(R630+R415), never a floor divide
    soret_index_min: float = 0.75
    # G4 spectral shape vs oxyHb reference, over the unclamped channels only.
    # Tighter than it looks: restricted to informative channels, genuine blood
    # scores ~0.99999 and the nearest chemical relatives ~0.988. CALIBRATE.
    sam_cos_min: float = 0.995

    # --- liveness, laser speckle -------------------------------------------
    # Sanity: are we looking at speckle at all? Fully developed speckle has
    # LOCAL contrast near 1; a blank or incoherently lit frame has almost none.
    speckle_contrast_min: float = 0.10
    # Spatial high-pass window, px. Real lensless speckle rides on a strongly
    # non-uniform beam envelope that is IDENTICAL frame to frame. Correlating
    # raw frames therefore measures the envelope, not the speckle, and can hold
    # r above 0.5 while the speckle is fully boiling — which fails G5 on
    # genuine blood. Removing anything smoother than a few grains fixes it.
    # Speckle grain is ~4 px by design (BUILD.md, optical head), so a window of
    # ~2x the grain passes the speckle and rejects the envelope.
    envelope_px: int = 8
    # Local window for the contrast estimate, px. Contrast must be measured
    # locally for the same reason: a global std/mean is inflated by the
    # envelope and would report speckle where there is none.
    contrast_px: int = 7
    # G5 free Brownian motion at the start — a live liquid cell suspension
    d_liquid_min: float = 0.60
    # G6 motion arrested at the end — a clot formed
    d_clot_max: float = 0.25
    d_drop_min: float = 0.35
    monotone_rho_max: float = -0.70

    # --- acquisition -------------------------------------------------------
    # Native whole blood on a non-activating plastic surface clots far slower
    # than on glass. This device is used twice a year; ten minutes is free.
    duration_s: float = 600.0
    chemistry_at_s: float = 5.0
    speckle_period_s: float = 20.0
    early_window_s: float = 60.0
    late_window_s: float = 120.0

    # ---------------------------------------------------------------------
    @classmethod
    def load(cls, path: "str | Path | None" = None) -> "Thresholds":
        """Load calibrated thresholds, falling back to the shipped defaults.

        `calibrate.py roc` writes thresholds.json; this reads it back. The
        device build should call Thresholds.load() rather than Thresholds(),
        so the calibration measured on your hardware is the one in force.

        Unknown keys are ignored, so the calibration report can carry
        provenance fields (measured_far, n_spoof, ...) in the same file.
        """
        p = Path(path) if path else Path(__file__).with_name("thresholds.json")
        if not p.exists():
            return cls()
        blob = json.loads(p.read_text())
        known = {f.name for f in fields(cls)}
        return replace(cls(), **{k: v for k, v in blob.items() if k in known})

    def provenance(self, path: "str | Path | None" = None) -> str:
        """One line for the device's About screen, naming which threshold set
        is in force and the confidence bound behind it."""
        p = Path(path) if path else Path(__file__).with_name("thresholds.json")
        if not p.exists():
            return "thresholds: shipped defaults — not yet calibrated to this device"
        b = json.loads(p.read_text())
        return (f"thresholds: calibrated, FRR {b.get('measured_frr', 0)*100:.1f}% "
                f"FAR<={b.get('far_upper_bound_pct', float('nan')):.2f}% "
                f"(n={b.get('n_spoof', 0)} spoof, {b.get('n_genuine', 0)} genuine)")


@dataclass
class GateResult:
    name: str
    passed: bool
    value: float
    threshold: float
    detail: str = ""

    def __str__(self) -> str:
        return (f"[{'PASS' if self.passed else 'FAIL'}] {self.name}: "
                f"{self.value:.4f} (limit {self.threshold:.4f}) {self.detail}")


@dataclass
class LivenessResult:
    accepted: bool
    gates: list[GateResult] = field(default_factory=list)
    noise_residual: bytes = b""     # feeds the CSPRNG pool ONLY — see BUILD.md
    attestation: dict = field(default_factory=dict)

    def first_failure(self) -> Optional[GateResult]:
        return next((g for g in self.gates if not g.passed), None)

    def user_message(self) -> str:
        """Shown on the device. Always names the specific failure — an opaque
        rejection trains the user to blindly retry, which is what an attacker
        wants."""
        if self.accepted:
            return "Sample accepted. Signing."
        g = self.first_failure()
        return f"Rejected at {g.name}.\n{g.detail or 'Out of range.'}"


# --------------------------------------------------------------------------
# Hardware abstraction
# --------------------------------------------------------------------------


class SensorHead(ABC):
    """Implemented by hardware.py on-device, and by a synthetic stub in calibrate.py."""

    @abstractmethod
    def read_channels(self) -> tuple[np.ndarray, float, float]:
        """(F1..F8 counts, clear, nir) with the white LEDs and IR LED on."""

    @abstractmethod
    def read_white_reference(self) -> tuple[np.ndarray, float, float]:
        """Same, aimed at the cartridge's own printed white patch."""

    @abstractmethod
    def read_dark(self) -> tuple[np.ndarray, float, float]:
        """Same position as the white reference, LEDs OFF.

        Dark current plus any ambient leaking in. Using an LEDs-off reading
        rather than a printed black trap removes a feature from every cartridge
        and costs nothing, provided the chamber passes the light-tightness test."""

    @abstractmethod
    def read_speckle_burst(self) -> np.ndarray:
        """A short burst of camera frames under laser illumination.

        Shape (N, H, W), float. A 128x128 ROI and 16 frames is plenty.

        The camera must have FIXED exposure, gain and white balance — any auto
        adjustment between frames destroys the correlation measurement. Exposure
        should be short (<=2 ms) so each frame samples the speckle field almost
        instantaneously rather than time-averaging it."""

    def read_temperatures(self) -> Optional[tuple[float, float]]:
        """(sample_c, ambient_c), or None if no thermal sensor is fitted.

        Not abstract, and not used by any gate. Logged for diagnostics only: an
        infrared thermometer cannot see the sample through the PET window
        anyway, because PET is opaque in the 8-14 um band."""
        return None


# --------------------------------------------------------------------------
# Photometry
# --------------------------------------------------------------------------


def absorbance(sample: np.ndarray, white: np.ndarray, dark: np.ndarray) -> np.ndarray:
    """Per-cartridge normalised absorbance, clamped at A_MAX.

    The white reference is printed on the cartridge itself, in the same layer,
    from the same filament, and is read seconds apart from the sample. This
    cancels LED aging, photodiode drift and print variation — first-order
    effects that would otherwise walk the thresholds out of spec within weeks
    without anyone noticing.

    The clamp matters: for genuine blood the 415 nm channel sits at the floor
    and would otherwise produce an unbounded absorbance. Reaching the clamp is
    the expected result, not an error.
    """
    num = np.clip(sample - dark, 1e-6, None)
    den = np.clip(white - dark, 1e-6, None)
    return np.clip(-np.log10(np.clip(num / den, 1e-9, 1.0)), 0.0, A_MAX)


# --------------------------------------------------------------------------
# Speckle
# --------------------------------------------------------------------------


def _highpass(frames: np.ndarray, win: int) -> np.ndarray:
    """Remove anything spatially smoother than `win` px from each frame.

    The beam envelope, vignetting and any fixed pattern on the sensor are
    static between frames. Left in, they dominate the frame-to-frame
    correlation and D reports the envelope rather than the speckle. Each frame
    is high-passed INDEPENDENTLY — subtracting a temporal mean instead would
    invert the gate, because a frozen field minus its own mean is pure noise
    and would decorrelate perfectly.
    """
    return frames - uniform_filter(frames, size=(1, win, win), mode="nearest")


def _local_contrast(frame: np.ndarray, win: int) -> float:
    """Mean local speckle contrast K = sigma/mu over `win` x `win` windows.

    Local, not global, for the same reason as the high-pass: a global std/mean
    is inflated by the illumination envelope and would report high contrast on
    a smoothly-lit blank frame, defeating the point of the check.
    """
    mu = uniform_filter(frame, size=win, mode="nearest")
    mu2 = uniform_filter(frame * frame, size=win, mode="nearest")
    var = np.clip(mu2 - mu * mu, 0.0, None)
    return float(np.mean(np.sqrt(var) / np.clip(np.abs(mu), 1e-9, None)))


def speckle_metrics(burst: np.ndarray,
                    th: "Thresholds | None" = None) -> tuple[float, float]:
    """Return (decorrelation D, mean local speckle contrast K) for one burst.

    D = 1 - mean Pearson correlation between consecutive HIGH-PASSED frames.
        Freely moving scatterers decorrelate the speckle field completely
        between frames, so D -> 1. When a fibrin network arrests that motion
        the pattern becomes static and D -> 0.

    K = mean local sigma/mu. Fully developed speckle has K near 1; a blank or
        incoherently lit frame has almost none. K is a validity check that we
        are looking at speckle at all, not a discriminator.

    Both are computed after the illumination envelope is removed. On real
    hardware that step is not cosmetic — see Thresholds.envelope_px.
    """
    th = th or Thresholds()
    b = np.asarray(burst, dtype=np.float64)
    K = float(np.mean([_local_contrast(fr, th.contrast_px) for fr in b]))
    f = _highpass(b, th.envelope_px).reshape(len(b), -1)
    f = f - f.mean(1, keepdims=True)
    f = f / np.clip(f.std(1, keepdims=True), 1e-9, None)
    r = float(np.mean((f[:-1] * f[1:]).mean(1))) if len(f) > 1 else 1.0
    return 1.0 - r, K

# --------------------------------------------------------------------------
# Gates — chemistry
# --------------------------------------------------------------------------


def gate1_return(clear: float, white_clear: float, dark_clear: float,
                 th: Thresholds) -> GateResult:
    """The well contains something as dark as whole blood.

    A WINDOW, not a floor. Whole blood in an optically semi-infinite well
    returns a small but non-zero fraction of the white patch. Both ends matter:

      too dark    an empty dark well, or a clear non-scattering liquid, which
                  returns almost nothing at any wavelength
      too bright  an empty WHITE well (~0.97 of the patch) or a red painted
                  swatch (~0.58) — a floor alone cannot reject either, and the
                  NULL pre-flight cartridge is exactly a bright red swatch

    Running this before any ratio also keeps the later gates off floor-level
    readings.
    """
    ret = (clear - dark_clear) / max(white_clear - dark_clear, 1e-6)
    if ret < th.return_min:
        return GateResult("G1 return signal", False, ret, th.return_min,
                          "Nothing scattering in the well — empty, or a clear liquid.")
    return GateResult("G1 return signal", ret <= th.return_max, ret, th.return_max,
                      "Far too bright to be whole blood — an empty well, or an "
                      "opaque swatch rather than a sample.")


def gate2_scatter(clear: float, nir: float, white_clear: float, white_nir: float,
                  th: Thresholds) -> GateResult:
    """Intact red cells scatter strongly in NIR, where haemoglobin barely
    absorbs. A dye solution does not scatter; haemolysed blood scatters far
    less. This separates a cellular suspension from a coloured liquid.

    BOTH channels are normalised against the cartridge's own white patch before
    the ratio is taken. That matters more than it looks: Clear is read under
    the white LED and NIR under the 940 nm LED, so a raw nir/clear ratio is set
    largely by the two drive currents and drifts as the LEDs age — the exact
    effect the printed white patch exists to cancel. Normalising each against
    the same patch, in the same layer of the same part, leaves a property of
    the SAMPLE.

    All four inputs are dark-corrected counts.
    """
    r_clear = clear / max(white_clear, 1e-6)
    r_nir = nir / max(white_nir, 1e-6)
    ratio = r_nir / max(r_clear, 1e-9)
    return GateResult("G2 cellular scatter", ratio >= th.nir_scatter_min, ratio,
                      th.nir_scatter_min,
                      "No cellular scattering — a solution, not whole blood.")

def gate3_soret(refl: np.ndarray, th: Thresholds) -> GateResult:
    """Haem present, as a bounded normalised-difference index.

    Porphyrins have an intense Soret absorption near 415 nm, roughly an order
    of magnitude stronger than anything else in the visible band. No common red
    substance — food dye, ketchup, beet juice, theatrical blood — has one.

    Expressed as (R630 - R415)/(R630 + R415), which stays in [-1, 1] and is
    stable when R415 is at the floor. Gate 1 has already established that the
    sample returns real signal, so the ratio is meaningful here.
    """
    r415, r630 = refl[IDX[415]], refl[IDX[630]]
    idx = (r630 - r415) / max(r630 + r415, 1e-9)
    return GateResult("G3 haem Soret band", idx >= th.soret_index_min, idx,
                      th.soret_index_min,
                      "No 415 nm absorption — this is not a porphyrin.")


def gate4_shape(a: np.ndarray, th: Thresholds) -> GateResult:
    """Spectral Angle Mapper against the oxyHb reference.

    SAM compares direction, not magnitude, so it is inherently immune to LED
    aging, fill-depth variation and integration-time changes.

    Computed over SHAPE_CHANNELS only — the channels not pinned at the
    absorbance clamp. A clamped channel holds an identical value for every
    sample that reaches it, so it contributes a constant to every vector and
    pulls all cosines toward 1. Including 415 nm here is what would let
    deoxygenated blood through; see SHAPE_CHANNELS above.

    This gate is the one that separates oxygenated capillary blood from its
    close chemical relatives — deoxyHb and metHb. Those are not kitchen fakes;
    they are what you get from a sample that is old, venous, or otherwise not
    the fresh fingertip draw the device is specified for.
    """
    w = a[SHAPE_CHANNELS]
    n = np.linalg.norm(w)
    cos = 0.0 if n == 0 else float(np.dot(w, _REF_SHAPE) / n)
    return GateResult("G4 spectral shape", cos >= th.sam_cos_min, cos, th.sam_cos_min,
                      "Spectrum does not match oxygenated whole blood.")


# --------------------------------------------------------------------------
# Gates — liveness
# --------------------------------------------------------------------------


def gate5_free_motion(t: np.ndarray, D: np.ndarray, K: np.ndarray,
                      th: Thresholds) -> GateResult:
    """The sample arrived as a live liquid suspension of moving particles.

    Rejects anything that was never liquid: already-clotted blood, corn syrup
    and cocoa gels (viscous enough that particles barely move), ketchup, and
    anything with no coherent scattering at all.
    """
    m = t <= th.early_window_s
    if not m.any():
        return GateResult("G5 free motion", False, 0.0, th.d_liquid_min,
                          "No speckle captured.")
    kbar = float(np.mean(K[m]))
    if kbar < th.speckle_contrast_min:
        return GateResult("G5 free motion", False, kbar, th.speckle_contrast_min,
                          "No speckle — laser off, or nothing coherently scattering.")
    d0 = float(np.mean(D[m]))
    return GateResult("G5 free motion", d0 >= th.d_liquid_min, d0, th.d_liquid_min,
                      "Particles were not moving freely — already set, or too viscous.")


def gate6_motion_arrested(t: np.ndarray, D: np.ndarray, th: Thresholds) -> GateResult:
    """The sample clotted while we watched. This is the anti-replay gate.

    It works because of a fact an attacker cannot engineer around:

        Blood you can store has been anticoagulated, and never clots.
        Blood that was not anticoagulated has already clotted, and cannot be
        poured into a well.

    No curve shape is assumed. Three conditions: the end state is arrested, the
    drop is large enough to be real, and the trend runs in the right direction.
    """
    if len(t) < 5:
        return GateResult("G6 motion arrested", False, 1.0, th.d_clot_max,
                          "Capture too short.")
    late = D[t >= t.max() - th.late_window_s]
    early = D[t <= th.early_window_s]
    if len(late) < 2 or len(early) < 1:
        return GateResult("G6 motion arrested", False, 1.0, th.d_clot_max,
                          "Capture too short.")
    d_late, d_early = float(np.mean(late)), float(np.mean(early))
    drop = d_early - d_late
    rho = float(spearmanr(t, D).statistic)

    ok = (d_late <= th.d_clot_max and drop >= th.d_drop_min
          and rho <= th.monotone_rho_max)
    return GateResult("G6 motion arrested", ok, d_late, th.d_clot_max,
                      f"drop={drop:.3f} rho={rho:.2f} — this never stopped moving "
                      f"(anticoagulated), or never started.")


# --------------------------------------------------------------------------
# Acquisition + orchestration
# --------------------------------------------------------------------------


def chemistry_gates(capture: dict, th: Thresholds) -> list[GateResult]:
    """Gates 1-4. Split out so acquire() can run them the moment the chemistry
    read lands, without waiting for the speckle series."""
    white_f8, white_clear, white_nir = capture["white"]
    dark_f8, dark_clear, dark_nir = capture["dark"]
    f8, clear, nir = capture["chem"]

    refl = np.clip(f8 - dark_f8, 1e-6, None) / np.clip(white_f8 - dark_f8, 1e-6, None)
    a = absorbance(f8, white_f8, dark_f8)
    return [
        gate1_return(clear, white_clear, dark_clear, th),
        gate2_scatter(clear - dark_clear, nir - dark_nir,
                      white_clear - dark_clear, white_nir - dark_nir, th),
        gate3_soret(refl, th),
        gate4_shape(a, th),
    ]


def acquire(head: SensorHead, th: Thresholds = Thresholds(),
            early_abort: bool = True) -> dict:
    """Run the capture.

    Chemistry is read at t = chemistry_at_s and the chemistry gates are
    evaluated THERE, not at the end. An obvious spoof — ketchup, dye, an empty
    well — is rejected in seconds instead of ten minutes. Without the abort the
    early read buys nothing: the sample still sits in the chamber for the full
    duration before anyone looks at the numbers.

    Pass early_abort=False when recording calibration data, where the full
    speckle series is wanted even for samples that fail on chemistry.
    """
    white = head.read_white_reference()
    dark = head.read_dark()

    t0 = time.monotonic()
    chem = None
    speckle = []       # (t, D, K)
    next_sp = 0.0
    aborted_at = None

    while (now := time.monotonic() - t0) < th.duration_s:
        if chem is None and now >= th.chemistry_at_s:
            chem = head.read_channels()
            if early_abort:
                partial = {"white": white, "dark": dark, "chem": chem}
                if not all(g.passed for g in chemistry_gates(partial, th)):
                    aborted_at = now
                    break
        if now >= next_sp:
            D, K = speckle_metrics(head.read_speckle_burst(), th)
            speckle.append((now, D, K))
            next_sp = now + th.speckle_period_s
        time.sleep(0.05)

    if chem is None:
        chem = head.read_channels()
    return {"white": white, "dark": dark, "chem": chem, "speckle": speckle,
            "aborted_at_s": aborted_at}


def evaluate(capture: dict, th: Thresholds = Thresholds()) -> LivenessResult:
    """Run every gate over a capture. Pure function — no hardware, no clock.
    This is what calibrate.py replays against recorded spoof-panel data."""
    gates = chemistry_gates(capture, th)

    sp = capture["speckle"]
    t = np.array([r[0] for r in sp])
    D = np.array([r[1] for r in sp])
    K = np.array([r[2] for r in sp])
    gates.append(gate5_free_motion(t, D, K, th))
    gates.append(gate6_motion_arrested(t, D, th))

    accepted = all(g.passed for g in gates)

    # Entropy contribution: the high-frequency residual of the decorrelation
    # series — the genuinely unpredictable part, with the trend removed. It
    # goes into the CSPRNG pool and from there into BIP-340 aux_rand ONLY. It
    # NEVER determines a nonce; deriving an ECDSA nonce from a biometric is how
    # you publish your private key.
    resid = np.diff(D, n=2) if len(D) > 3 else np.array([0.0])
    noise = (resid * 1e9).astype(np.int64).tobytes()

    return LivenessResult(
        accepted=accepted,
        gates=gates,
        noise_residual=noise,
        attestation={
            "gate_scores": {g.name: round(g.value, 6) for g in gates},
            "accepted": accepted,
            "n_speckle": len(sp),
            "aborted_at_s": capture.get("aborted_at_s"),
            "thresholds": asdict(th),
        },
    )


# Every tunable threshold, with the raw metric it is compared against and the
# direction of the comparison. calibrate.py drives its whole sweep off this, so
# adding a threshold here is all that is needed to bring it under calibration —
# there is no second list to keep in step.
#   "min" -> genuine must be >= the threshold
#   "max" -> genuine must be <= the threshold
TUNABLE = {
    "return_min":           ("g1_return",     "min"),
    "return_max":           ("g1_return",     "max"),
    "nir_scatter_min":      ("g2_scatter",    "min"),
    "soret_index_min":      ("g3_soret",      "min"),
    "sam_cos_min":          ("g4_sam",        "min"),
    "speckle_contrast_min": ("g5_contrast",   "min"),
    "d_liquid_min":         ("g5_d_early",    "min"),
    "d_clot_max":           ("g6_d_late",     "max"),
    "d_drop_min":           ("g6_drop",       "min"),
    "monotone_rho_max":     ("g6_rho",        "max"),
}


def metrics(capture: dict, th: Thresholds = Thresholds()) -> dict:
    """Every raw number the gates compare, with no thresholds applied.

    Separating measurement from judgement is what makes calibration possible:
    the sweep needs the distribution of each metric across the panel, not a
    pass/fail that has already collapsed it. Any threshold in TUNABLE can then
    be set from real data instead of from first principles.
    """
    white_f8, white_clear, white_nir = capture["white"]
    dark_f8, dark_clear, dark_nir = capture["dark"]
    f8, clear, nir = capture["chem"]

    refl = np.clip(f8 - dark_f8, 1e-6, None) / np.clip(white_f8 - dark_f8, 1e-6, None)
    a = absorbance(f8, white_f8, dark_f8)
    w = a[SHAPE_CHANNELS]
    nw = np.linalg.norm(w)

    r_clear = (clear - dark_clear) / max(white_clear - dark_clear, 1e-6)
    r_nir = (nir - dark_nir) / max(white_nir - dark_nir, 1e-6)

    sp = capture["speckle"]
    t = np.array([r[0] for r in sp])
    D = np.array([r[1] for r in sp])
    K = np.array([r[2] for r in sp])

    m = {
        "g1_return":  float(r_clear),
        "g2_scatter": float(r_nir / max(r_clear, 1e-9)),
        "g3_soret":   float((refl[IDX[630]] - refl[IDX[415]])
                            / max(refl[IDX[630]] + refl[IDX[415]], 1e-9)),
        "g4_sam":     0.0 if nw == 0 else float(np.dot(w, _REF_SHAPE) / nw),
    }
    if len(t) == 0:
        m.update(g5_contrast=0.0, g5_d_early=0.0,
                 g6_d_late=1.0, g6_drop=0.0, g6_rho=1.0)
        return m

    early = t <= th.early_window_s
    late = t >= t.max() - th.late_window_s
    d_early = float(np.mean(D[early])) if early.any() else 0.0
    d_late = float(np.mean(D[late])) if late.any() else 1.0
    m.update(
        g5_contrast=float(np.mean(K[early])) if early.any() else 0.0,
        g5_d_early=d_early,
        g6_d_late=d_late,
        g6_drop=d_early - d_late,
        g6_rho=float(spearmanr(t, D).statistic) if len(t) >= 3 else 1.0,
    )
    return m


def authorize(head: SensorHead, th: Thresholds = Thresholds()) -> LivenessResult:
    """Top-level entry point. Called immediately before the signing key is
    unwrapped — never before the transaction has been rendered and physically
    confirmed."""
    return evaluate(acquire(head, th), th)


if __name__ == "__main__":
    print(__doc__)
    print("Chemistry (AS7341):  G1 return · G2 scatter · G3 Soret · G4 shape")
    print("Liveness  (speckle): G5 free motion · G6 motion arrested")
    print("\nShipped thresholds are physics-derived defaults.")
    print("Calibrate to your hardware: calibrate.py, and BUILD.md section 13.")
