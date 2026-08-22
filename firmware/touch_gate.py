"""CELL touch mode — photoplethysmography liveness.

The light tier. A fingertip on the ring instead of a drop in a cartridge.

    Blood mode   proves a living body BLED here, now.        ~10 min, one cartridge.
    Touch mode   proves a living body IS here, now.          ~15 s, no consumable.

Runs entirely on hardware the device already has: the white LED gives a red
channel, the 940 nm LED gives infrared, and the AS7341 samples both at 50 Hz
through the ring bore. No added parts.

What it measures: arterial blood volume in the fingertip changes with each
heartbeat, so the light coming back is a small pulsatile signal riding on a
large steady one. Six gates check that the pulsatile part looks like a heart
and that the absorber looks like haemoglobin.

The two-wavelength gate is the important one. A silicone finger with red dye
pumped through it can produce a convincing pulse, but dye does not have
haemoglobin's red-to-infrared absorption ratio. That is the same physics the
blood mode uses at 415 nm, applied to a living finger instead of a sample.

WHAT THIS TIER DOES NOT DO: one drop of blood is one signature, rate-limited by
your body. A pulse can be produced indefinitely. Touch mode is for operations
where "a live human is present" is enough — never for the ones where the cost
is the point. The tier boundary is user-configured policy; the device must
never choose it. See BUILD.md.

Dependencies: numpy, scipy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict

import numpy as np
from scipy.signal import butter, filtfilt, find_peaks

from blood_gate import GateResult


@dataclass(frozen=True)
class TouchThresholds:
    """Every number touch mode can reject on."""

    # TARGET sample rate. The hardware reports what it actually achieved and
    # that is what the maths uses — see fs_min. A Python loop over an I2C
    # spectrometer does not hit an arbitrary rate, and silently using the
    # nominal value scales bpm and RMSSD by the ratio of the two.
    fs: float = 50.0
    # Hard floor on the ACHIEVED rate. The passband reaches 4 Hz, so Nyquist
    # alone demands >8 Hz; peak timing for RMSSD wants several times that. Below
    # this the capture is not analysable and the device must say so rather than
    # report a confident wrong heart rate.
    fs_min: float = 20.0
    duration_s: float = 15.0    # ~15-25 beats, enough for a variability estimate

    # T1 a finger is pressed on the ring
    dc_min: float = 0.08        # fraction of the white reference
    dc_max: float = 0.85        # brighter than this means no finger, just the bore

    # T2 the signal is pulsatile, and pulsatile at a physiological depth.
    # Reflectance perfusion index at a fingertip runs 0.5-5%. Above ~10% the
    # geometry is changing, not the blood volume — that is a motion artefact,
    # and the ceiling catches it directly.
    perfusion_min: float = 0.003
    perfusion_max: float = 0.100

    # T3 the rate is physiological
    bpm_min: float = 40.0
    bpm_max: float = 180.0

    # T4 the cardiac band dominates — rejects motion artefact and broadband noise
    band_snr_min: float = 0.45

    # T5 a real heart is not a metronome. A mechanical pulsator has near-zero
    # beat-to-beat variability; chaos means the beat detection is unreliable.
    rmssd_min_ms: float = 5.0
    rmssd_max_ms: float = 250.0

    # T6 the absorber is haemoglobin, not dye. R is the ratio-of-ratios; the
    # window corresponds to living perfused tissue. CALIBRATE PER DEVICE —
    # reflectance geometry shifts R and the absolute value is not a clinical
    # measurement, it is only used to reject non-haemoglobin absorbers.
    # R near 1.0 is the signature of a common-mode disturbance: a geometry
    # change hits both wavelengths equally, whereas real perfusion does not.
    # Well-perfused tissue sits near 0.5-0.7.
    r_ratio_min: float = 0.40
    r_ratio_max: float = 0.90

    @classmethod
    def load(cls, path=None) -> "TouchThresholds":
        """Load calibrated touch thresholds, falling back to shipped defaults.

        Mirrors blood_gate.Thresholds.load. The device build should call this
        rather than TouchThresholds(), so a calibration run actually reaches
        the device instead of sitting in a JSON file nobody reads.
        """
        from pathlib import Path
        import json
        from dataclasses import fields, replace
        p = Path(path) if path else Path(__file__).with_name("touch_thresholds.json")
        if not p.exists():
            return cls()
        blob = json.loads(p.read_text())
        known = {f.name for f in fields(cls)}
        return replace(cls(), **{k: v for k, v in blob.items() if k in known})


@dataclass
class TouchResult:
    accepted: bool
    gates: list[GateResult] = field(default_factory=list)
    attestation: dict = field(default_factory=dict)

    def first_failure(self):
        return next((g for g in self.gates if not g.passed), None)

    def user_message(self) -> str:
        if self.accepted:
            return "Pulse confirmed. Signing."
        g = self.first_failure()
        return f"Rejected at {g.name}.\n{g.detail or 'Out of range.'}"


class TouchSensor(ABC):
    """Implemented by hardware.py on-device."""

    @abstractmethod
    def read_ppg(self, duration_s: float,
                 fs: float) -> tuple[np.ndarray, np.ndarray, float]:
        """Return (red, ir, fs_achieved) taken through the ring bore.

        `fs` is a TARGET. The third return value is the rate actually achieved,
        measured over the capture, and it is what the analysis uses. Returning
        the nominal rate when the loop ran slower makes every downstream
        frequency wrong by that ratio and turns a healthy 68 bpm into a T3
        rejection.

        Red comes from the white LED's long-wavelength channels (F7 630 nm);
        infrared from the 940 nm LED read on the AS7341 NIR channel. Alternate
        the two LEDs within each sample period so both channels see the same
        beat. Fixed integration time and gain — an auto-adjusting DC level
        destroys the perfusion measurement."""

    @abstractmethod
    def read_bore_reference(self) -> tuple[float, float]:
        """(red, ir) with the LEDs on and nothing on the ring. Establishes the
        empty-bore level so T1 can tell a finger from an open port."""


# --------------------------------------------------------------------------
# Signal processing
# --------------------------------------------------------------------------


# Cardiac passband. Wider than T3's accept range on purpose — see ppg_features.
PASSBAND_LO = 0.35
PASSBAND_HI = 4.0

# Minimum spacing between detected beats, as a rate. This is an ANALYSIS
# parameter and deliberately NOT TouchThresholds.bpm_max, which is an accept
# window. Using the accept threshold here couples the two: calibrating bpm_max
# would change the peak spacing, which changes RMSSD, which is itself a
# calibrated threshold — so a sweep fits the RMSSD window under one peak
# detector and then judges it under another, and rejects every genuine session
# it just fitted. Measured: it puts FRR at 100%. The detector should resolve
# anything physiologically possible; T3 is what decides whether the rate is
# acceptable.
PEAK_MAX_BPM = 240.0


def _bandpass(x: np.ndarray, fs: float,
              lo: float = PASSBAND_LO, hi: float = PASSBAND_HI) -> np.ndarray:
    b, a = butter(3, [lo / (fs / 2), hi / (fs / 2)], btype="band")
    return filtfilt(b, a, x)


def ppg_features(red: np.ndarray, ir: np.ndarray, th: TouchThresholds,
                 fs: float | None = None) -> dict:
    """Extract every quantity the gates test. Pure function, no hardware.

    `fs` is the ACHIEVED sample rate, which is not necessarily th.fs — see
    TouchThresholds.fs. Every frequency-derived quantity (bpm, RMSSD) scales
    directly with it, so passing the nominal rate when the hardware ran slower
    reports a wrong heart rate with total confidence.
    """
    fs = th.fs if fs is None else fs
    dc_red, dc_ir = float(np.mean(red)), float(np.mean(ir))
    ac_red, ac_ir = _bandpass(red, fs), _bandpass(ir, fs)

    def pk2pk(x):
        return float(np.percentile(x, 97) - np.percentile(x, 3))

    perfusion = pk2pk(ac_red) / max(dc_red, 1e-9)

    # dominant cardiac frequency
    win = np.hanning(len(ac_red))
    spec = np.abs(np.fft.rfft(ac_red * win)) ** 2
    freq = np.fft.rfftfreq(len(ac_red), 1 / fs)
    # Search the full passband, which is deliberately wider than T3's accept
    # range (40-180 bpm = 0.67-3.0 Hz), so an out-of-range rate is DETECTED and
    # rejected by T3 rather than being missed and mistaken for a harmonic.
    band = (freq >= PASSBAND_LO) & (freq <= PASSBAND_HI)
    if not band.any() or spec[band].sum() <= 0:
        return {"dc_red": dc_red, "dc_ir": dc_ir, "perfusion": perfusion,
                "bpm": 0.0, "band_snr": 0.0, "rmssd_ms": 0.0, "r_ratio": 0.0}

    f0 = float(freq[band][np.argmax(spec[band])])
    near = (freq >= f0 - 0.15) & (freq <= f0 + 0.15)
    band_snr = float(spec[near].sum() / spec[band].sum())

    # beat-to-beat variability
    peaks, _ = find_peaks(ac_red, distance=max(1, int(fs / (PEAK_MAX_BPM / 60))))
    peaks = peaks[(peaks > 0) & (peaks < len(ac_red) - 1)]
    if len(peaks) >= 4:
        y0, y1, y2 = ac_red[peaks - 1], ac_red[peaks], ac_red[peaks + 1]
        den = y0 - 2 * y1 + y2
        refined = peaks + np.where(np.abs(den) > 1e-12,
                                   0.5 * (y0 - y2) / np.where(den == 0, 1, den), 0.0)
        rr = np.diff(refined) / fs * 1000.0
        rmssd = float(np.sqrt(np.mean(np.diff(rr) ** 2)))
    else:
        rmssd = 0.0

    # ratio-of-ratios: the haemoglobin test
    r_ratio = ((pk2pk(ac_red) / max(dc_red, 1e-9)) /
               max(pk2pk(ac_ir) / max(dc_ir, 1e-9), 1e-9))

    return {"dc_red": dc_red, "dc_ir": dc_ir, "perfusion": perfusion,
            "bpm": f0 * 60.0, "band_snr": band_snr, "rmssd_ms": rmssd,
            "r_ratio": r_ratio}


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------


def evaluate(red: np.ndarray, ir: np.ndarray, bore: tuple[float, float],
             th: TouchThresholds = TouchThresholds(),
             fs: float | None = None) -> TouchResult:
    fs = th.fs if fs is None else fs

    # T0 is a capture-validity check, not an anti-spoof gate, and it runs first
    # because every gate after it is computed in units of fs. A capture taken
    # too slowly cannot be analysed, and reporting a wrong bpm from it would be
    # worse than refusing: it fails T3 and sends the user hunting a heart
    # problem that is really an I2C timing problem.
    if fs < th.fs_min:
        return TouchResult(
            accepted=False,
            gates=[GateResult("T0 capture rate", False, fs, th.fs_min,
                              f"Sampled at {fs:.1f} Hz, need >={th.fs_min:.0f} Hz. "
                              f"This is a hardware timing fault, not a failed "
                              f"pulse — see hardware.py read_ppg.")],
            attestation={"accepted": False, "fs_achieved": fs},
        )

    f = ppg_features(red, ir, th, fs)
    bore_red = max(bore[0], 1e-9)
    dc_frac = f["dc_red"] / bore_red

    g = [
        GateResult("T0 capture rate", True, fs, th.fs_min, ""),
        GateResult("T1 contact", th.dc_min <= dc_frac <= th.dc_max, dc_frac,
                   th.dc_min, "No finger on the ring, or pressed hard enough to "
                              "occlude perfusion."),
        GateResult("T2 pulsatile",
                   th.perfusion_min <= f["perfusion"] <= th.perfusion_max,
                   f["perfusion"], th.perfusion_min,
                   "Pulsation absent (a static object) or far too deep to be "
                   "perfusion (the sensor or finger moved)."),
        GateResult("T3 rate physiological",
                   th.bpm_min <= f["bpm"] <= th.bpm_max, f["bpm"], th.bpm_min,
                   f"{f['bpm']:.0f} bpm is outside the human range."),
        GateResult("T4 cardiac band", f["band_snr"] >= th.band_snr_min,
                   f["band_snr"], th.band_snr_min,
                   "Signal is broadband — motion artefact, not a heartbeat."),
        GateResult("T5 beat variability",
                   th.rmssd_min_ms <= f["rmssd_ms"] <= th.rmssd_max_ms,
                   f["rmssd_ms"], th.rmssd_min_ms,
                   "Metronomic — a pump, not a heart."),
        GateResult("T6 haemoglobin ratio",
                   th.r_ratio_min <= f["r_ratio"] <= th.r_ratio_max,
                   f["r_ratio"], th.r_ratio_min,
                   "Red/infrared ratio is wrong for haemoglobin — a dye, not blood."),
    ]
    return TouchResult(
        accepted=all(x.passed for x in g), gates=g,
        attestation={"features": {k: round(v, 6) for k, v in f.items()},
                     "accepted": all(x.passed for x in g),
                     "fs_achieved": fs,
                     "thresholds": asdict(th)},
    )


def authorize(sensor: TouchSensor,
              th: TouchThresholds = TouchThresholds()) -> TouchResult:
    """Top-level entry point for touch mode."""
    red, ir, fs = sensor.read_ppg(th.duration_s, th.fs)
    return evaluate(red, ir, sensor.read_bore_reference(), th, fs)


# --------------------------------------------------------------------------
# Synthetic self-test — no hardware. Plausible, NOT calibration data.
# --------------------------------------------------------------------------


def _synth(kind: str, seed: int = 0, th: TouchThresholds = TouchThresholds()):
    rng = np.random.default_rng(seed)
    n = int(th.duration_s * th.fs)
    t = np.arange(n) / th.fs
    bore = (1.0, 1.0)

    if kind == "no_contact":
        return rng.normal(0.97, 0.004, n), rng.normal(0.97, 0.004, n), bore
    if kind == "static_object":                       # wood, a printed photo
        return rng.normal(0.35, 0.0015, n), rng.normal(0.35, 0.0015, n), bore

    bpm = {"too_slow": 26, "too_fast": 230}.get(kind, 68)
    hz = bpm / 60.0
    # Respiratory sinus arrhythmia — heart rate rises and falls with breathing
    # at ~0.25 Hz. This is the dominant component of short-term HRV in a healthy
    # resting adult, and it is what a mechanical pulsator has none of.
    if kind == "pump_fake":
        hz_inst = np.full(n, hz)
    else:
        rsa = 0.10 * np.sin(2 * np.pi * 0.25 * t + rng.uniform(0, 6.28))
        hz_inst = hz * (1 + rsa + rng.normal(0, 0.012, n))
    phase = np.cumsum(hz_inst / th.fs)
    beat = (np.sin(2 * np.pi * phase) + 0.35 * np.sin(4 * np.pi * phase))

    pi_red = 0.020
    # ratio-of-ratios: living tissue ~0.6; red dye absorbs almost nothing in IR
    pi_ir = pi_red / (3.20 if kind == "dye_fake" else 0.62)

    dc = 0.34
    red = dc * (1 - pi_red * beat) + rng.normal(0, 8e-5, n)
    ir = dc * (1 - pi_ir * beat) + rng.normal(0, 8e-5, n)
    if kind == "motion":
        w = 2 * np.pi * rng.uniform(1.3, 2.4)
        art = 0.055 * np.sin(w * t + rng.uniform(0, 6.28)) * (1 + 0.5 * np.sin(0.7 * t))
        art = art + np.cumsum(rng.normal(0, 0.0025, n))
        red, ir = red + art * dc, ir + art * dc
    return red, ir, bore


PANEL = ("genuine", "no_contact", "static_object", "pump_fake",
         "dye_fake", "motion", "too_slow", "too_fast", "slow_capture")


# Every tunable touch threshold, with the feature it is compared against and
# the direction of the comparison — the same contract blood_gate.TUNABLE
# carries, so `calibrate.py touch` drives its sweep off this and adding a
# threshold here is all it takes to bring it under calibration.
#   "min" -> genuine must be >= the threshold
#   "max" -> genuine must be <= the threshold
#
# fs, fs_min and duration_s are deliberately absent: they are properties of the
# CAPTURE, not of the finger, and fitting them to your own sessions would set a
# validity floor from the very data it is supposed to validate.
TUNABLE = {
    "dc_min":        ("dc_red",     "min"),
    "dc_max":        ("dc_red",     "max"),
    "perfusion_min": ("perfusion",  "min"),
    "perfusion_max": ("perfusion",  "max"),
    "bpm_min":       ("bpm",        "min"),
    "bpm_max":       ("bpm",        "max"),
    "band_snr_min":  ("band_snr",   "min"),
    "rmssd_min_ms":  ("rmssd_ms",   "min"),
    "rmssd_max_ms":  ("rmssd_ms",   "max"),
    "r_ratio_min":   ("r_ratio",    "min"),
    "r_ratio_max":   ("r_ratio",    "max"),
}


def features(red: np.ndarray, ir: np.ndarray,
             th: "TouchThresholds | None" = None,
             fs: float | None = None) -> dict:
    """Every raw number the gates compare, with no thresholds applied.

    Same separation of measurement from judgement that blood_gate.metrics()
    makes, and for the same reason: a sweep needs the distribution of each
    feature across the panel, not a pass/fail that has already collapsed it.
    """
    return ppg_features(red, ir, th or TouchThresholds(), fs)


def selftest(n: int = 6) -> int:
    print("Touch mode self-test — 6 gates, existing hardware.")
    print("Synthetic. Exercises the pipeline only; NOT calibration data.\n")
    print(f"{'class':<16}{'accepted':>10}   first failing gate")
    print("-" * 62)
    ok = True
    exercised = set()
    for kind in PANEL:
        acc, fails = 0, {}
        for s in range(n):
            if kind == "slow_capture":
                # Not a spoof: the hardware timing fault of hardware.py's
                # read_ppg. A genuine finger sampled too slowly must be
                # reported as a capture fault, never as a failed pulse.
                r = evaluate(*_synth("genuine", s), TouchThresholds(), fs=8.0)
            else:
                r = evaluate(*_synth(kind, s))
            if r.accepted:
                acc += 1
            elif (g := r.first_failure()):
                fails[g.name] = fails.get(g.name, 0) + 1
        want = acc == n if kind == "genuine" else acc == 0
        ok &= want
        top = max(fails, key=fails.get) if fails else "-"
        exercised.add(top)
        print(f"{kind:<16}{acc:>6}/{n:<4}   {top}{'' if want else '   <-- UNEXPECTED'}")
    print("-" * 62)

    # Same coverage rule as the blood panel: a gate no class exercises is a
    # gate no test covers.
    expected = {f"T{i} " for i in range(0, 7)}
    uncovered = sorted(g for g in expected
                       if not any(e.startswith(g) for e in exercised))
    if uncovered:
        ok = False
        print(f"UNCOVERED GATES: {', '.join(g.strip() for g in uncovered)} — no "
              f"panel class rejects there, so nothing tests them.")
    else:
        print("Gate coverage: all 7 gates exercised by at least one class.")

    print("PASS: pipeline behaves as designed." if ok else "FAIL: see flagged rows.")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(selftest())
