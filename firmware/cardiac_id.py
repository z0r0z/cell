"""Cardiac identity from the PPG waveform the touch tier already captures.

The touch tier proves a living human is present. It does not prove which one.
The pulse waveform carries some individual information, and the sensor that
would read it is already in the device -- so unlike a fingerprint reader this
costs nothing in parts. That is the whole appeal, and it is worth being clear
about what it does and does not buy.

WHAT THE SHAPE OF A PULSE ENCODES. Light returning from a fingertip traces
arterial volume through one cardiac cycle. Its shape is set by things that
differ between people and are fairly stable within one: arterial stiffness,
the timing of the reflected wave from the lower body, vessel geometry. The
classic descriptors are the systolic peak, the dicrotic notch, and the ratios
between them, plus the a-b-c-d-e features of the second derivative.

WHAT IT IS NOT. A biometric of this kind is soft. It is not revocable, it is
not secret, and matching it is fuzzy. So it can only ever be an ADDITIONAL
signal beside the PIN, never a replacement for it, and never an input to key
derivation -- see signer.unwrap_context, which takes stable inputs only.

WHAT IT MEASURED. Built and run against synthetic people whose morphology
differs by generous, chosen amounts. Equal error rate, enrolling at 68 bpm:

    matched rate   14.2%      +/- 12 bpm   27.5%
    +/- 4 bpm      13.3%      +/- 27 bpm   33.3%

Chance is 50%. A biometric anyone deploys is well under 1%. So this does not
separate usefully even under conditions chosen to flatter it, and a pulse 12
bpm off doubles the error. Real people months apart will be worse.

That is the finding, and it is why nothing here is wired into the touch gate.
The module stays because the question is worth re-asking against real captures
and a better feature set -- second-derivative landmarks, rate normalisation --
not because the mean-beat template works.

Three things this cost, all of which would bite anyone attempting it:
reflectance PPG is inverted, so a foot detector finds peaks unless the signal
is flipped; beats have to be cut as a fixed DURATION, since the reflected wave
arrives at a fixed delay and fraction-of-RR normalisation slides it; and the
touch gate's 0.35-4 Hz band is wrong here, because it removes the harmonics
that carry shape and which of them survive depends on heart rate.

WHY IT SHIPS DISABLED. Reported accuracies for PPG identity are mostly from
one sitting, with enrolment and test minutes apart. What matters here is
whether a template taken today still matches you in six months, across
temperature, hydration, posture and contact pressure. That number decides
whether this is a feature or a lockout, and nobody has it for this hardware.
So `Template.enabled` is False until `calibrate.py touch-id` measures the
separation on real captures and says otherwise. A gate that rejects its owner
when they are cold is worse than no gate.

Dependencies: numpy, scipy.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

import numpy as np
from scipy.signal import find_peaks

from touch_gate import _bandpass

# Identity needs a WIDER band than the touch gate's 0.35-4 Hz cardiac window.
# That window exists to isolate the fundamental and reject artefact, and it is
# right for detecting a pulse. It is wrong for measuring the shape of one: the
# dicrotic notch and the upstroke are fast features carried by the harmonics it
# removes, and WHICH harmonics survive depends on heart rate -- so filtering
# this way makes morphology a function of how fast the heart is beating.
# Measured here before the band was widened, the same person at 68 and 95 bpm
# scored further apart than two different people.
ID_LO, ID_HI = 0.5, 12.0

# Every beat is resampled onto this many points before comparison, so beats at
# different heart rates are compared by SHAPE rather than by duration. Rate is
# already covered by T3 and is not identity: yours changes when you climb
# stairs, and a stranger's can match it exactly.
BEAT_POINTS = 64

# Beats are cut as a fixed DURATION from the foot, not as a fraction of the RR
# interval. This is the difference between a working identity check and one
# that mistakes your heart rate for someone else.
#
# What carries identity is when the reflected wave gets back from the lower
# body, and that delay is set by height and arterial stiffness -- roughly fixed
# in seconds, not as a share of the beat. Normalise to a fraction of RR and the
# reflection slides as your pulse changes: measured here, the same person at 68
# and 95 bpm looked LESS alike than two different people at 68.
WINDOW_S = 0.50

# 0.50 s has to fit inside one RR interval, so identity cannot be assessed
# above about 115 bpm. That is an abstain, not a rejection -- the tier's other
# gates still run, and refusing to answer beats answering wrongly.
ID_MAX_BPM = 115.0


@dataclass
class Template:
    """An enrolled person, as a mean beat plus its spread.

    `enabled` is the gate. It stays False until a calibration run has measured
    a usable equal error rate on captures taken ACROSS sessions.
    """

    beat: list[float] = field(default_factory=list)      # BEAT_POINTS, unit norm
    spread: list[float] = field(default_factory=list)    # per-point std
    n_beats: int = 0
    n_sessions: int = 0
    threshold: float = 0.0        # accept when score <= this
    enabled: bool = False
    note: str = "not calibrated"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Template":
        return Template(**d)


def _feet(ac: np.ndarray, fs: float) -> np.ndarray:
    """Indices of pulse feet -- the minima that start each upstroke.

    Feet rather than peaks: the foot is the steepest, least ambiguous landmark
    on a PPG, and peak position itself varies with the very morphology being
    measured, so segmenting on peaks would fold the signal into the alignment.
    """
    # 180 bpm is the physiological ceiling T3 enforces, so beats cannot be
    # closer than that.
    min_gap = int(fs / (180 / 60))
    peaks, _ = find_peaks(-ac, distance=max(min_gap, 2))
    return peaks


def beats(red: np.ndarray, fs: float) -> np.ndarray:
    """Every clean beat in a capture, resampled and normalised.

    Returns (n_beats, BEAT_POINTS). Amplitude is normalised away because
    perfusion depends on how hard the finger presses, which is not identity.
    Shape is what is left.
    """
    # Reflectance PPG is inverted: more arterial blood absorbs more light, so
    # a systolic peak is a DOWNWARD excursion in raw counts. Flip it first, or
    # the foot detector lands on peaks and every beat comes out backwards --
    # which looks like a working pipeline right up until morphology is compared.
    hi = min(ID_HI, fs * 0.45)          # stay clear of Nyquist
    ac = -_bandpass(np.asarray(red, dtype=float), fs, ID_LO, hi)
    feet = _feet(ac, fs)
    if len(feet) < 3:
        return np.empty((0, BEAT_POINTS))

    out = []
    grid = np.linspace(0, 1, BEAT_POINTS)
    span = int(round(WINDOW_S * fs))
    if span < 8:
        return np.empty((0, BEAT_POINTS))
    for a, b in zip(feet[:-1], feet[1:]):
        # The window must sit inside this beat, or it swallows the next
        # upstroke and the tail stops meaning anything.
        if (b - a) < span or a + span > len(ac):
            continue
        seg = ac[a:a + span]
        rng = seg.max() - seg.min()
        if rng <= 0:
            continue
        seg = (seg - seg.min()) / rng
        out.append(np.interp(grid, np.linspace(0, 1, len(seg)), seg))
    if not out:
        return np.empty((0, BEAT_POINTS))

    b = np.asarray(out)
    # Drop beats far from the session's own median: motion artefacts and
    # ectopic beats are not the person, and one of them can drag a template.
    med = np.median(b, axis=0)
    d = np.linalg.norm(b - med, axis=1)
    keep = d <= (np.median(d) + 2.0 * (np.std(d) + 1e-9))
    return b[keep] if keep.any() else b


def enrol(sessions: list[tuple[np.ndarray, float]]) -> Template:
    """Build a template from several captures.

    Deliberately takes SESSIONS, not one long recording. A template from a
    single sitting describes that sitting -- finger position, temperature,
    whether you had just walked upstairs -- and will not match you next week.
    """
    all_beats, used = [], 0
    for red, fs in sessions:
        b = beats(red, fs)
        if len(b):
            all_beats.append(b)
            used += 1
    if not all_beats:
        return Template(note="no usable beats")
    b = np.vstack(all_beats)
    mean = b.mean(axis=0)
    n = np.linalg.norm(mean)
    if n == 0:
        return Template(note="degenerate template")
    return Template(beat=(mean / n).tolist(),
                    spread=b.std(axis=0).tolist(),
                    n_beats=int(len(b)), n_sessions=used,
                    note=f"{len(b)} beats over {used} sessions, not yet calibrated")


def score(t: Template, red: np.ndarray, fs: float) -> float:
    """Distance from a capture to a template. Lower is more like the enrollee.

    Cosine distance on the mean beat, weighted by the inverse of the enrolled
    spread: points that vary a lot within one person carry little identity, so
    they should not dominate the comparison.
    """
    if not t.beat:
        return float("inf")
    b = beats(red, fs)
    if not len(b):
        return float("inf")
    probe = b.mean(axis=0)
    n = np.linalg.norm(probe)
    if n == 0:
        return float("inf")
    probe = probe / n

    w = 1.0 / (np.asarray(t.spread) + 1e-3)
    w = w / np.linalg.norm(w)
    a = np.asarray(t.beat) * w
    c = probe * w
    denom = np.linalg.norm(a) * np.linalg.norm(c)
    if denom == 0:
        return float("inf")
    return float(1.0 - np.dot(a, c) / denom)


def equal_error_rate(genuine: list[float], impostor: list[float]) -> tuple[float, float]:
    """(EER, threshold) over the two score distributions.

    EER is the point where false accepts and false rejects are equal. It is the
    honest single number for a soft biometric, because quoting accuracy without
    a threshold lets you pick whichever end flatters the result.
    """
    if not genuine or not impostor:
        return 1.0, 0.0
    g, i = np.asarray(genuine), np.asarray(impostor)
    best = (1.0, 0.0, 1.0)
    for th in np.unique(np.concatenate([g, i])):
        frr = float(np.mean(g > th))       # genuine rejected
        far = float(np.mean(i <= th))      # impostor accepted
        if abs(frr - far) < best[2]:
            best = ((frr + far) / 2, float(th), abs(frr - far))
    return best[0], best[1]
