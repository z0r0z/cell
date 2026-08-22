"""Cardiac identity tests, and the measurement that decides whether it ships.

Two different things are checked here and they must not be confused.

  THE PIPELINE. Segmentation, normalisation, scoring and the EER machinery do
  what they claim on synthetic waveforms whose morphology differs by known
  amounts. This is real: a broken scorer fails here.

  THE CLAIM. Whether real people separate, across sessions, months apart, in
  the cold. Synthetic data CANNOT answer that, and no amount of it ever will.
  The synthetic people here differ by parameters we chose, so of course they
  separate. That is the same trap as a spoof panel built out of shapes picked
  to fail.

So this suite ends by asserting the feature is DISABLED, and stays that way
until calibrate.py measures the cross-session EER on real captures. The test
that would catch someone quietly turning it on is the last one.
"""

from __future__ import annotations

import numpy as np

import cardiac_id as cid

FS = 50.0
DUR = 15.0


def synth(person: int, session: int, bpm: float = 68.0, noise: float = 6e-5,
          n: int | None = None) -> np.ndarray:
    """A PPG-shaped waveform for a made-up person.

    The morphology knobs are the ones the literature treats as individual:
    where the reflected wave lands (arterial stiffness and body height) and how
    large it is relative to the systolic peak (the augmentation index). Session
    varies posture and contact pressure, which is what has to be tolerated.
    """
    rng = np.random.default_rng(person * 1000 + session)
    n = n or int(DUR * FS)
    t = np.arange(n) / FS

    refl_delay = 0.22 + 0.055 * person      # s, reflected wave arrival
    refl_amp = 0.55 - 0.075 * person        # relative to systolic peak
    width = 0.115 + 0.012 * person

    # Session-to-session variation the template has to survive.
    refl_delay += rng.normal(0, 0.006)
    refl_amp += rng.normal(0, 0.02)
    hz = bpm / 60.0

    rsa = 0.09 * np.sin(2 * np.pi * 0.25 * t + rng.uniform(0, 6.28))
    phase = np.cumsum(hz * (1 + rsa + rng.normal(0, 0.010, n)) / FS)
    frac = phase % 1.0
    period = 1.0 / hz

    def gauss(centre, sigma, amp):
        d = (frac * period - centre)
        return amp * np.exp(-0.5 * (d / sigma) ** 2)

    beat = gauss(0.13, width, 1.0) + gauss(0.13 + refl_delay, width * 1.35, refl_amp)
    dc = 0.34 * (1 + rng.normal(0, 0.02))
    return dc * (1 - 0.02 * beat) + rng.normal(0, noise, n)


def pipeline() -> bool:
    ok, checks = True, []
    b = cid.beats(synth(1, 0), FS)
    checks.append(("segments a capture into beats", len(b) >= 8))
    checks.append(("beats are resampled to a common length",
                   b.shape[1] == cid.BEAT_POINTS))
    checks.append(("beats are amplitude-normalised",
                   bool(np.all(b.min(axis=1) > -0.05) and np.all(b.max(axis=1) < 1.05))))

    t = cid.enrol([(synth(1, s), FS) for s in range(3)])
    checks.append(("enrolment uses every session", t.n_sessions == 3))
    checks.append(("enrolment ships disabled", t.enabled is False))

    # Rate must not be identity: the same person at a different heart rate has
    # to score closer than a different person at the same rate.
    same_fast = cid.score(t, synth(1, 9, bpm=95), FS)
    other_same = cid.score(t, synth(4, 9, bpm=68), FS)
    checks.append(("scores shape, not heart rate", same_fast < other_same))

    checks.append(("empty capture scores infinite",
                   cid.score(t, np.zeros(int(DUR * FS)), FS) == float("inf")))
    checks.append(("uncalibrated template scores infinite",
                   cid.score(cid.Template(), synth(1, 0), FS) == float("inf")))
    checks.append(("template round-trips",
                   cid.Template.from_dict(t.to_dict()) == t))

    # EER machinery, on distributions with a known answer.
    eer, _ = cid.equal_error_rate([0.0, 0.1, 0.2], [0.8, 0.9, 1.0])
    checks.append(("EER is 0 for separated distributions", eer == 0.0))
    eer, _ = cid.equal_error_rate([0.0, 1.0], [0.0, 1.0])
    checks.append(("EER is 0.5 for identical distributions", 0.4 <= eer <= 0.6))

    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    return ok


def separation() -> bool:
    """Measure, and print, how identity separation survives a changing pulse.

    This does not assert a flattering threshold. It reports the number, because
    the number is the whole point: it is what decides whether the feature is
    worth wiring in, and the answer here is no.
    """
    def eer(enrol_bpm, probe_bpms):
        people = range(5)
        T = {p: cid.enrol([(synth(p, s, bpm=enrol_bpm), FS) for s in range(4)])
             for p in people}
        g, i = [], []
        for p in people:
            for s, r in enumerate(probe_bpms, start=20):     # unseen sessions
                probe = synth(p, s, bpm=r)
                g.append(cid.score(T[p], probe, FS))
                i += [cid.score(T[q], probe, FS) for q in people if q != p]
        return cid.equal_error_rate(g, i)[0]

    rows = [("matched rate", [68, 68, 68]),
            ("+/- 4 bpm", [64, 68, 72]),
            ("+/- 12 bpm", [60, 68, 80]),
            ("+/- 27 bpm", [55, 68, 95])]
    results = [(label, eer(68, probes)) for label, probes in rows]
    for label, e in results:
        print(f"  enrol at 68 bpm, verify {label:<14} EER {e*100:5.1f}%")

    matched = results[0][1]
    print()
    print("  Chance is 50%. A biometric anyone would deploy is well under 1%.")
    print("  So even at a matched heart rate this does not separate usefully,")
    print("  and a pulse 12 bpm off doubles the error. Real people, months")
    print("  apart, in the cold, will be worse than these synthetic ones --")
    print("  whose differences this file chose and made generous.")
    print()
    print("  Conclusion: the mean-beat template is not a viable identity gate.")
    print("  The harness stays because the question is worth re-asking against")
    print("  real captures and a better feature set, not because this works.")

    # The only pass condition that means anything: the scorer is not broken.
    # Beating chance proves the pipeline carries signal. It does not make the
    # feature usable, and nothing here should be read as saying it does.
    return matched < 0.40


def stays_disabled() -> bool:
    """The guard against shipping this on faith."""
    t = cid.enrol([(synth(2, s), FS) for s in range(3)])
    good = (t.enabled is False and t.threshold == 0.0
            and "not yet calibrated" in t.note)
    print(f"  {'fresh template is inert until calibrated':<48}"
          f"{'PASS' if good else 'FAIL'}")
    return good


def main() -> int:
    print("Cardiac identity — PPG waveform, no added hardware\n")
    print("Pipeline:")
    a = pipeline()
    print("\nCross-session separation, synthetic:")
    b = separation()
    print("\nShip guard:")
    c = stays_disabled()
    ok = a and b and c
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
