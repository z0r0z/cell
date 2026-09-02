#!/usr/bin/env python3
"""The chamber as an entropy source, and the way it would fail silently.

The failure this file exists to catch is specific. A speckle image is the PUF
and is reproducible by construction, so a seed drawn from one frame would be
the same on every power cycle of that device, forever, while every statistical
test on it passed. The tests below therefore ask the anti-PUF question first:
does the same chamber, read twice, give two different answers.

The rest are the ways a real chamber fails. A dead laser and a stuck sensor
both look like a constant frame. A laser still settling puts a DC step between
two frames. A blocked window biases the sample. Each has to be refused rather
than hashed into somebody's seed.
"""

from __future__ import annotations

import sys

import numpy as np

import chamber_trng as trng
from chamber_trng import NotEnoughEntropy

SIZE = 96


def _report(checks) -> bool:
    ok = True
    for label, good in checks:
        ok &= bool(good)
        print(f"  {label:<56}{'PASS' if good else 'FAIL'}")
    return ok


def _field(rng, size=SIZE):
    e = rng.normal(size=(size, size)) + 1j * rng.normal(size=(size, size))
    return np.abs(e) ** 2


def _burst(field, rng, n=64, shot=0.05):
    return field[None, ...] + rng.normal(0, shot, (n,) + field.shape)


def _raises(fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
    except NotEnoughEntropy:
        return True
    except Exception:                                       # noqa: BLE001
        return False
    return False


def the_anti_puf_question() -> bool:
    """One chamber, two captures. The PUF wants these equal. This wants them not."""
    rng = np.random.default_rng(7)
    field = _field(rng)                       # the diffuser, fixed forever
    a, _ = trng.harvest(_burst(field, np.random.default_rng(11)))
    b, _ = trng.harvest(_burst(field, np.random.default_rng(12)))
    # A second device whose diffuser is different, read with the SAME noise
    # stream. The field cancels in the subtraction, so the output is a
    # function of the noise and not of the pattern -- which is the mechanism
    # spelled out, and the exact opposite of what optical_puf.py wants from
    # the same capture.
    #
    # Exactly equal here because this simulation adds noise that does not
    # depend on the field. Real shot noise scales with intensity, so on
    # hardware the cancellation is partial. The claim that survives either way
    # is the one that matters: the output is not the pattern.
    other = _field(np.random.default_rng(99))
    c, _ = trng.harvest(_burst(other, np.random.default_rng(11)))
    return _report([
        ("the same chamber read twice gives different bytes", a != b),
        ("a different chamber on the same noise gives the same bytes,",  c == a),
        ("  which is the field cancelling rather than being hashed", c == a),
        ("the output is the requested length", len(a) == 32),
        ("the same frames give the same bytes",
         trng.harvest(_burst(field, np.random.default_rng(11)))[0] == a),
    ])


def a_static_field_is_not_a_source() -> bool:
    """No per-frame noise: the difference is zero and there is nothing here."""
    field = _field(np.random.default_rng(3))
    frames = np.repeat(field[None, ...], 32, axis=0)         # identical frames
    res = trng.residuals(frames)
    return _report([
        ("identical frames leave a zero residual", not res.any()),
        ("and are refused rather than hashed", _raises(trng.harvest, frames)),
        ("a single frame is refused",
         _raises(trng.harvest, field[None, ...])),
        ("a 2-D array is refused", _raises(trng.harvest, field)),
    ])


def pairs_are_disjoint() -> bool:
    """d1 = f2-f1 and d2 = f3-f2 share f2. Sharing is a correlation."""
    f = np.arange(6 * 4 * 4, dtype=np.float64).reshape(6, 4, 4)
    res = trng.residuals(f)
    odd = trng.residuals(f[:5])
    return _report([
        ("six frames make three differences", res.shape[0] == 3),
        ("the first is f0 - f1", np.array_equal(res[0], f[0] - f[1])),
        ("the second is f2 - f3, not f1 - f2",
         np.array_equal(res[1], f[2] - f[3])),
        ("an odd frame is dropped rather than reused", odd.shape[0] == 2),
    ])


def the_ways_a_chamber_fails() -> bool:
    rng = np.random.default_rng(5)
    field = _field(rng)

    # A laser still settling: a DC step between the two halves of each pair.
    settling = _burst(field, np.random.default_rng(21))
    settling[1::2] += 0.9
    ok_settling = trng.harvest(settling)[1].ok

    # A stuck sensor: one value everywhere, every frame.
    stuck = np.full((32, SIZE, SIZE), 7.0)

    # A blocked window: quantised to nothing, so every frame is identical.
    dark = np.zeros((32, SIZE, SIZE))

    # An overexposed chamber. Most pixels clip to the same value, so most of
    # the residual is exactly zero and only a few live pixels are left. This
    # is the bias that survives median thresholding, because the ties all fall
    # on one side of it.
    hot = np.clip(field, 0, np.quantile(field, 0.10))
    saturated = hot[None, ...] + np.random.default_rng(31).normal(
        0, 0.02, (32, SIZE, SIZE))
    saturated = np.rint(np.clip(saturated, 0, np.quantile(field, 0.10)) * 255)

    # Real noise, but far too little of it to cover 256 bits with margin.
    small = _field(rng, size=8)
    thin = small[None, ...] + np.random.default_rng(41).normal(
        0, 0.05, (4, 8, 8))

    return _report([
        ("a DC step between paired frames is survived", ok_settling),
        ("a stuck sensor is refused", _raises(trng.harvest, stuck)),
        ("a dark chamber is refused", _raises(trng.harvest, dark)),
        ("an overexposed chamber is refused", _raises(trng.harvest, saturated)),
        ("too few bits is refused even when they are good",
         _raises(trng.harvest, thin)),
        ("the repetition test sees a stuck run",
         trng.repetition_count(np.zeros(4096, dtype=np.uint8))
         >= trng.repetition_cutoff(4096)),
        # The cutoff is sized for the draw, not per sample: a fixed 21 refused
        # a healthy chamber roughly a quarter of the time on the 294,912-bit
        # burst this module harvests.
        ("the cutoff grows with the size of the draw",
         trng.repetition_cutoff(4096) > trng.repetition_cutoff(1)
         and trng.repetition_cutoff(64 * 96 * 96) > trng.repetition_cutoff(4096)),
        ("a healthy chamber is not refused by the run test",
         all(trng.repetition_count(
                 np.random.default_rng(s_).integers(0, 2, 64 * 96 * 96
                                                    ).astype(np.uint8))
             < trng.repetition_cutoff(64 * 96 * 96) for s_ in range(6))),
        # A sample too short for one window has to say so. Returning 0 meant
        # assess() read "could not run" as "comfortably passed".
        ("a sample shorter than one window reports that it could not run",
         trng.adaptive_proportion(np.ones(600, dtype=np.uint8)) < 0),
        ("the proportion test sees a biased window",
         trng.adaptive_proportion(
             np.concatenate([np.ones(900, dtype=np.uint8),
                             np.zeros(124, dtype=np.uint8)]))
         >= trng.PROPORTION_CUTOFF),
        ("a fair sample clears both",
         trng.repetition_count(
             np.random.default_rng(2).integers(0, 2, 8192).astype(np.uint8))
         < trng.repetition_cutoff(8192)
         and trng.adaptive_proportion(
             np.random.default_rng(2).integers(0, 2, 8192).astype(np.uint8))
         < trng.PROPORTION_CUTOFF),
        # harvest() checks the health of the bits against the number of bytes
        # asked for, so it has to return that many.
        ("a request larger than one digest is answered in full",
         len(trng.harvest(_burst(_field(np.random.default_rng(5)),
                                 np.random.default_rng(5)), 64)[0]) == 64),
    ])


def what_the_report_says() -> bool:
    rng = np.random.default_rng(13)
    _, r = trng.harvest(_burst(_field(rng), rng))
    text = "\n".join(r.lines())
    return _report([
        ("it reports the frames it drew", r.frames == 64 and r.pairs == 32),
        ("it reports a per-bit min-entropy under 1.0", 0.5 < r.per_bit <= 1.0),
        ("the margin required is twice the output",
         r.wanted == 256 and trng.ENTROPY_MARGIN == 2.0),
        ("the balance is reported for a human to read",
         0.45 < r.ones < 0.55),
        ("the lines say usable", "usable" in text),
        ("a refused sample says why",
         "REFUSED" in "\n".join(
             trng.assess(np.zeros(4096, dtype=np.uint8), 256, 2, 1).lines())),
    ])


def the_mix_is_xor() -> bool:
    """The rule the whole thing rests on: it can only ever add.

    A third source that REPLACED either of the other two would make a broken
    chamber a weaker seed. XOR means the worst a hostile or dead chamber can
    do is contribute nothing.
    """
    import os
    kernel = os.urandom(32)
    chip = os.urandom(32)
    chamber, _ = trng.harvest(
        _burst(_field(np.random.default_rng(17)), np.random.default_rng(18)))
    mixed = bytes(a ^ b ^ c for a, b, c in zip(kernel, chip, chamber))
    # A chamber returning attacker-chosen bytes cannot steer the result unless
    # it also knows the other two.
    evil = bytes(32)
    without = bytes(a ^ b ^ c for a, b, c in zip(kernel, chip, evil))
    return _report([
        ("mixing three sources is 32 bytes", len(mixed) == 32),
        ("a chamber of zeros leaves the other two intact",
         without == bytes(a ^ b for a, b in zip(kernel, chip))),
        ("the chamber changes the result when it works", mixed != without),
        ("dropping any one source changes the seed",
         bytes(a ^ b for a, b in zip(chip, chamber)) != mixed),
    ])


def main() -> int:
    print("Chamber entropy: the third term, and the way it would fail quietly\n")
    print("The anti-PUF question, which is the whole design:")
    a = the_anti_puf_question()
    print("\nA static field is not a source:")
    b = a_static_field_is_not_a_source()
    print("\nDisjoint pairs:")
    c = pairs_are_disjoint()
    print("\nThe ways a real chamber fails:")
    d = the_ways_a_chamber_fails()
    print("\nWhat travels with the seed:")
    e = what_the_report_says()
    print("\nThe mix:")
    f = the_mix_is_xor()
    ok = all([a, b, c, d, e, f])
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
