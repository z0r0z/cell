#!/usr/bin/env python3
"""The optical PUF, driven past its limits.

Two things are being asked. Does the coding layer do what BCH is supposed to
do -- correct exactly t errors and refuse t+1 rather than returning a wrong
answer quietly. And does the whole extractor reproduce a key across a drifting
chamber while failing on a disturbed one, which is the property the design
rests on.

The speckle here is a static complex Gaussian field filtered to a grain size,
with intensity |E|^2 -- the same construction firmware/speckle_sim.py uses,
minus the time evolution, because a diffuser epoxied into a chamber does not
decorrelate on its own. Drift is modelled as partial decorrelation: a
wavelength or mount shift replaces some fraction of the field with fresh
speckle. That is the right shape for both causes and it is the only knob that
matters, since everything else the environment does is either an intensity
change (the sign features remove it) or a shift of this kind.

What this does NOT establish: what drift fraction a real epoxied diffuser
shows over months and temperature. That is a hardware panel.
"""

from __future__ import annotations

import numpy as np

import optical_puf as puf

RNG = np.random.default_rng(20260823)


# --------------------------------------------------------------------------
# A static speckle chamber
# --------------------------------------------------------------------------

def _field(shape, grain_px, rng):
    """Complex Gaussian field, spatially filtered to the given grain size."""
    h, w = shape
    e = rng.normal(size=(h, w)) + 1j * rng.normal(size=(h, w))
    fy = np.fft.fftfreq(h)[:, None]
    fx = np.fft.fftfreq(w)[None, :]
    # A Gaussian aperture of this width produces grains of ~grain_px.
    envelope = np.exp(-0.5 * (fy ** 2 + fx ** 2) * (2 * np.pi * grain_px) ** 2)
    return np.fft.ifft2(np.fft.fft2(e) * envelope)


class Chamber:
    """One epoxied diffuser. Its field is its identity."""

    def __init__(self, size=768, grain_px=4, rng=RNG):
        self.size, self.grain_px, self.rng = size, grain_px, rng
        self.E = _field((size, size), grain_px, rng)

    def read(self, drift=0.0, frames=16, shot=0.02, gain=1.0, shift=(0, 0)):
        """A prepared image. `drift` is the fraction of the field replaced,
        `shift` is whole-pixel translation of the whole pattern -- what a
        mount does when the resin warms."""
        E = self.E
        if any(shift):
            E = np.roll(np.roll(E, shift[0], axis=0), shift[1], axis=1)
        if drift > 0:
            fresh = _field((self.size, self.size), self.grain_px, self.rng)
            E = np.sqrt(1 - drift) * E + np.sqrt(drift) * fresh
        I = np.abs(E) ** 2
        I = I / I.mean() * gain
        out = I[None, ...] + self.rng.normal(0, shot, (frames,) + I.shape)
        return puf.prepare(out)


def _checks():
    checks = []

    # -- BCH, at and beyond the correction radius -----------------------
    code = puf.BCH(8, 10)
    msg = RNG.integers(0, 2, code.k, dtype=np.uint8)
    cw = code.encode(msg)

    checks.append(("encodes systematically",
                   np.array_equal(code.message(cw), msg)))
    checks.append(("clean word decodes",
                   np.array_equal(code.decode(cw), cw)))

    ok_at_t = True
    for _ in range(20):
        r = cw.copy()
        r[RNG.choice(code.n, code.t, replace=False)] ^= 1
        ok_at_t &= np.array_equal(code.decode(r), cw)
    checks.append((f"corrects exactly t={code.t} errors", ok_at_t))

    # Beyond t a bounded-distance decoder must not return a WRONG codeword.
    silent = 0
    for _ in range(40):
        r = cw.copy()
        r[RNG.choice(code.n, code.t + 4, replace=False)] ^= 1
        got = code.decode(r)
        if got is not None and not np.array_equal(got, cw):
            silent += 1
    checks.append(("never miscorrects silently past t", silent == 0))

    # -- feature extraction --------------------------------------------
    ch = Chamber()
    img = ch.read()
    b, _ = puf.bits_from_image(img, ch.grain_px)
    checks.append(("one bit per grain, not per pixel",
                   b.size == (ch.size // ch.grain_px) ** 2))
    checks.append(("bits are balanced", 0.45 < b.mean() < 0.55))

    # Sign features must ignore illumination and exposure changes.
    b_gain, _ = puf.bits_from_image(ch.read(gain=3.0), ch.grain_px)
    checks.append(("survives a 3x gain change",
                   (b != b_gain).mean() < 0.02))

    # Two chambers must not resemble each other.
    other = Chamber(rng=np.random.default_rng(7))
    inter = (b != puf.bits_from_image(other.read(), ch.grain_px)[0]).mean()
    checks.append((f"different chambers differ ~50% (got {inter:.1%})",
                   0.45 < inter < 0.55))

    # -- the raw error rate the extractor has to absorb -----------------
    def _ber(d, selected=None):
        out = []
        for _ in range(3):
            a, _m = puf.bits_from_image(ch.read(), ch.grain_px)
            b2, _m2 = puf.bits_from_image(ch.read(drift=d), ch.grain_px)
            sel = slice(None) if selected is None else selected
            out.append((a[sel] != b2[sel]).mean())
        return float(np.mean(out))

    ber = {d: _ber(d) for d in (0.0, 0.02, 0.05, 0.10)}
    checks.append((f"undisturbed BER is small (got {ber[0.0]:.2%})",
                   ber[0.0] < 0.05))

    # -- the extractor, end to end --------------------------------------
    m, t = 12, 180
    enrol = [ch.read() for _ in range(5)]
    try:
        helper, key = puf.enroll(enrol, m=m, t=t, rng=RNG)
        enrolled = True
    except puf.PufError:
        helper, key, enrolled = None, None, False
    checks.append(("enrols from a 768px ROI", enrolled))

    if enrolled:
        checks.append(("key is 256 bits", len(key) == 32))

        again = 0
        for _ in range(10):
            try:
                again += puf.reproduce(ch.read(), helper) == key
            except puf.PufError:
                pass
        checks.append((f"reproduces on a quiet chamber ({again}/10)",
                       again == 10))

        drifted = 0
        for _ in range(10):
            try:
                drifted += puf.reproduce(ch.read(drift=0.02), helper) == key
            except puf.PufError:
                pass
        checks.append((f"survives 2% drift ({drifted}/10)", drifted >= 9))

        # Tamper. Opening the case replaces the field outright.
        opened = Chamber(rng=np.random.default_rng(99))
        leaked = 0
        for _ in range(10):
            try:
                if puf.reproduce(opened.read(), helper) == key:
                    leaked += 1
            except puf.PufError:
                pass
        checks.append(("a swapped chamber never yields the key", leaked == 0))

        # Partial disturbance must also fail rather than half-work.
        big = 0
        for _ in range(10):
            try:
                if puf.reproduce(ch.read(drift=0.5), helper) == key:
                    big += 1
            except puf.PufError:
                pass
        checks.append(("heavy disturbance fails closed", big == 0))

        # Registration. A grain is ~4 px, so an unregistered 4 px shift loses
        # the key outright -- and PETG over the 20 mm standoff moves about a
        # pixel per kelvin, so this is a cold morning, not an attack.
        moved = {}
        for px in (0, 2, 4, 8, 16):
            got = 0
            for _ in range(3):
                try:
                    got += puf.reproduce(ch.read(shift=(px, 0)), helper) == key
                except puf.PufError:
                    pass
            moved[px] = got
        checks.append((f"survives translation up to 16 px "
                       f"({'/'.join(str(moved[p]) for p in (0, 2, 4, 8, 16))} of 3)",
                       all(v == 3 for v in moved.values())))

        diag = 0
        for _ in range(3):
            try:
                diag += puf.reproduce(ch.read(shift=(9, -7)), helper) == key
            except puf.PufError:
                pass
        checks.append(("survives a diagonal shift", diag == 3))

        checks.append(("registration finds the shift it was given",
                       puf.estimate_shift(ch.read(shift=(6, -3)),
                                          helper.fiducial) == (6, -3)))

        # Translation must not become a way to pass with the wrong chamber:
        # the search is over shifts, not over diffusers.
        slid = 0
        for _ in range(5):
            try:
                if puf.reproduce(opened.read(shift=(5, 5)), helper) == key:
                    slid += 1
            except puf.PufError:
                pass
        checks.append(("registration does not rescue a swapped chamber",
                       slid == 0))

        # The fiducial is published, so it must not be key material.
        lo = puf.FIDUCIAL_ORIGIN // ch.grain_px
        hi = -(-(puf.FIDUCIAL_ORIGIN + puf.FIDUCIAL_PX) // ch.grain_px)
        cells_wide = ch.size // ch.grain_px
        fid_idx = {r * cells_wide + c
                   for r in range(lo, hi) for c in range(lo, hi)}
        checks.append(("no key bit comes from the published fiducial",
                       not (set(helper.mask.tolist()) & fid_idx)))

        # ---- what the published helper is allowed to cost ----------------
        # The helper discloses at most n-k bits. That is only affordable if
        # the bits it protects are worth close to one bit each, and the margin
        # filter is exactly the thing that could quietly stop them being.
        def _H(p):
            p = min(max(p, 1e-12), 1 - 1e-12)
            return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))

        bits0, _ = puf.bits_from_image(enrol[0])
        chosen = bits0[helper.mask]
        bias = float(chosen.mean())
        checks.append((f"selected bits are not biased (got {bias:.3f})",
                       0.40 < bias < 0.60))

        # Raw intensity is exponential, so an untransformed margin selects the
        # bright tail and the bits come out ~80% ones. The quantile transform
        # is what stops that, and this is the check that notices if it goes.
        gw = ch.size // ch.grain_px
        chosen_set = set(int(i) for i in helper.mask)
        touching = sum(1 for i in chosen_set
                       if (i + 1) in chosen_set and (i + 1) % gw != 0)
        checks.append((f"no two key bits are adjacent grains ({touching})",
                       touching == 0))

        code = puf.BCH(m, t)
        residual = code.n * _H(bias) - (code.n - code.k)
        checks.append((f"residual entropy clears a 256-bit key "
                       f"({residual:.0f} bits)", residual > 512))

        # The helper is public, so it must not carry the key.
        h2, k2 = puf.enroll(enrol, m=m, t=t, rng=np.random.default_rng(5))
        checks.append(("same chamber, same key regardless of codeword",
                       k2 == key))
        checks.append(("helper differs when the codeword does",
                       not np.array_equal(h2.offset, helper.offset)))

        b_helper = np.unpackbits(np.packbits(helper.offset))[:helper.offset.size]
        checks.append(("helper offset looks uniform",
                       0.45 < b_helper.mean() < 0.55))

    print("    raw BER vs drift:      " +
          ", ".join(f"{d:.0%}->{v:.2%}" for d, v in ber.items()))
    if enrolled:
        sel = {d: _ber(d, helper.mask) for d in (0.0, 0.02, 0.05, 0.10)}
        print("    after margin select:   " +
              ", ".join(f"{d:.0%}->{v:.2%}" for d, v in sel.items()))
        print(f"    code corrects:         {t / puf.BCH(m, t).n:.2%}")
    return checks


def main() -> int:
    print("Optical PUF")
    checks = _checks()
    bad = 0
    for name, ok in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")
        bad += not ok
    print(f"\n  {len(checks) - bad}/{len(checks)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
