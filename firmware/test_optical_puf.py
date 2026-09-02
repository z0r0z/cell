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

    def read(self, drift=0.0, frames=16, shot=0.02, gain=1.0, shift=(0, 0),
             rot_deg=0.0):
        """A prepared image. `drift` is the fraction of the field replaced,
        `shift` is whole-pixel translation of the whole pattern -- what a
        mount does when the resin warms."""
        E = self.E
        if rot_deg:
            n = self.size
            c = (n - 1) / 2.0
            th = np.deg2rad(rot_deg)
            ct, st = np.cos(th), np.sin(th)
            y, x = np.mgrid[0:n, 0:n]
            yc, xc = y - c, x - c
            iy = np.clip(np.rint(ct * yc - st * xc + c).astype(int), 0, n - 1)
            ix = np.clip(np.rint(st * yc + ct * xc + c).astype(int), 0, n - 1)
            E = E[iy, ix]
        if any(shift):
            E = np.roll(np.roll(E, shift[0], axis=0), shift[1], axis=1)
        if drift > 0:
            fresh = _field((self.size, self.size), self.grain_px, self.rng)
            E = np.sqrt(1 - drift) * E + np.sqrt(drift) * fresh
        I = np.abs(E) ** 2
        I = I / I.mean() * gain
        out = I[None, ...] + self.rng.normal(0, shot, (frames,) + I.shape)
        return puf.prepare(out)


def _reproduces(img, helper, key) -> bool:
    try:
        return puf.reproduce(img, helper) == key
    except puf.PufError:
        return False


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

    # -- the code against something that is not itself -------------------
    # Dimensions of primitive BCH codes are tabulated in the coding
    # literature (Lin & Costello, appendix C) and do not come from anything
    # here. Three lengths, so a mistake in the generator would have to be a
    # mistake that happens to be right 47 times.
    TABLES = {
        6: {1: 57, 2: 51, 3: 45, 4: 39, 5: 36, 6: 30, 7: 24, 10: 18, 11: 16,
            13: 10, 15: 7},
        8: {1: 247, 2: 239, 3: 231, 4: 223, 5: 215, 6: 207, 7: 199, 8: 191,
            9: 187, 10: 179, 11: 171, 12: 163, 13: 155, 14: 147, 15: 139,
            18: 131, 19: 123, 21: 115, 22: 107, 23: 99, 25: 91, 26: 87,
            27: 79, 29: 71, 30: 63, 31: 55},
        9: {1: 502, 2: 493, 3: 484, 4: 475, 5: 466, 6: 457, 7: 448, 8: 439,
            9: 430, 10: 421},
    }
    wrong = [(m, t) for m, tab in TABLES.items() for t, k in tab.items()
             if puf.BCH(m, t).k != k]
    n_par = sum(len(v) for v in TABLES.values())
    checks.append((f"dimensions match published BCH tables "
                   f"({n_par - len(wrong)}/{n_par})", not wrong))

    # And the two algebraic facts that define the code: the designed roots
    # really are roots of the generator, and the generator really divides
    # x^n - 1. Either failing means the thing is not a BCH code at all.
    alg = True
    for m, t in ((8, 10), (12, 180), (6, 3)):
        c = puf.BCH(m, t)
        for i in range(1, 2 * t + 1):
            v = 0
            for j, coef in enumerate(c.g):
                if coef:
                    v ^= c.gf.exp[(i * j) % c.gf.n]
            if v:
                alg = False
        poly = np.zeros(c.n + 1, dtype=np.uint8)
        poly[0] = poly[c.n] = 1
        r, dg = poly.copy(), len(c.g) - 1
        for i in range(len(r) - 1, dg - 1, -1):
            if r[i]:
                r[i - dg:i + 1] ^= c.g
        if r[:dg].any():
            alg = False
    checks.append(("designed roots are roots, and g divides x^n - 1", alg))

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
        for _ in range(2):
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
        for _ in range(5):
            try:
                again += puf.reproduce(ch.read(), helper) == key
            except puf.PufError:
                pass
        checks.append((f"reproduces on a quiet chamber ({again}/5)",
                       again == 5))

        drifted = 0
        for _ in range(5):
            try:
                drifted += puf.reproduce(ch.read(drift=0.02), helper) == key
            except puf.PufError:
                pass
        checks.append((f"survives 2% drift ({drifted}/5)", drifted == 5))

        # Tamper. Opening the case replaces the field outright.
        opened = Chamber(rng=np.random.default_rng(99))
        leaked = 0
        for _ in range(4):
            try:
                if puf.reproduce(opened.read(), helper) == key:
                    leaked += 1
            except puf.PufError:
                pass
        checks.append(("a swapped chamber never yields the key", leaked == 0))

        # Partial disturbance must also fail rather than half-work.
        big = 0
        for _ in range(4):
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
            for _ in range(2):
                try:
                    got += puf.reproduce(ch.read(shift=(px, 0)), helper) == key
                except puf.PufError:
                    pass
            moved[px] = got
        checks.append((f"survives translation up to 16 px "
                       f"({'/'.join(str(moved[p]) for p in (0, 2, 4, 8, 16))} of 2)",
                       all(v == 2 for v in moved.values())))

        diag = 0
        for _ in range(2):
            try:
                diag += puf.reproduce(ch.read(shift=(9, -7)), helper) == key
            except puf.PufError:
                pass
        checks.append(("survives a diagonal shift", diag == 2))

        checks.append(("registration finds the shift it was given",
                       puf.estimate_shift(ch.read(shift=(6, -3)),
                                          helper.fiducial) == (6, -3)))

        # Rotation. A mount that twists rather than slides is the same
        # failure and one fiducial cannot see it -- a twist and a slide look
        # identical from a single patch. Two, along a known baseline, separate
        # them. Half a degree is ~3 px at the edge of this field, which was
        # enough to lose the key before this existed.
        turned = {}
        for deg in (0.0, 0.5, 1.0, 2.0, 3.0):
            got = 0
            for _ in range(2):
                try:
                    got += puf.reproduce(ch.read(rot_deg=deg), helper) == key
                except puf.PufError:
                    pass
            turned[deg] = got
        checks.append((f"survives rotation to 3 deg "
                       f"({'/'.join(str(turned[d]) for d in turned)} of 2)",
                       all(v == 2 for v in turned.values())))

        est = np.rad2deg(puf.estimate_rotation(ch.read(rot_deg=2.0), helper))
        checks.append((f"rotation is measured, not just tolerated "
                       f"(got {est:.2f} deg)", 1.6 < est < 2.4))

        checks.append(("a twist and a slide together still resolve",
                       _reproduces(ch.read(rot_deg=1.0, shift=(9, -7)),
                                   helper, key)))

        # Translation must not become a way to pass with the wrong chamber:
        # the search is over shifts, not over diffusers.
        slid = 0
        for _ in range(3):
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
        bits0, _ = puf.bits_from_image(enrol[0], fid_b=helper.fid_b)
        chosen = bits0[helper.mask]
        bias = float(chosen.mean())
        checks.append((f"selected bits are not biased (got {bias:.3f})",
                       0.40 < bias < 0.60))

        # Raw intensity is exponential, so an untransformed margin selects the
        # bright tail and the bits come out ~80% ones. The quantile transform
        # is what stops that, and this is the check that notices if it goes.
        gw = ch.size // ch.grain_px
        chosen_set = set(int(i) for i in helper.mask)
        # BOTH axes. `_spaced` excludes vertical neighbours as well, and
        # checking only i+1 left half of what it enforces untested -- a
        # regression that admitted the grain directly below would have read
        # PASS.
        touching = sum(1 for i in chosen_set
                       if ((i + 1) in chosen_set and (i + 1) % gw != 0)
                       or (i + gw) in chosen_set)
        checks.append((f"no two key bits are adjacent grains ({touching})",
                       touching == 0))

        # MIN-entropy, not Shannon. The helper's n-k disclosure has to be paid
        # out of the attacker's best single guess, and the two part company
        # exactly where it matters: this selection is 0.99 bits of Shannon and
        # 0.79 of min-entropy. Asserting the first would have passed while
        # claiming roughly 800 bits that do not exist.
        h_min = puf.min_entropy(chosen)
        code = puf.BCH(m, t)
        residual = code.n * h_min - (code.n - code.k)
        checks.append((f"min-entropy per selected bit stays high "
                       f"({h_min:.3f})", h_min > 0.65))
        checks.append((f"residual MIN-entropy clears a 256-bit key "
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
