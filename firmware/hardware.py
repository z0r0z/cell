"""CELL hardware drivers — the concrete sensor heads.

blood_gate.SensorHead and touch_gate.TouchSensor are abstract so the gate logic
can be replayed against recorded data. This file is the real implementation.

    UNTESTED ON HARDWARE. Everything else in this repo self-tests; this cannot,
    because it needs the parts. Treat it as a wiring diagram in Python, and
    verify each piece against the checks marked VERIFY below before trusting a
    single measurement.

Install:
    pip install adafruit-circuitpython-as7341 picamera2 numpy

The cartridge reads at TWO STOPS, in this order. Push to the
first click and the printed white patch is under the aperture: that is where
read_white_reference() and read_dark() must happen. Push past the detent to the
second stop and the well is under the aperture, for the sample and the speckle
series. Every gate normalises against the patch, so a white reference taken at
the wrong stop reads the sample against itself, absorbance collapses to zero,
and the device rejects genuine blood at G1 while reporting "far too bright".

Sequencing rule that matters more than any other line here: THE TWO OPTICAL
PATHS MUST NEVER RUN AT ONCE. The laser contaminates the 630 nm channel and the
white LEDs wash out the speckle. Every method below leaves its illumination OFF
on exit, and _exclusive() enforces it.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Optional

import numpy as np

from blood_gate import SensorHead
from touch_gate import TouchSensor

# GPIO, BCM numbering. Must match BUILD.md, Wiring.
PIN_LED2 = 12       # second white LED, 2N7002 + 68R
PIN_IR = 23         # 940 nm, 2N7002 + 47R
PIN_LASER = 6       # 650 nm, interlocked to the cartridge switch
PIN_CARTRIDGE = 22  # microswitch, pull-up, LOW when a cartridge is seated

SPECKLE_ROI = 128   # px, square
SPECKLE_FRAMES = 16
# The chamber PUF reads a wider field than the blood path does. Blood needs
# only enough grains to average a correlation over; the PUF spends grains on
# key material, on the margin filter that discards the unreliable ones, and on
# a rule that no two key bits come from touching grains -- adjacent grains
# share the tail of one speckle lobe. Same sensor, same optics, a larger crop
# -- see read_chamber_burst.
PUF_ROI = 768
PUF_FRAMES = 16
SPECKLE_EXPOSURE_US = 2000   # <=2 ms so each frame samples the field, not a time-average

# AS7341 integration = (ATIME+1) * (ASTEP+1) * 2.78 us.
#
# CHEMISTRY: long integration, best SNR. 101 * 1000 * 2.78us = 281 ms.
# Fine — the chemistry read happens once.
ATIME_CHEM, ASTEP_CHEM = 100, 999
#
# PPG: the same config CANNOT be used. Touch mode needs two reads per sample at
# 50 Hz, i.e. a 20 ms budget for both; 281 ms per channel misses it by more
# than an order of magnitude, and the resulting capture is analysed at the
# nominal rate and reports a heart rate ~6x too low. 1 * 1000 * 2.78us = 2.8 ms
# per channel leaves room for I2C overhead and LED settling inside the budget.
ATIME_PPG, ASTEP_PPG = 0, 999
#
# Source settling. The 60 ms used for chemistry is dominated by letting the
# long integration flush; the LEDs themselves are stable in microseconds. PPG
# alternates channels every few ms and cannot afford it.
SETTLE_CHEM_S = 0.06
SETTLE_PPG_S = 0.002


class RealSensorHead(SensorHead):
    """Blood tier: AS7341 chemistry + laser/camera speckle."""

    def __init__(self, prompt=None):
        """`prompt(text)` blocks until the operator has done what it says.

        Injected so the device build can drive the ST7789 and the CONFIRM
        button, while a bring-up session on a laptop gets input(). It is a
        constructor argument rather than a hardcoded input() because a device
        that blocks on stdin with no terminal attached hangs forever.
        """
        self._prompt = prompt or (lambda msg: input(msg + " [Enter] "))
        import board, busio, digitalio            # noqa: E401
        import adafruit_as7341
        from picamera2 import Picamera2

        self._i2c = busio.I2C(board.SCL, board.SDA)
        self.spec = adafruit_as7341.AS7341(self._i2c)

        # VERIFY: pick ATIME/ASTEP so the 630/680 channels land at 40-70% of
        # full scale on a white patch. The 415 channel WILL sit near zero on
        # blood — that is expected and handled by the clamp in blood_gate.
        #
        # AND VERIFY THE NOISE FLOOR, which the fill level above does not
        # constrain. robustness.py bisects it: G4 is the gate with the least
        # slack in the whole design, and it gives way once read noise reaches
        # ~0.1% of full scale. That is a property of the DARK channels — on
        # blood, 445 nm sits at a few hundred counts, so absolute noise there
        # dominates the spectral shape long before it troubles 630/680.
        # Measure it: 100 reads of a static target, and take the standard
        # deviation of the 445 channel. If it is above ~65 counts, raise the
        # integration time or average more reads before trusting a spectrum.
        self._set_integration(ATIME_CHEM, ASTEP_CHEM)
        self.spec.gain = 8

        def _out(pin):
            d = digitalio.DigitalInOut(pin)
            d.direction = digitalio.Direction.OUTPUT
            d.value = False
            return d

        self.led2 = _out(getattr(board, f"D{PIN_LED2}"))
        self.ir = _out(getattr(board, f"D{PIN_IR}"))
        self.laser = _out(getattr(board, f"D{PIN_LASER}"))

        self.cart = digitalio.DigitalInOut(getattr(board, f"D{PIN_CARTRIDGE}"))
        self.cart.direction = digitalio.Direction.INPUT
        self.cart.pull = digitalio.Pull.UP

        self.cam = Picamera2()
        cfg = self.cam.create_still_configuration(
            main={"size": (SPECKLE_ROI, SPECKLE_ROI), "format": "YUV420"},
            controls={
                # Fixed everything. Any auto-adjustment between frames destroys
                # the correlation measurement and produces confident garbage.
                "ExposureTime": SPECKLE_EXPOSURE_US,
                "AnalogueGain": 1.0,
                "AeEnable": False,
                "AwbEnable": False,
                "NoiseReductionMode": 0,
            })
        self.cam.configure(cfg)
        self.cam.start()
        time.sleep(0.5)

    # -- illumination ------------------------------------------------------

    def _set_integration(self, atime: int, astep: int) -> float:
        """Set integration time and return it in seconds."""
        self.spec.atime = atime
        self.spec.astep = astep
        return (atime + 1) * (astep + 1) * 2.78e-6

    @contextmanager
    def _exclusive(self, *, white: bool = False, ir: bool = False,
                   laser: bool = False, settle_s: float = SETTLE_CHEM_S):
        """Own the chamber for the duration. Nothing else may be lit."""
        if laser and self.cartridge_present() is False:
            # Mirrors an interlock that is wired in HARDWARE -- BUILD.md 11
            # puts the switch contacts in series with the laser module's
            # supply, where firmware cannot talk past them. This check only
            # turns a silent dark frame into a sentence. It fires for the
            # chamber PUF read too, which is why a chamber-enrolled device
            # needs something in the slot at every unlock: see BUILD.md 9.
            raise RuntimeError(
                "laser interlock: the cartridge bay is open, so the diode is "
                "unpowered. Seat a cartridge (a spare or cartridge_null will "
                "do) and try again")
        try:
            self.spec.led = white          # AS7341 drives white LED #1 on its LDR pin
            self.led2.value = white
            self.ir.value = ir
            self.laser.value = laser
            time.sleep(settle_s)           # let the sources settle
            yield
        finally:
            self.spec.led = False
            self.led2.value = False
            self.ir.value = False
            self.laser.value = False

    def cartridge_present(self) -> bool:
        return not self.cart.value        # pull-up, LOW when seated

    # -- spectrometer ------------------------------------------------------

    def _channels(self) -> tuple[np.ndarray, float, float]:
        f8 = np.array([
            self.spec.channel_415nm, self.spec.channel_445nm,
            self.spec.channel_480nm, self.spec.channel_515nm,
            self.spec.channel_555nm, self.spec.channel_590nm,
            self.spec.channel_630nm, self.spec.channel_680nm], dtype=float)
        # VERIFY these attribute names against your adafruit_as7341 version;
        # Clear and NIR have been renamed across releases.
        return f8, float(self.spec.channel_clear), float(self.spec.channel_nir)

    def read_channels(self):
        """The sample. Requires the cartridge at the SECOND stop.

        The microswitch closes only when the cartridge is fully seated, so this
        is checked rather than assumed — reading the sample at stop 1 would
        measure the white patch and call it blood.
        """
        self._await_seated()
        with self._exclusive(white=True, ir=True):
            return self._channels()

    def await_sample_position(self):
        """The SensorHead hook blood_gate.acquire() calls between the two
        reads. Same check as the sample read makes, done once, before any
        timing starts."""
        self._await_seated()

    def _await_seated(self):
        if not self.cartridge_present():
            self._prompt("Push the cartridge past the detent to the second stop.")
        if not self.cartridge_present():
            raise RuntimeError(
                "cartridge is not fully seated — the well is not under the "
                "aperture and any reading would be of the white patch")

    def read_white_reference(self):
        """The cartridge's own printed white patch, at the FIRST stop.

        This is what cancels LED aging, photodiode drift and print variation,
        and it is read from the same part, in the same layer, seconds before
        the sample. It cannot be read at the second stop: at that depth the
        well is under the aperture and the patch is 7.5 mm past it.
        """
        if self.cartridge_present():
            raise RuntimeError(
                "cartridge is already at the second stop — withdraw it to the "
                "first click, or the white reference will be a reading of the "
                "sample against itself")
        with self._exclusive(white=True, ir=True):
            return self._channels()

    def read_dark(self):
        # Same position as the white reference, LEDs off. Taken at stop 1 for
        # exactly that reason — see blood_gate.SensorHead.read_dark.
        with self._exclusive():            # everything off
            return self._channels()

    # -- speckle -----------------------------------------------------------

    def read_speckle_burst(self) -> np.ndarray:
        """SPECKLE_FRAMES frames under laser illumination, luma only.

        VERIFY once, before any calibration run: take the 2-D autocorrelation of
        a single frame. The central peak must span 3-5 px. Narrower means the
        speckle is undersampled and D will read low no matter what the sample
        does; broader means you are imaging something that is not speckle.
        """
        frames = np.empty((SPECKLE_FRAMES, SPECKLE_ROI, SPECKLE_ROI), dtype=np.float32)
        with self._exclusive(laser=True):
            for i in range(SPECKLE_FRAMES):
                frames[i] = self.cam.capture_array("main")[:SPECKLE_ROI, :SPECKLE_ROI]
        return frames

    # -- the chamber itself ------------------------------------------------

    def read_chamber_burst(self) -> np.ndarray:
        """PUF_FRAMES frames of the diffuser, for optical_puf.

        This measures the INSTRUMENT, not a sample. The diffuser is epoxied
        into the chamber at build time and its speckle is a property of the
        assembly, so opening the case changes the answer and the seed does not
        unwrap. See signer.unwrap_context.

        AVERAGED, unlike the blood burst. There the frames carry the signal --
        how fast the pattern decorrelates IS the measurement, and averaging
        would destroy it. Here the pattern is meant to be static, so the
        frames are repeated looks at one thing and averaging buys shot-noise
        margin. Same rig, opposite treatment; optical_puf.speckle_features
        does the averaging.

        THE LASER INTERLOCK STILL APPLIES. This goes through _exclusive() like
        every other lit path, so the bay must be closed before the diode is
        energised. The diffuser must therefore sit clear of the cartridge's
        optical window, or the reading would depend on which cartridge happens
        to be seated and every cartridge change would look like tampering.
        BUILD.md section 9 places it.
        """
        frames = np.empty((PUF_FRAMES, PUF_ROI, PUF_ROI), dtype=np.float32)
        with self._exclusive(laser=True):
            with self._crop(PUF_ROI):
                for i in range(PUF_FRAMES):
                    frames[i] = self.cam.capture_array("main")[:PUF_ROI, :PUF_ROI]
        return frames

    @contextmanager
    def _crop(self, roi: int):
        """Widen the capture to `roi` px square, then put it back.

        The camera is configured once at start-up for the speckle path and
        left alone, because reconfiguring mid-burst is exactly the kind of
        auto-adjustment the correlation measurement cannot survive. The PUF
        read is not inside a burst, so it may switch modes -- but it must
        switch back, and it must not inherit any auto control on the way.
        """
        if roi == SPECKLE_ROI:
            yield
            return
        cfg = self.cam.create_still_configuration(
            main={"size": (roi, roi), "format": "YUV420"},
            controls={"ExposureTime": SPECKLE_EXPOSURE_US, "AnalogueGain": 1.0,
                      "AeEnable": False, "AwbEnable": False,
                      "NoiseReductionMode": 0})
        self.cam.switch_mode(cfg)
        try:
            yield
        finally:
            self.cam.switch_mode(self.cam.create_still_configuration(
                main={"size": (SPECKLE_ROI, SPECKLE_ROI), "format": "YUV420"},
                controls={"ExposureTime": SPECKLE_EXPOSURE_US,
                          "AnalogueGain": 1.0, "AeEnable": False,
                          "AwbEnable": False, "NoiseReductionMode": 0}))

    def close(self):
        """Release everything, not just the stream.

        Picamera2.stop() stops the stream and keeps the camera ACQUIRED; only
        close() releases it. So a head that was stopped rather than closed
        made the next RealSensorHead() on the same boot fail to open the
        camera -- which, in the signing flow, is the chamber read that follows
        a gate: the owner has already bled, and the advice on screen ("try
        again") would have failed identically until a power cycle.
        """
        try:
            self.cam.close()
        finally:
            for pin in (self.led2, self.ir, self.laser, self.cart):
                try:
                    pin.deinit()
                except Exception:                               # noqa: BLE001
                    pass
            try:
                self._i2c.deinit()
            except Exception:                                   # noqa: BLE001
                pass


class RealTouchSensor(TouchSensor):
    """Touch tier: PPG through the ring bore. Shares the spectrometer head."""

    def __init__(self, head: RealSensorHead):
        self.h = head

    def read_ppg(self, duration_s: float, fs: float):
        """Return (red, ir, fs_achieved) through the ring bore.

        Alternates red and IR within each sample period so both channels see
        the same beat, at the SHORT integration time — the chemistry config is
        281 ms per channel and cannot produce a PPG waveform at any useful
        rate. See ATIME_PPG.

        The achieved rate is measured and returned rather than assumed. If the
        loop cannot keep up, touch_gate rejects the capture at T0 as a hardware
        fault instead of computing a confident wrong heart rate from it.

        VERIFY on first bring-up: run this and check the reported rate is at
        least th.fs_min and stable run to run. If it is not, shorten ATIME
        further or lower the target fs — do not paper over it, the analysis
        uses whatever this returns.
        """
        n = int(duration_s * fs)
        red = np.empty(n)
        ir = np.empty(n)
        period = 1.0 / fs

        prev = (self.h.spec.atime, self.h.spec.astep)
        self.h._set_integration(ATIME_PPG, ASTEP_PPG)
        try:
            t0 = time.monotonic()
            for i in range(n):
                with self.h._exclusive(white=True, settle_s=SETTLE_PPG_S):
                    red[i] = self.h.spec.channel_630nm
                with self.h._exclusive(ir=True, settle_s=SETTLE_PPG_S):
                    ir[i] = self.h.spec.channel_nir
                slack = (i + 1) * period - (time.monotonic() - t0)
                if slack > 0:
                    time.sleep(slack)
            elapsed = time.monotonic() - t0
        finally:
            self.h._set_integration(*prev)

        # n samples span n-1 intervals. Use the measured elapsed time, never
        # the requested rate.
        fs_achieved = (n - 1) / elapsed if elapsed > 0 and n > 1 else 0.0
        return red, ir, fs_achieved

    def read_bore_reference(self) -> tuple[float, float]:
        """Empty bore, LEDs on. Establishes the no-finger level so the contact
        gate can tell a fingertip from an open port.

        Call it with NOTHING on the ring, and before read_ppg rather than
        after. T1 is `mean(red) / bore_red`; a reference measured through the
        finger is a reading of the finger against itself.

        Taken at the PPG integration time, not the chemistry one. The head
        idles at ATIME_CHEM (281 ms per channel) and read_ppg switches to
        ATIME_PPG (2.8 ms) for the duration of the capture. Counts scale with
        integration time, so a reference read at the chemistry setting is
        ~100x the level of the samples it is the denominator for, and T1
        rejects every genuine session as "no finger".
        """
        prev = (self.h.spec.atime, self.h.spec.astep)
        self.h._set_integration(ATIME_PPG, ASTEP_PPG)
        try:
            with self.h._exclusive(white=True, settle_s=SETTLE_PPG_S):
                r = float(self.h.spec.channel_630nm)
            with self.h._exclusive(ir=True, settle_s=SETTLE_PPG_S):
                n = float(self.h.spec.channel_nir)
        finally:
            self.h._set_integration(*prev)
        return r, n


if __name__ == "__main__":
    print(__doc__)
    print("Bring-up order — do not skip:")
    for i, step in enumerate([
        "i2cdetect finds the AS7341 at 0x39",
        "White LEDs on: 630/680 channels land at 40-70% of full scale on a white card",
        "100 reads of a static target: the 445 channel's standard deviation is "
        "under ~65 counts. This is the tightest budget in the design — see "
        "robustness.py",
        "LEDs off: all channels at the dark floor. If not, the chamber leaks light",
        "Laser on with a cartridge seated: camera sees speckle, contrast K > 0.3",
        "Autocorrelate one frame: central peak spans 3-5 px",
        "Confirm the achieved PPG sample rate is stable at the configured fs",
        "Cartridge at stop 1: the clear channel reads HIGH — that is the "
        "white patch. At stop 2 with blood loaded it drops to ~0.15 of it",
        "Only then run: calibrate.py capture --label genuine",
    ], 1):
        print(f"  {i}. {step}")
