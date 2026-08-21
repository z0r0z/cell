"""CELL hardware drivers — the concrete sensor heads.

blood_gate.SensorHead and touch_gate.TouchSensor are abstract so the gate logic
can be replayed against recorded data. This file is the real implementation.

    UNTESTED ON HARDWARE. Everything else in this repo self-tests; this cannot,
    because it needs the parts. Treat it as a wiring diagram in Python, and
    verify each piece against the checks marked VERIFY below before trusting a
    single measurement.

Install:
    pip install adafruit-circuitpython-as7341 picamera2 numpy

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

    def __init__(self):
        import board, busio, digitalio            # noqa: E401
        import adafruit_as7341
        from picamera2 import Picamera2

        self._i2c = busio.I2C(board.SCL, board.SDA)
        self.spec = adafruit_as7341.AS7341(self._i2c)

        # VERIFY: pick ATIME/ASTEP so the 630/680 channels land at 40-70% of
        # full scale on a white patch. The 415 channel WILL sit near zero on
        # blood — that is expected and handled by the clamp in blood_gate.
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
            raise RuntimeError("laser interlock: no cartridge seated")
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
        with self._exclusive(white=True, ir=True):
            return self._channels()

    def read_white_reference(self):
        # The cartridge's own printed white patch. Positioning is mechanical:
        # the patch sits under the aperture when the cartridge is fully seated.
        with self._exclusive(white=True, ir=True):
            return self._channels()

    def read_dark(self):
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

    def close(self):
        self.cam.stop()


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
        gate can tell a fingertip from an open port. Capture at provisioning
        and store it; re-measuring with a finger present defeats the point."""
        with self.h._exclusive(white=True):
            r = float(self.h.spec.channel_630nm)
        with self.h._exclusive(ir=True):
            n = float(self.h.spec.channel_nir)
        return r, n


if __name__ == "__main__":
    print(__doc__)
    print("Bring-up order — do not skip:")
    for i, step in enumerate([
        "i2cdetect finds the AS7341 at 0x39",
        "White LEDs on: 630/680 channels land at 40-70% of full scale on a white card",
        "LEDs off: all channels at the dark floor. If not, the chamber leaks light",
        "Laser on with a cartridge seated: camera sees speckle, contrast K > 0.3",
        "Autocorrelate one frame: central peak spans 3-5 px",
        "Confirm the achieved PPG sample rate is stable at the configured fs",
        "Only then run: calibrate.py capture --label genuine",
    ], 1):
        print(f"  {i}. {step}")
