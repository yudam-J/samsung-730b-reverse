#!/usr/bin/env python3
"""Finger-detect heuristic against the checked-in Samsung 730B captures.

A 6-packet probe is what wait_finger() actually inspects: the 2-byte
status from packet 0 plus five 256-byte image packets. none/half/default
raws are 21506 bytes and already include that status prefix. capture.raw
is the post-fix 21504-byte image with the status discarded, so the probe
is reconstructed by prefixing two zero status bytes.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# The driver imports pyusb at module level. The heuristic does not need a device.
for _name in ("usb", "usb.core", "usb.util"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

from samsung_730b import Samsung730B

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample"
PROBE = 2 + 5 * 256  # status + packets 1..5


def probe(name: str) -> bytes:
    data = (SAMPLE / f"{name}.raw").read_bytes()
    if name == "capture":
        # capture() drops the 2-byte status. detect() keeps it.
        data = b"\x00\x00" + data
    return data[:PROBE]


def main() -> int:
    sensor = Samsung730B(debug=False)
    cases = {
        "none": False,
        "half": True,
        "default": True,
        "capture": True,
    }
    failed = 0
    windows = {
        "probe": lambda blob: blob,
        # Shortest buffer the heuristic will score. half is closest to the
        # 0xFF cutoff here (ff ~0.084), none is closest to the zero cutoff (0.914).
        "min512": lambda blob: blob[:512],
    }
    for name, expect in cases.items():
        raw = probe(name)
        for label, take in windows.items():
            blob = take(raw)
            got = sensor._has_fingerprint_in_detect(blob)
            zeros = blob.count(0) / len(blob)
            ff = blob.count(0xFF) / len(blob)
            mark = "ok" if got is expect else "FAIL"
            if got is not expect:
                failed += 1
            print(
                f"{mark:4} {name:8} {label:6} expect={expect!s:5} got={got!s:5} "
                f"n={len(blob)} zero={zeros:.3f} ff={ff:.3f}"
            )

    # Idle frame and a truncated probe must not count as a finger.
    extras = [
        ("zeros", bytes(4096), False),
        ("short", bytes(100), False),
        ("saturated", bytes([0xFF]) * 512, True),
    ]
    for name, blob, expect in extras:
        got = sensor._has_fingerprint_in_detect(blob)
        mark = "ok" if got is expect else "FAIL"
        if got is not expect:
            failed += 1
        print(f"{mark:4} {name:8} expect={expect!s:5} got={got!s:5} n={len(blob)}")

    if failed:
        print(f"{failed} case(s) failed")
        return 1
    print("finger detect ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
