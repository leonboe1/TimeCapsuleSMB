"""Enroll a device key only after an independently verified fingerprint matches."""
from __future__ import annotations

import argparse
import subprocess

from timecapsulesmb.services.host_trust import enroll

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="device hostname or IP address, optionally prefixed by root@")
    parser.add_argument("--fingerprint", required=True, help="SHA256 fingerprint verified independently")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args(argv)
    try:
        enroll(args.host, args.fingerprint, port=args.port)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Could not trust device: {exc}")
        return 1
    print("Verified device key saved to known_hosts.")
    return 0
