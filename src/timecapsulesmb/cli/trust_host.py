"""Enroll a device key only after an independently verified fingerprint matches."""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import re
import subprocess

from timecapsulesmb.core.config import validate_ssh_target
from timecapsulesmb.transport.ssh import known_hosts_path
from timecapsulesmb.core.net import parse_endpoint


def enroll(host: str, fingerprint: str, *, port: int = 22) -> None:
    target = host if "@" in host else "root@" + host
    error = validate_ssh_target(target, "host")
    if error:
        raise ValueError(error)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise ValueError("provide the verified SHA256 fingerprint from a trusted source")
    hostname = parse_endpoint(target).host
    label = hostname if port == 22 else f"[{hostname}]:{port}"
    result = subprocess.run(
        ["ssh-keyscan", "-T", "5", "-p", str(port), "-t", "rsa,ecdsa,ed25519", hostname],
        capture_output=True, text=True, check=False, timeout=20,
    )
    matched = None
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0].startswith("#"):
            continue
        try:
            raw = base64.b64decode(fields[2], validate=True)
        except ValueError:
            continue
        digest = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        if digest == fingerprint:
            matched = f"{label} {fields[1]} {fields[2]}\n"
            break
    if matched is None:
        raise ValueError("the device did not present the verified fingerprint; no key was saved")
    path = known_hosts_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("refusing to modify a symlinked known_hosts file")
    with path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        existing = subprocess.run(
            ["ssh-keygen", "-F", label, "-f", str(path)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        keys = [line.split()[1:3] for line in existing.stdout.splitlines() if line and not line.startswith("#")]
        if matched.split()[1:3] in keys:
            return
        if keys or existing.returncode not in (0, 1):
            raise ValueError("a different key is already trusted; verify and rotate it explicitly with ssh-keygen")
        stream.seek(0)
        content = stream.read()
        if content and not content.endswith("\n"):
            stream.write("\n")
        stream.write(matched)
        stream.flush()
        path.chmod(0o600)


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
