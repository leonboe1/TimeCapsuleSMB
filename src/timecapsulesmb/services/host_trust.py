"""Read SSH fingerprints and explicitly enroll a verified device identity."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

from timecapsulesmb.core.config import DEFAULTS, validate_ssh_target
from timecapsulesmb.core.net import parse_endpoint
from timecapsulesmb.transport.ssh import known_hosts_path, _normalize_ssh_tokens


def _scan_key_lines(hostname: str, *, port: int = 22) -> list[str]:
    result = subprocess.run(
        ["ssh-keyscan", "-T", "5", "-p", str(port), "-t", "rsa,ecdsa,ed25519", hostname],
        capture_output=True, text=True, check=False, timeout=20,
    )
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith("#")]
    if lines:
        return lines
    # ssh-keyscan cannot opt into legacy KEX/MAC algorithms. Obtain the candidate
    # with the normal client's compatibility options in a disposable trust store.
    # No credentials, commands, forwards, user SSH config, or real trust-store writes.
    with tempfile.TemporaryDirectory(prefix="tcapsule-host-scan-") as directory:
        candidate_path = Path(directory) / "known_hosts"
        options = {
            "StrictHostKeyChecking": "accept-new",
            "UserKnownHostsFile": shlex.quote(str(candidate_path)),
            "GlobalKnownHostsFile": "/dev/null",
            "KnownHostsCommand": "none", "VerifyHostKeyDNS": "no", "UpdateHostKeys": "no",
            "HashKnownHosts": "no", "CheckHostIP": "no",
            "BatchMode": "yes", "PreferredAuthentications": "none",
            "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
            "PubkeyAuthentication": "no", "HostbasedAuthentication": "no",
            "GSSAPIAuthentication": "no", "IdentityAgent": "none",
            "ControlMaster": "no", "ControlPath": "none", "ClearAllForwardings": "yes",
            "ConnectTimeout": "5", "ConnectionAttempts": "1",
        }
        arguments = [item for key, value in options.items() for item in ("-o", f"{key}={value}")]
        try:
            subprocess.run(
                ["ssh", "-F", "/dev/null", "-N", "-p", str(port), *arguments,
                 *_normalize_ssh_tokens(DEFAULTS["TC_SSH_OPTS"]), f"root@{hostname}"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=15,
            )
        except subprocess.TimeoutExpired:
            # A server accepting unauthenticated sessions can keep -N open.
            # subprocess.run kills and reaps it; only the candidate key is needed.
            pass
        return candidate_path.read_text().splitlines() if candidate_path.is_file() else []


def scan_untrusted_fingerprint(host: str) -> str:
    """Read a candidate without credentials. Never offer to replace a trusted key."""
    error = validate_ssh_target(host, "host")
    if error:
        raise ValueError(error)
    hostname = parse_endpoint(host).host
    path = known_hosts_path()
    if path.is_symlink():
        raise ValueError("refusing a symlinked known_hosts file")
    if path.exists():
        existing = subprocess.run(
            ["ssh-keygen", "-F", hostname, "-f", str(path)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if existing.returncode != 1 or existing.stdout.strip():
            raise ValueError(
                "An SSH key is already trusted for this address, but identity verification failed. "
                "Check that this is the same device and address. The app will not replace an existing key."
            )
    lines = _scan_key_lines(hostname)
    candidates = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 3 or fields[1] not in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"):
            continue
        try:
            raw = base64.b64decode(fields[2], validate=True)
        except ValueError:
            continue
        # Check that the blob identifies the same algorithm as the scan line.
        name = fields[1].encode()
        if not raw.startswith(len(name).to_bytes(4, "big") + name):
            continue
        candidates[fields[1]] = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    for algorithm in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"):
        if algorithm in candidates:
            return candidates[algorithm]
    raise ValueError("No SSH host key could be read. Check the device address and retry Save Device.")


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
    lines = _scan_key_lines(hostname, port=port)
    matched = None
    for line in lines:
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

