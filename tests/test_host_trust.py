import base64
import hashlib
import subprocess

import pytest

from timecapsulesmb.services import host_trust as trust_host
from timecapsulesmb.transport import ssh


def key(seed):
    raw = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes([seed]) * 32
    encoded = base64.b64encode(raw).decode()
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return encoded, fingerprint


def test_enrollment_matches_verified_fingerprint_and_refuses_rotation(tmp_path, monkeypatch):
    known = tmp_path / "known_hosts"
    monkeypatch.setattr(trust_host, "known_hosts_path", lambda: known)
    original_run = subprocess.run
    encoded, fingerprint = key(1)
    offered = encoded

    def run(command, **kwargs):
        if command[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(command, 0, f"device ssh-ed25519 {offered}\n", "")
        return original_run(command, **kwargs)

    monkeypatch.setattr(trust_host.subprocess, "run", run)
    with pytest.raises(ValueError, match="did not present"):
        trust_host.enroll("root@device", key(2)[1])
    assert not known.exists()
    trust_host.enroll("root@device", fingerprint)
    expected = known.read_bytes()
    trust_host.enroll("root@device", fingerprint)
    assert known.read_bytes() == expected
    assert known.stat().st_mode & 0o777 == 0o600
    offered, replacement = key(2)
    with pytest.raises(ValueError, match="different key"):
        trust_host.enroll("root@device", replacement)
    assert known.read_bytes() == expected


def test_openssh_effective_policy_overrides_legacy_bypasses():
    connection = ssh.SshConnection("root@device", "password", "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
    result = subprocess.run(["ssh", "-G", *ssh._connection_ssh_args(connection), connection.host], capture_output=True, text=True, check=True)
    config = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    assert config["stricthostkeychecking"] == "true"
    assert config["userknownhostsfile"] == str(ssh.known_hosts_path())
    assert config["verifyhostkeydns"] == "false"
    assert config["updatehostkeys"] == "false"


@pytest.mark.parametrize("message", ["Host key verification failed.", "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "No RSA host key is known and you have requested strict checking."])
def test_key_failures_are_reported_as_trust_errors(message):
    assert isinstance(ssh.classify_ssh_client_error(message), ssh.SshClientConfigError)
