"""GUI onboarding using mock transports; never contact or modify a real device."""
from dataclasses import replace
import base64
import hashlib
import json
import subprocess
from unittest.mock import Mock

import pytest

from timecapsulesmb.app import service
from timecapsulesmb.app.ops import configure
from timecapsulesmb.integrations import acp
from timecapsulesmb.services import host_trust
from timecapsulesmb.device.probe import SshAccessStatus
from test_app_api import CollectingSink, probed_state, unreachable_probed_state


def candidate(seed=1):
    blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes([seed]) * 32
    encoded = base64.b64encode(blob).decode()
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return encoded, fingerprint


def untrusted_state():
    state = probed_state()
    return replace(state, compatibility=None, probe_result=replace(
        state.probe_result, ssh_status=SshAccessStatus.TRANSPORT_FAILED,
        error="SSH host identity verification failed.", host_identity_failed=True,
    ))


@pytest.fixture
def isolated_transport(tmp_path, monkeypatch):
    monkeypatch.delenv("TCAPSULE_ALLOW_INSECURE_ACP", raising=False)
    known = tmp_path / "known_hosts"
    monkeypatch.setattr(host_trust, "known_hosts_path", lambda: known)
    real_run = subprocess.run
    offered = [candidate()[0]]

    def run(command, **kwargs):
        if command[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(command, 0, f"device ssh-ed25519 {offered[0]}\n", "")
        return real_run(command, **kwargs)

    monkeypatch.setattr(host_trust.subprocess, "run", run)
    return known, offered


def request(params):
    collector = CollectingSink()
    rc = service.run_api_request({"operation": "configure", "params": params}, collector.sink)
    assert "private-password" not in json.dumps(collector.events)
    return rc, collector


def confirmation(collector):
    error = collector.events_of_type("error")[-1]
    assert error["code"] == "confirmation_required"
    return error["details"]


def test_gui_enable_then_trust_then_save_without_environment_override(tmp_path, monkeypatch, isolated_transport):
    known, _ = isolated_transport
    params = {"config": str(tmp_path / ".env"), "host": "root@10.0.0.2", "password": "private-password"}
    probe = Mock(return_value=unreachable_probed_state())
    monkeypatch.setattr(configure, "probe_connection_state", probe)
    from timecapsulesmb.services import acp_ssh
    monkeypatch.setattr(acp_ssh, "tcp_connect_error", lambda *args: None)
    monkeypatch.setattr(configure.configure_service, "wait_for_tcp_port_state", lambda *args, **kwargs: True)
    # Exercise the real enable_ssh, set_property_int and ACP security gate.
    socket = Mock()
    monkeypatch.setattr(acp, "_open_connection", lambda *args, **kwargs: socket)
    monkeypatch.setattr(acp, "_read_reply_header", lambda *args, **kwargs: object())
    monkeypatch.setattr(acp, "_read_property_results", lambda *args: None)
    monkeypatch.setattr(acp, "_read_property_result", lambda *args: None)

    rc, first = request(params)
    assert rc == 1
    approval = confirmation(first)
    assert approval["presentation_id"] == "ssh_setup.enable_legacy"
    assert "recoverable administrator password" in approval["message"]
    socket.sendall.assert_not_called()
    assert not known.exists()

    params["confirmation_id"] = approval["confirmation_id"]
    probe.side_effect = [unreachable_probed_state(), untrusted_state()]
    rc, second = request(params)
    assert rc == 1
    assert socket.sendall.call_count == 2  # SSH enable + reboot only.
    approval = confirmation(second)
    assert approval["presentation_id"] == "ssh_setup.trust_host"
    assert candidate()[1] in approval["message"]
    assert not known.exists()
    assert not (tmp_path / ".env").exists()
    assert acp._ssh_setup_host.get() is None

    params["confirmation_id"] = approval["confirmation_id"]
    probe.side_effect = [untrusted_state(), probed_state()]
    rc, third = request(params)
    assert rc == 0, third.events
    assert known.exists()
    assert (tmp_path / ".env").exists()
    assert "private-password" not in (tmp_path / ".env").read_text()
    assert socket.sendall.call_count == 2
    assert acp._ssh_setup_host.get() is None


def test_gui_changed_candidate_invalidates_approval(tmp_path, monkeypatch, isolated_transport):
    known, offered = isolated_transport
    params = {"config": str(tmp_path / ".env"), "host": "root@10.0.0.2", "password": "private-password"}
    monkeypatch.setattr(configure, "probe_connection_state", lambda connection: untrusted_state())
    _, first = request(params)
    old = confirmation(first)
    params["confirmation_id"] = old["confirmation_id"]
    offered[0] = candidate(2)[0]
    _, second = request(params)
    new = confirmation(second)
    assert new["confirmation_id"] != old["confirmation_id"]
    assert candidate(2)[1] in new["message"]
    assert not known.exists()
    assert not (tmp_path / ".env").exists()


def test_gui_never_offers_to_replace_existing_identity(tmp_path, monkeypatch, isolated_transport):
    known, _ = isolated_transport
    known.write_text(f"10.0.0.2 ssh-ed25519 {candidate(2)[0]}\n")
    before = known.read_bytes()
    monkeypatch.setattr(configure, "probe_connection_state", lambda connection: untrusted_state())
    rc, collector = request({"config": str(tmp_path / ".env"), "host": "root@10.0.0.2", "password": "private-password"})
    assert rc == 1
    assert collector.events_of_type("error")[-1]["code"] == "host_identity_failed"
    assert known.read_bytes() == before
    assert not (tmp_path / ".env").exists()


def test_key_change_during_enrollment_saves_nothing(isolated_transport):
    known, offered = isolated_transport
    fingerprint = host_trust.scan_untrusted_fingerprint("root@10.0.0.2")
    offered[0] = candidate(2)[0]
    with pytest.raises(ValueError, match="did not present"):
        host_trust.enroll("root@10.0.0.2", fingerprint)
    assert not known.exists()


def test_strict_identity_error_survives_device_probe(monkeypatch):
    from timecapsulesmb.device import probe
    from timecapsulesmb.transport.ssh import SshConnection, classify_ssh_client_error
    error = classify_ssh_client_error("Host key verification failed.")
    monkeypatch.setattr(probe, "tcp_open", lambda *args: True)
    monkeypatch.setattr(probe, "_probe_remote_os_info_conn", Mock(side_effect=error))
    result = probe.probe_device_conn(SshConnection("root@device", "private-password", ""))
    assert result.host_identity_failed
    assert result.ssh_status == SshAccessStatus.TRANSPORT_FAILED


def test_legacy_scan_never_authenticates_or_writes_real_trust_store(isolated_transport, monkeypatch):
    known, _ = isolated_transport
    real_run = subprocess.run
    scanned_files = []

    def run(command, **kwargs):
        if command[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(command, 1, "", "no matching key exchange method")
        if command[0] == "ssh" and "-N" in command:
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert "-F" in command and "/dev/null" in command
            effective = real_run([command[0], "-G", *command[1:]], capture_output=True, text=True, check=True)
            config = dict(line.split(" ", 1) for line in effective.stdout.splitlines())
            assert config["stricthostkeychecking"] == "accept-new"
            assert config["preferredauthentications"] == "none"
            for option in ("passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "hostbasedauthentication", "gssapiauthentication"):
                assert config[option] in ("no", "false")
            assert config.get("controlpath", "none") == "none"
            assert config["controlmaster"] in ("no", "false")
            assert config["clearallforwardings"] in ("yes", "true")
            assert "diffie-hellman-group14-sha1" in config["kexalgorithms"]
            from pathlib import Path
            path = Path(config["userknownhostsfile"])
            assert path != known
            scanned_files.append(path)
            path.write_text(f"10.0.0.2 ssh-ed25519 {candidate()[0]}\n")
            return subprocess.CompletedProcess(command, 255, "", "Permission denied.")
        return real_run(command, **kwargs)

    monkeypatch.setattr(host_trust.subprocess, "run", run)
    assert host_trust.scan_untrusted_fingerprint("root@10.0.0.2") == candidate()[1]
    assert not known.exists()
    assert len(scanned_files) == 1
    assert not scanned_files[0].exists()
    host_trust.enroll("root@10.0.0.2", candidate()[1])
    assert known.exists()
    assert len(scanned_files) == 2
    assert not scanned_files[1].exists()
