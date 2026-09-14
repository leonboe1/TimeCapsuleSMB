"""Exercise generated device commands on temporary files, without a device."""
from __future__ import annotations

from pathlib import Path
import shlex
import subprocess

import pytest

from timecapsulesmb.deploy.boot_assets import load_boot_asset_text
from timecapsulesmb.deploy.planner import build_deployment_plan
from timecapsulesmb.deploy.planner import build_uninstall_plan
from timecapsulesmb.deploy.commands import (
    MANAGED_PAYLOAD_FILES, PrepareDirsAction, RemovePayloadProgramsAction, render_remote_action,
)
from timecapsulesmb.device.storage import PayloadHome, verify_payload_home_conn
from timecapsulesmb.transport.ssh import SshConnection


def local_ssh(_connection, command, *, check=True, **_kwargs):
    return subprocess.run(command, shell=True, check=check, capture_output=True, text=True)


@pytest.mark.parametrize("missing", [None, "smbd", "mdns-advertiser", "nbns-advertiser", "service", "private"])
@pytest.mark.parametrize("legacy_smbd", [False, True])
def test_both_validators_check_the_deployed_layout(tmp_path, monkeypatch, missing, legacy_smbd):
    home = PayloadHome(str(tmp_path / "disk ' with spaces"), "/dev/dk2", ".samba4")
    plan = build_deployment_plan("host", home, Path("smbd"), Path("mdns"), Path("nbns"), service_path=Path("service"))
    for target in plan.payload_targets.values():
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    Path(plan.private_dir).mkdir()
    if missing:
        target = Path(plan.payload_dir) / missing
        if target.is_dir():
            target.rmdir()
        else:
            target.unlink()
    if legacy_smbd and missing != "smbd":
        target = Path(plan.payload_dir) / "sbin/smbd"
        target.parent.mkdir()
        (Path(plan.payload_dir) / "smbd").rename(target)
    monkeypatch.setattr("timecapsulesmb.device.storage.ensure_volume_root_mounted_conn", lambda *a, **k: True)
    monkeypatch.setattr("timecapsulesmb.device.storage.run_ssh", local_ssh)
    result = verify_payload_home_conn(SshConnection("host", "", ""), home, wait_seconds=0)
    script = load_boot_asset_text("common.d/40-storage-discovery.sh")
    script += f"\ntc_verify_payload_dir {shlex.quote(plan.payload_dir)}\n"
    boot_result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
    assert result.ok == (missing is None), result.detail
    assert (boot_result.returncode == 0) == (missing is None), boot_result.stderr
    assert not (Path(plan.payload_dir) / "rsync").exists()
    assert not (Path(plan.payload_dir) / "rsyncd.conf").exists()


def test_uninstall_and_reinstall_preserve_metadata_and_unknown_data(tmp_path):
    payload = tmp_path / "disk/.samba4"
    data = {
        payload / "private/xattr.tdb": b"persistent metadata\0\xff",
        payload / "private/secrets.tdb": b"persistent secrets",
        payload / "notes": b"user file",
        payload.parent / "backup.sparsebundle/bands/0": b"backup data",
    }
    for path, content in data.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for name in MANAGED_PAYLOAD_FILES:
        path = payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("program")
    plan = build_uninstall_plan("host", [str(payload.parent)], [str(payload)])
    actions = [a for a in plan.remote_actions if isinstance(a, RemovePayloadProgramsAction)]
    assert len(actions) == 1
    for _ in range(2):  # Repeated uninstall is safe, including missing files.
        local_ssh(None, render_remote_action(actions[0]))
    assert all(not (payload / name).exists() for name in MANAGED_PAYLOAD_FILES)
    assert str(payload) not in plan.verify_absent_targets
    assert str(payload / "private") in plan.preserved_metadata_dirs
    home = PayloadHome(str(payload.parent), "/dev/dk2", ".samba4")
    install = build_deployment_plan("host", home, Path("smbd"), Path("mdns"), Path("nbns"), service_path=Path("service"))
    prepare = next(a for a in install.pre_upload_actions if isinstance(a, PrepareDirsAction))
    local_ssh(None, render_remote_action(PrepareDirsAction(
        tuple(d for d in prepare.directories if d.startswith(str(payload))), (),
    )))
    for target in install.payload_targets.values():
        Path(target).write_text("new program")
    for path, content in data.items():
        assert path.read_bytes() == content


@pytest.mark.parametrize("link_parent", [False, True])
def test_uninstall_refuses_symlinked_payload_directories(tmp_path, link_parent):
    other = tmp_path / "other"
    other.mkdir()
    (other / "smbd").write_text("unrelated file")
    payload = tmp_path / "disk/.samba4"
    payload.mkdir(parents=True)
    if link_parent:
        payload.rmdir()
        payload.symlink_to(other, target_is_directory=True)
    else:
        (payload / "sbin").symlink_to(other, target_is_directory=True)
    result = local_ssh(None, render_remote_action(RemovePayloadProgramsAction(str(payload))), check=False)
    assert result.returncode != 0
    assert (other / "smbd").read_text() == "unrelated file"
