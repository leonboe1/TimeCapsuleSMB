"""Exercise generated device commands on temporary files, without a device."""
from __future__ import annotations

from pathlib import Path
import shlex
import subprocess

import pytest

from timecapsulesmb.deploy.boot_assets import load_boot_asset_text
from timecapsulesmb.deploy.planner import build_deployment_plan
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
