import shlex
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from timecapsulesmb.device import maintenance_lock as locks
from timecapsulesmb.device import storage
from timecapsulesmb.deploy import executor
from timecapsulesmb.deploy.commands import RemovePathAction
from timecapsulesmb.services import flash, maintenance, reboot
from timecapsulesmb.transport.ssh import SshConnection


@pytest.fixture
def device_lock(tmp_path, monkeypatch):
    path = tmp_path / "maintenance-lock"
    monkeypatch.setattr(locks, "MAINTENANCE_LOCK", str(path))
    def ssh(connection, command, *, check=True, **kwargs):
        return subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
    for module in (locks, storage, executor):
        monkeypatch.setattr(module, "run_ssh", ssh)
    monkeypatch.setattr(locks, "_active", locks.ContextVar("test_locks", default={}))
    return path, SshConnection("same-device", "", "")


def test_lock_precedes_mount_and_preserves_other_owner(device_lock, monkeypatch, tmp_path):
    path, connection = device_lock
    other = SshConnection(connection.host, "", "")
    with locks.maintenance_lock(connection) as lease:
        mount_script = storage.render_ensure_volume_root_mounted_script(str(tmp_path / "volume"), "/dev/dk2", 0)
        result = subprocess.run(["/bin/sh", "-c", mount_script], capture_output=True)
        assert result.returncode == 75
        assert not (tmp_path / "volume").exists()
        with pytest.raises(RuntimeError, match="maintenance lock"):
            executor.run_remote_actions(other, [RemovePathAction(str(tmp_path / "sentinel"))])
        assert (path / "owner").read_text().strip() == lease.token
    assert not path.exists()


def test_nested_mount_uses_transaction_owner(device_lock, tmp_path, monkeypatch):
    path, connection = device_lock
    monkeypatch.setattr(storage, "_remote_mounted_test", lambda root: "exit 0")
    with locks.maintenance_lock(connection) as lease:
        script = storage.render_ensure_volume_root_mounted_script(str(tmp_path / "volume"), "/dev/dk2", 0, lease=lease)
        script = script.replace("/usr/bin/acp rpc diskd.useVolume", "true")
        result = subprocess.run(["/bin/sh", "-c", script], capture_output=True)
        assert result.returncode == 0
        assert (path / "owner").read_text().strip() == lease.token
    assert not path.exists()


def test_uncertain_client_failure_retains_lock(device_lock):
    path, connection = device_lock
    with pytest.raises(TimeoutError):
        with locks.maintenance_lock(connection):
            raise TimeoutError("SSH disconnected while a command may still run")
    assert path.is_dir()
    assert locks.active_lock(connection) is None
    with pytest.raises(RuntimeError, match="maintenance lock"):
        with locks.maintenance_lock(connection):
            pytest.fail("must not steal the lost client's lock")


def test_terminated_remote_command_leaves_lock_held(device_lock):
    path, _ = device_lock
    script = locks.render_locked_script("/bin/sh -c 'kill -TERM $$'")
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True)
    assert result.returncode == 143
    assert path.is_dir()


def test_release_cannot_remove_replaced_owner(device_lock):
    path, connection = device_lock
    lease = locks.MaintenanceLock(connection)
    lease.acquire()
    (path / "owner").write_text("replacement-owner\n")
    lease.release()
    assert (path / "owner").read_text() == "replacement-owner\n"


def test_symlink_lock_is_rejected(device_lock, tmp_path):
    path, connection = device_lock
    target = tmp_path / "private"
    target.mkdir()
    path.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="maintenance lock"):
        locks.MaintenanceLock(connection).acquire()
    assert list(target.iterdir()) == []


def test_active_repair_blocks_mount_uninstall_flash_and_reboot(device_lock, tmp_path, monkeypatch):
    path, connection = device_lock
    for name in ("render_direct_pkill9_manager", "render_direct_pkill9_watchdog", "render_direct_pkill9_by_ucomm"):
        monkeypatch.setattr(maintenance, name, lambda *args: ":")
    gate = tmp_path / "repair-gate"
    gate.touch()
    started = tmp_path / "repair-started"
    script = maintenance.build_remote_fsck_script("/dev/dk2", "/Volumes/dk2", reboot=False).replace("sleep 2", ":")
    for name in ("umount", "mount", "fsck_hfs"):
        script = script.replace("/sbin/" + name, "fake_" + name)
    stubs = f"""
        fake_umount() {{ :; }}
        fake_mount() {{ :; }}
        fake_fsck_hfs() {{
            touch {shlex.quote(str(started))}
            while test -f {shlex.quote(str(gate))}; do sleep 0.05; done
        }}
    """
    writer = Mock(side_effect=AssertionError("must not write firmware"))
    monkeypatch.setattr(flash, "write_and_validate_plan", writer)
    reboot_request = Mock(side_effect=AssertionError("must not request reboot"))
    child = subprocess.Popen(["/bin/sh", "-c", stubs + script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists()
        assert not storage.ensure_volume_root_mounted_conn(connection, str(tmp_path / "volume"), "/dev/dk2", wait_seconds=0)
        assert not (tmp_path / "volume").exists()
        sentinel = tmp_path / "program"
        sentinel.touch()
        with pytest.raises(RuntimeError, match="maintenance lock"):
            executor.remote_uninstall_payload(connection, SimpleNamespace(remote_actions=[RemovePathAction(str(sentinel))]))
        assert sentinel.exists()
        with pytest.raises(RuntimeError, match="maintenance lock"):
            flash.write_flash_plan(target=SimpleNamespace(connection=connection), bundle=None,
                                   plan=SimpleNamespace(target_bank=object(), payload=b"firmware"))
        with pytest.raises(RuntimeError, match="maintenance lock"):
            reboot.request_reboot(connection, strategy="acp_then_ssh", request_acp_reboot=reboot_request)
        writer.assert_not_called()
        reboot_request.assert_not_called()
    finally:
        gate.unlink(missing_ok=True)
        stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, (stdout, stderr)
    assert not path.exists()


def test_reboot_retains_lock_until_ram_reset(device_lock):
    path, connection = device_lock
    request = Mock()
    reboot.request_reboot(connection, strategy="acp_then_ssh", request_acp_reboot=request)
    request.assert_called_once()
    assert path.is_dir()
    assert locks.active_lock(connection) is None


def test_nested_reboot_cannot_release_lock_before_shutdown(device_lock):
    path, connection = device_lock
    with locks.maintenance_lock(connection):
        reboot.request_reboot(connection, strategy="acp_then_ssh", request_acp_reboot=Mock())
    assert path.is_dir()
    assert locks.active_lock(connection) is None


@pytest.mark.parametrize("stale", [False, True])
def test_flash_validates_live_bank_while_excluding_other_operations(device_lock, monkeypatch, stale):
    path, connection = device_lock
    original = b"previous firmware"
    plan = SimpleNamespace(target_bank=SimpleNamespace(
        name="primary", device="/dev/flash0", sha256=flash.sha256_hex(original),
    ), payload=b"new firmware")
    def read(*args, **kwargs):
        assert path.is_dir()
        return b"changed" if stale else original
    def write(**kwargs):
        assert path.is_dir()
        return {"validated": True}
    writer = Mock(side_effect=write)
    monkeypatch.setattr(flash, "dump_remote_bank", read)
    monkeypatch.setattr(flash, "write_and_validate_plan", writer)
    monkeypatch.setattr(flash, "record_write_outcome", Mock())
    monkeypatch.setattr(flash, "write_stage_for_plan", lambda plan: "write_primary")
    target = SimpleNamespace(connection=connection, acp_host="same-device", compatibility=SimpleNamespace(os_release="4.0"))
    if stale:
        with pytest.raises(flash.FlashAnalysisError, match="bank changed"):
            flash.write_flash_plan(target=target, bundle=None, plan=plan)
        writer.assert_not_called()
    else:
        assert flash.write_flash_plan(target=target, bundle=None, plan=plan) == {"validated": True}
        writer.assert_called_once()
        assert not path.exists()
