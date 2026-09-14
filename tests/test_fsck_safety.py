"""Exercise generated shell control flow with no device/system mutations."""
import subprocess

import pytest

from timecapsulesmb.services import maintenance


@pytest.mark.parametrize("unmount_status,mount_status,mounts,fsck_status,called,status", [
    (1, 0, "", 0, False, 1),
    (0, 1, "", 0, False, 1),
    (0, 0, "/dev/dk2 on /Volumes/dk2 (hfs, local)", 0, False, 1),
    (0, 0, "/dev/dk2 on /another/path (hfs, local)", 0, False, 1),
    (0, 0, "/dev/other on /Volumes/dk2 (hfs, local)", 0, False, 1),
    (0, 0, "", 8, True, 8),
    (0, 0, "", 0, True, 0),
])
def test_repair_fails_closed(tmp_path, monkeypatch, unmount_status, mount_status, mounts,
                           fsck_status, called, status):
    import shlex

    monkeypatch.setattr("timecapsulesmb.device.maintenance_lock.MAINTENANCE_LOCK", str(tmp_path / "maintenance-lock"))

    for name in ("render_direct_pkill9_manager", "render_direct_pkill9_watchdog", "render_direct_pkill9_by_ucomm"):
        monkeypatch.setattr(maintenance, name, lambda *args: ":")
    monkeypatch.setattr(maintenance, "DETACHED_SHUTDOWN_REBOOT_COMMAND", "echo REBOOT")
    script = maintenance.build_remote_fsck_script("/dev/dk2", "/Volumes/dk2", reboot=True)
    script = script.replace("sleep 2", ":")
    for name in ("umount", "mount", "fsck_hfs"):
        script = script.replace("/sbin/" + name, "audit_" + name)
    stubs = (
        f"audit_umount() {{ return {unmount_status}; }}\n"
        f"audit_mount() {{ printf '%s\\n' {shlex.quote(mounts)}; return {mount_status}; }}\n"
        f"audit_fsck_hfs() {{ echo REPAIR; return {fsck_status}; }}\n"
    )
    result = subprocess.run(["/bin/sh", "-c", stubs + script], capture_output=True, text=True)
    assert result.returncode == status
    assert ("REPAIR" in result.stdout) == called
    assert ("REBOOT" in result.stdout) == (status == 0)
