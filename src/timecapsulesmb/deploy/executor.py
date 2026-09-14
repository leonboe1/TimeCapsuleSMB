from __future__ import annotations

import shlex
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping

from timecapsulesmb.deploy.commands import EnsureVolumeMountedAction, RemoteAction, render_remote_action
from timecapsulesmb.device.maintenance_lock import active_lock, maintenance_lock, render_locked_script
from timecapsulesmb.device.storage import ensure_volume_root_mounted_conn
from timecapsulesmb.deploy.planner import DeploymentPlan, FileTransfer, UninstallPlan
from timecapsulesmb.deploy.transaction import DeploymentTransaction, deploy_transaction
from timecapsulesmb.transport.ssh import SshConnection, run_scp, run_ssh


DETACHED_SHUTDOWN_REBOOT_COMMAND = (
    "/bin/sh -c 'exec </dev/null >/dev/null 2>&1; "
    "(/bin/sync; /bin/sleep 1; "
    "/sbin/shutdown -r now || /sbin/reboot"
    ") & exit 0'"
)
REBOOT_REQUEST_TIMEOUT_SECONDS = 30
PAYLOAD_FLUSH_SETTLE_SECONDS = 5
FLUSH_REMOTE_FILESYSTEMS_COMMAND = (
    f"/bin/sh -c {shlex.quote(f'/bin/sync; /bin/sleep {PAYLOAD_FLUSH_SETTLE_SECONDS}; /bin/sync')}"
)
# Time Capsule HFS disks can spend well over 30 seconds flushing the Samba
# payload after a slow upload. Keep this bounded, but long enough for real disks.
FLUSH_REMOTE_FILESYSTEMS_TIMEOUT_SECONDS = 300


def _flash_upload_tmp_path(destination: str) -> str:
    path = PurePosixPath(destination)
    return str(path.with_name(f".{path.name}.tmp"))


def _best_effort_cleanup_flash_upload_tmp_path(connection: SshConnection, tmp_destination: str) -> None:
    try:
        run_ssh(connection, f"/bin/sh -c {shlex.quote(f'rm -f {shlex.quote(tmp_destination)}')}", check=False)
    except Exception:
        pass


def upload_flash_file(
    connection: SshConnection,
    source: Path,
    destination: str,
    *,
    timeout: int = 120,
    mode: str = "755",
) -> None:
    tmp_destination = _flash_upload_tmp_path(destination)
    quoted_tmp = shlex.quote(tmp_destination)
    quoted_destination = shlex.quote(destination)
    quoted_mode = shlex.quote(mode)

    run_ssh(connection, f"/bin/sh -c {shlex.quote(f'rm -f {quoted_tmp}')}")
    try:
        run_scp(connection, source, tmp_destination, timeout=timeout)
        install_script = (
            "rc=0; "
            f"chmod {quoted_mode} {quoted_tmp} && mv -f {quoted_tmp} {quoted_destination} || rc=$?; "
            f"rm -f {quoted_tmp}; "
            'exit "$rc"'
        )
        run_ssh(connection, f"/bin/sh -c {shlex.quote(install_script)}")
    except Exception:
        _best_effort_cleanup_flash_upload_tmp_path(connection, tmp_destination)
        raise


def upload_deployment_payload(
    plan: DeploymentPlan,
    *,
    connection: SshConnection,
    source_resolver: Mapping[str, Path],
    on_uploading: Callable[[FileTransfer], None] | None = None,
    on_uploaded: Callable[[FileTransfer], None] | None = None,
    before_commit: Callable[[], None] | None = None,
    on_recovery: Callable[[str], None] | None = None,
) -> DeploymentTransaction:
    return deploy_transaction(
        plan, connection=connection, source_resolver=source_resolver,
        on_uploading=on_uploading, on_uploaded=on_uploaded,
        on_recovery=on_recovery,
        before_commit=before_commit or (lambda: run_remote_actions(connection, plan.pre_upload_actions)),
    )


def run_remote_actions(
    connection: SshConnection,
    actions: Iterable[RemoteAction],
    *,
    on_action_done: Callable[[RemoteAction, int, int], None] | None = None,
) -> None:
    action_list = list(actions)
    total = len(action_list)
    with maintenance_lock(connection, runner=run_ssh) as lease:
        for index, action in enumerate(action_list, start=1):
            if isinstance(action, EnsureVolumeMountedAction):
                if not ensure_volume_root_mounted_conn(connection, action.volume_root, action.device_path, wait_seconds=action.wait_seconds):
                    raise RuntimeError(f"Volume {action.volume_root} could not be mounted during maintenance")
            else:
                run_ssh(connection, lease.guard(render_remote_action(action)))
            if on_action_done is not None:
                on_action_done(action, index, total)


def remote_request_reboot(connection: SshConnection) -> None:
    lease = active_lock(connection)
    if lease is not None:
        lease.reboot_pending = True
    script = render_locked_script(DETACHED_SHUTDOWN_REBOOT_COMMAND, lease=lease, keep_on_success=True)
    run_ssh(connection, f"/bin/sh -c {shlex.quote(script)}", check=False, timeout=REBOOT_REQUEST_TIMEOUT_SECONDS)


def flush_remote_filesystem_writes(connection: SshConnection) -> None:
    run_ssh(connection, FLUSH_REMOTE_FILESYSTEMS_COMMAND, timeout=FLUSH_REMOTE_FILESYSTEMS_TIMEOUT_SECONDS)


def remote_uninstall_payload(connection: SshConnection, plan: UninstallPlan) -> None:
    # Hold exclusion across all deletions, including recovery snapshots.
    with maintenance_lock(connection, runner=run_ssh, reuse=False):
        run_remote_actions(connection, plan.remote_actions)
