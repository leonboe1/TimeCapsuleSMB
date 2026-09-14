from __future__ import annotations

import shlex
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping

from timecapsulesmb.deploy.commands import RemoteAction, render_remote_actions
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
    commands = render_remote_actions(action_list)
    total = len(action_list)
    for index, (action, command) in enumerate(zip(action_list, commands), start=1):
        run_ssh(connection, command)
        if on_action_done is not None:
            on_action_done(action, index, total)


def remote_request_reboot(connection: SshConnection) -> None:
    run_ssh(connection, DETACHED_SHUTDOWN_REBOOT_COMMAND, check=False, timeout=REBOOT_REQUEST_TIMEOUT_SECONDS)


def flush_remote_filesystem_writes(connection: SshConnection) -> None:
    run_ssh(connection, FLUSH_REMOTE_FILESYSTEMS_COMMAND, timeout=FLUSH_REMOTE_FILESYSTEMS_TIMEOUT_SECONDS)


def remote_uninstall_payload(connection: SshConnection, plan: UninstallPlan) -> None:
    # Use for loop to avoid rc=255 bug on NetBSD 4 Time Capsules
    for command in render_remote_actions(plan.remote_actions):
        run_ssh(connection, command)
