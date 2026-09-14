"""One RAM lock for cooperating device mutations, including mount requests.

Keep the earlier deployment lock name so older hardened deploy clients also
exclude these operations. A lost client never steals a lock; reboot clears RAM.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import PurePosixPath
import shlex
import uuid

from timecapsulesmb.transport.ssh import SshConnection, run_ssh


MAINTENANCE_LOCK = "/mnt/Memory/.tcapsulesmb-deploy-lock"
_active: ContextVar[dict[int, "MaintenanceLock"]] = ContextVar("device_maintenance_locks", default={})
LOCK_ERROR = (
    "Device maintenance lock is held or invalid. Another operation may be active. "
    "After confirming that every other client and remote operation has stopped, "
    "reboot the device to clear its RAM lock and retry."
)


def _ownership(path: str, token: str) -> str:
    owner = shlex.quote(f"{path}/owner")
    guards = " && ".join(f"[ ! -L {shlex.quote(str(p))} ]" for p in (PurePosixPath(path), *PurePosixPath(path).parents))
    return f'{guards} && [ ! -L {owner} ] && [ -f {owner} ] && read tc_owner < {owner} && [ "$tc_owner" = {shlex.quote(token)} ]'


def _acquire(path: str, token: str) -> str:
    quoted = shlex.quote(path)
    guards = "".join(f"[ ! -L {shlex.quote(str(p))} ]; " for p in PurePosixPath(path).parents)
    return (
        f"set -eu; umask 077; {guards}[ ! -L {quoted} ]; mkdir {quoted}; chmod 700 {quoted}; "
        f"printf '%s\\n' {shlex.quote(token)} > {shlex.quote(path + '/owner')}"
    )


def _release(path: str, token: str) -> str:
    return f"{_ownership(path, token)} && rm -f {shlex.quote(path + '/owner')} && rmdir {shlex.quote(path)}"


def active_lock(connection: SshConnection) -> MaintenanceLock | None:
    return _active.get().get(id(connection))


def render_locked_script(script: str, *, lease: MaintenanceLock | None = None,
                         keep_on_success: bool = False) -> str:
    """Run a complete remote operation; disconnect/signal leaves its lock held.

    Mount requests use this even when rendered as standalone remote actions.
    A caller already holding a host lease passes it explicitly, never via an
    unverified process environment variable.
    """
    if lease is not None:
        return f"{_ownership(lease.lock, lease.token)} || exit 75;\n(\n{script}\n)"
    path, token = MAINTENANCE_LOCK, uuid.uuid4().hex
    acquire = f"/bin/sh -c {shlex.quote(_acquire(path, token))}"
    return (
        f"{acquire} || {{ echo {shlex.quote(LOCK_ERROR)} >&2; exit 75; }}\n"
        "trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM\n"
        f"(\n{script}\n)\ntc_status=$?\n"
        "[ \"$tc_status\" -lt 128 ] || exit \"$tc_status\"\n"
        + ('[ "$tc_status" -ne 0 ] || exit 0\n' if keep_on_success else "")
        + f"{_release(path, token)} || exit 75\nexit \"$tc_status\""
    )


class MaintenanceLock:
    def __init__(self, connection: SshConnection, *, path: str | None = None, runner=None):
        self.connection = connection
        self.lock = path or MAINTENANCE_LOCK
        self.token = uuid.uuid4().hex
        self.locked = False
        self.reboot_pending = False
        self.runner = runner or run_ssh

    def acquire(self) -> None:
        result = self.runner(self.connection, f"/bin/sh -c {shlex.quote(_acquire(self.lock, self.token))}", check=False, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(LOCK_ERROR)
        self.locked = True
        self.reboot_pending = False
        _active.set({**_active.get(), id(self.connection): self})

    def guard(self, command: str) -> str:
        return f"/bin/sh -c {shlex.quote(render_locked_script(command, lease=self))}"

    def forget(self) -> None:
        if active_lock(self.connection) is self:
            _active.set({key: value for key, value in _active.get().items() if value is not self})
        self.locked = False

    def release(self) -> None:
        if self.locked and not self.reboot_pending:
            try:
                self.runner(self.connection, f"/bin/sh -c {shlex.quote(_release(self.lock, self.token))}", check=False, timeout=30)
            except Exception:
                pass  # A disconnect leaves the device locked until reboot.
        self.forget()


@contextmanager
def maintenance_lock(connection: SshConnection, *, runner=None, keep_on_success=False, reuse=True):
    existing = active_lock(connection)
    if existing is not None and reuse:
        # Do not release a transaction's lease from a nested operation.
        existing.runner(connection, existing.guard(":"), timeout=30)
        if keep_on_success:
            existing.reboot_pending = True
        yield existing
        return
    lease = MaintenanceLock(connection, runner=runner)
    lease.acquire()
    try:
        yield lease
    except BaseException:
        lease.forget()  # The remote command may still be running.
        raise
    else:
        if keep_on_success:
            lease.forget()  # Reboot requests retain exclusion until RAM resets.
        else:
            lease.release()
