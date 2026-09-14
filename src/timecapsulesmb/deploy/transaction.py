"""Recoverable deployment across the disk and Flash filesystems.

All new files and previous program files live on disk before activation starts.
An inert rc.local prevents booting a mixed installation; the real rc.local is
installed last. Recovery restores programs but deliberately keeps boot disabled:
an old installation may contain the removed remote-execution service.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path, PurePosixPath
import shlex
import uuid
from typing import Callable, Mapping

from timecapsulesmb.deploy.planner import DeploymentPlan, FileTransfer
from timecapsulesmb.device.storage import ensure_volume_root_mounted_conn
from timecapsulesmb.transport.ssh import SshConnection, run_scp, run_ssh, run_ssh_capture_bytes


TRANSACTION_DIR = ".deploy-transaction"
PREVIOUS_DIR = ".deploy-previous"
MAX_PROGRAM_BYTES = 20 * 1024 * 1024
BOOT_GUARD = (
    "#!/bin/sh\n"
    "# TimeCapsuleSMB: deployment recovery guard\n"
    "echo 'TimeCapsuleSMB startup disabled after an incomplete deployment. Rerun tcapsule deploy.' >&2\n"
    "exit 1\n"
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DeploymentTransaction:
    def __init__(
        self, plan: DeploymentPlan, connection: SshConnection, stop_runtime: Callable[[], None],
        report: Callable[[str], None] | None = None,
    ):
        self.plan = plan
        self.connection = connection
        self.stop_runtime = stop_runtime
        self.report = report or logging.getLogger(__name__).warning
        self.root = f"{plan.payload_dir}/{TRANSACTION_DIR}"
        self.previous = f"{plan.payload_dir}/{PREVIOUS_DIR}"
        self.journal: dict = {"format": 1, "phase": "staging", "entries": []}
        self.armed = False
        self.token = uuid.uuid4().hex
        self.lock = str(PurePosixPath(plan.flash_targets["rc.local"]).parent.parent / "Memory/.tcapsulesmb-deploy-lock")
        self.locked = False
        destinations = [t.destination for t in plan.uploads]
        if len(set(destinations)) != len(destinations) or plan.flash_targets["rc.local"] not in destinations:
            raise ValueError("A deployment transaction requires unique targets and rc.local")
        allowed = set(plan.payload_targets.values()) | set(plan.flash_targets.values())
        if set(destinations) != allowed:
            raise ValueError("A deployment transaction requires the complete managed file set")

    def _mounted(self) -> None:
        if not ensure_volume_root_mounted_conn(
            self.connection, self.plan.volume_root, self.plan.device_path,
            wait_seconds=self.plan.apple_mount_wait_seconds,
        ):
            raise RuntimeError(f"Payload volume {self.plan.volume_root} is not mounted; deployment stopped")

    def _command(self, script: str) -> None:
        self._mounted()
        owner = shlex.quote(f"{self.lock}/owner")
        ownership = (
            f"[ ! -L {shlex.quote(self.lock)} ] && [ ! -L {owner} ] || exit 1; "
            f"read token < {owner}; [ \"$token\" = {self.token} ]; "
        )
        run_ssh(self.connection, f"/bin/sh -c {shlex.quote('set -eu; umask 077; ' + ownership + script)}", timeout=300)

    def acquire(self) -> None:
        self._mounted()
        lock = shlex.quote(self.lock)
        owner = shlex.quote(f"{self.lock}/owner")
        ancestors = "".join(f"[ ! -L {shlex.quote(str(p))} ]; " for p in PurePosixPath(self.lock).parents)
        script = ancestors + (
            f"[ ! -L {lock} ]; mkdir {lock}; chmod 700 {lock}; "
            f"printf '%s\\n' {self.token} > {owner}"
        )
        result = run_ssh(self.connection, f"/bin/sh -c {shlex.quote('set -eu; umask 077; ' + script)}", check=False, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(
                "Deployment lock is held or invalid. Another deployment may be active. "
                "If that client has stopped, reboot the device to clear its RAM lock, then rerun deploy."
            )
        self.locked = True

    def release(self) -> None:
        if not self.locked:
            return
        owner = shlex.quote(f"{self.lock}/owner")
        script = (
            f"[ ! -L {shlex.quote(self.lock)} ] && [ ! -L {owner} ] && "
            f"read token < {owner} && [ \"$token\" = {self.token} ] && "
            f"rm -f {owner} && rmdir {shlex.quote(self.lock)}"
        )
        # Disconnects retain the RAM lock until reboot; never steal another
        # client's lock or mask the operation's own result during cleanup.
        try:
            run_ssh(self.connection, f"/bin/sh -c {shlex.quote(script)}", check=False, timeout=30)
        except Exception:
            pass
        self.locked = False

    def resume_after_reboot(self) -> None:
        # Real reboot clears the RAM lock. The durable journal identifies this
        # transaction so a late client cannot modify a subsequent deployment.
        self.locked = False
        self.armed = False
        self.acquire()
        if self._load_journal(self.root).get("transaction_id") != self.journal.get("transaction_id"):
            raise RuntimeError("Deployment changed while rebooting; refusing to modify another transaction")
        self.armed = True

    def _guard_paths(self, paths: list[str]) -> None:
        guards = set()
        for value in paths:
            path = PurePosixPath(value)
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Unsafe deployment path: {value}")
            for part in (path, *path.parents):
                guards.add(f"[ ! -L {shlex.quote(str(part))} ]")
        self._command(" && ".join(sorted(guards)))

    def _read(self, path: str, limit: int = MAX_PROGRAM_BYTES) -> bytes:
        self._mounted()
        self._guard_paths([path])
        # Bound reads on the device as well as the host (including special files).
        quoted = shlex.quote(path)
        count = limit // 65536 + 1
        script = f"[ -f {quoted} ] && dd if={quoted} bs=65536 count={count} 2>/dev/null"
        data = run_ssh_capture_bytes(
            self.connection, f"/bin/sh -c {shlex.quote(script)}", timeout=300,
            missing_tool_message="Binary deployment verification requires local sshpass; rerun tcapsule bootstrap.",
        )
        if len(data) > limit:
            raise RuntimeError(f"Deployment file exceeds verification limit: {path}")
        return data

    def _exists(self, path: str) -> bool:
        self._guard_paths([path])
        result = run_ssh(self.connection, f"test -e {shlex.quote(path)}", check=False, timeout=30)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Could not inspect deployment path: {path}")
        return result.returncode == 0

    def _write_journal(self) -> None:
        text = json.dumps(self.journal, sort_keys=True)
        tmp = shlex.quote(f"{self.root}/journal.tmp")
        target = shlex.quote(f"{self.root}/journal.json")
        self._command(f"printf %s {shlex.quote(text)} > {tmp}; chmod 600 {tmp}; sync; mv -f {tmp} {target}; sync")

    def _load_journal(self, root: str) -> dict:
        data = json.loads(self._read(f"{root}/journal.json", 65536))
        if not isinstance(data, dict) or data.get("format") != 1:
            raise RuntimeError("Unrecognized deployment recovery journal; retained for manual inspection")
        if data.get("phase") not in {"staging", "prepared", "committing", "installed", "rolling_back", "recovered"}:
            raise RuntimeError("Invalid deployment recovery phase")
        identity = data.get("transaction_id")
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity):
            raise RuntimeError("Invalid deployment recovery identity")
        entries = data.get("entries")
        if not isinstance(entries, list) or len(entries) > len(self.plan.uploads):
            raise RuntimeError("Invalid deployment recovery entries")
        expected = {transfer.destination for transfer in self.plan.uploads}
        seen = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or entry.get("destination") not in expected or entry["destination"] in seen:
                raise RuntimeError("Invalid deployment recovery destination")
            seen.add(entry["destination"])
            if entry.get("index") != index or entry.get("mode") not in {"600", "755"}:
                raise RuntimeError("Invalid deployment recovery file attributes")
            for key in ("old_sha256", "new_sha256"):
                value = entry.get(key)
                if key == "old_sha256" and value is None:
                    continue
                if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise RuntimeError("Invalid deployment recovery hash")
        if data["phase"] != "staging" and seen != expected:
            raise RuntimeError("Incomplete deployment recovery journal")
        return data

    def _remove_snapshot(self, root: str) -> None:
        directories = [f"{root}/new", f"{root}/old"]
        self._guard_paths([root, *directories])
        files = [f"{directory}/{i}" for directory in directories for i in range(len(self.plan.uploads))]
        # Unknown contents may be recovery notes or user data. Refuse to erase
        # them, and retain the journal if the directory is not a pure snapshot.
        allowed = "|".join(str(i) for i in range(len(self.plan.uploads)))
        for directory in directories:
            self._command(
                f"for path in {shlex.quote(directory)}/* {shlex.quote(directory)}/.[!.]* {shlex.quote(directory)}/..?*; do "
                '[ -e "$path" ] || [ -L "$path" ] || continue; '
                f'case "${{path##*/}}" in {allowed}) [ -f "$path" ] || [ -L "$path" ];; *) exit 1;; esac; done'
            )
        self._command(
            f"for path in {shlex.quote(root)}/* {shlex.quote(root)}/.[!.]* {shlex.quote(root)}/..?*; do "
            '[ -e "$path" ] || [ -L "$path" ] || continue; '
            'case "${path##*/}" in new|old) [ -d "$path" ];; '
            'journal.json|journal.tmp) [ -f "$path" ] || [ -L "$path" ];; *) exit 1;; esac; done'
        )
        self._command("rm -f " + " ".join(shlex.quote(path) for path in files))
        for directory in directories:
            self._command(f"if [ -d {shlex.quote(directory)} ]; then rmdir {shlex.quote(directory)}; fi")
        # Keep the journal until the last directory removal so an interrupted
        # cleanup can be recognized on retry. A final empty root is also safe.
        self._command(f"rm -f {shlex.quote(root + '/journal.tmp')} {shlex.quote(root + '/journal.json')}; rmdir {shlex.quote(root)}")

    def _archive(self) -> None:
        if self._exists(self.previous):
            if self._exists(f"{self.previous}/journal.json"):
                self._load_journal(self.previous)  # Never remove an unrelated directory.
                self._remove_snapshot(self.previous)
            else:
                self._command(f"rmdir {shlex.quote(self.previous)}")
        self._command(f"mv {shlex.quote(self.root)} {shlex.quote(self.previous)}; sync")

    def prepare(self) -> None:
        self.acquire()
        paths = [self.root, self.previous, self.plan.private_dir, *[t.destination for t in self.plan.uploads]]
        self._guard_paths(paths)
        if self._exists(self.root):
            if not self._exists(f"{self.root}/journal.json"):
                # Only an empty directory can precede the first journal write.
                self._command(f"rmdir {shlex.quote(self.root)}")
            else:
                self.journal = self._load_journal(self.root)
                phase = self.journal["phase"]
                if phase in {"committing", "rolling_back"}:
                    self.armed = True
                    self.rollback()
                elif phase == "installed":
                    try:
                        self.verify_installed()
                    except Exception:
                        self.armed = True
                        self.rollback()
                if phase in {"staging", "prepared"}:
                    self._remove_snapshot(self.root)
                else:
                    self._archive()
        self.journal = {"format": 1, "transaction_id": self.token, "phase": "staging", "entries": []}
        self._command(f"mkdir -p {shlex.quote(self.plan.payload_dir)}; mkdir {shlex.quote(self.root)}; chmod 700 {shlex.quote(self.root)}")
        self._write_journal()
        self._command(f"mkdir {shlex.quote(self.root + '/new')} {shlex.quote(self.root + '/old')}")

    def stage(self, sources: Mapping[str, Path], on_uploading=None, on_uploaded=None) -> None:
        modes = {permission.path: permission.mode for permission in self.plan.permissions}
        for index, transfer in enumerate(self.plan.uploads):
            source = sources[transfer.source_id]
            content = source.read_bytes()
            if len(content) > MAX_PROGRAM_BYTES:
                raise ValueError(f"Deployment source is too large: {source}")
            if on_uploading:
                on_uploading(transfer)
            staged = f"{self.root}/new/{index}"
            self._mounted()
            run_scp(self.connection, source, staged, timeout=transfer.timeout_seconds or 180)
            if _digest(self._read(staged)) != _digest(content):
                raise RuntimeError(f"Uploaded content verification failed: {transfer.destination}")
            old_hash = None
            if self._exists(transfer.destination):
                old_hash = _digest(self._read(transfer.destination))
                backup = f"{self.root}/old/{index}"
                self._command(f"cp -p {shlex.quote(transfer.destination)} {shlex.quote(backup)}")
                if _digest(self._read(backup)) != old_hash:
                    raise RuntimeError(f"Previous program backup verification failed: {transfer.destination}")
            self.journal["entries"].append({
                "index": index, "destination": transfer.destination, "mode": modes[transfer.destination],
                "old_sha256": old_hash, "new_sha256": _digest(content),
            })
            if on_uploaded:
                on_uploaded(transfer)
        self.journal["phase"] = "prepared"
        self._write_journal()

    def _install(self, source: str, destination: str, digest: str, mode: str | None = None) -> None:
        path = PurePosixPath(destination)
        tmp = str(path.with_name(f".{path.name}.deploy-new"))
        self._guard_paths([source, destination, tmp])
        # cp -p preserves the original mode during recovery. Only staged new
        # files get planned modes. One temporary Flash file fits the old budget.
        self._command(f"cp -p {shlex.quote(source)} {shlex.quote(tmp)}")
        if mode:
            self._command(f"chmod {mode} {shlex.quote(tmp)}")
        if _digest(self._read(tmp)) != digest:
            raise RuntimeError(f"Deployment install verification failed: {destination}")
        self._command(f"sync; mv -f {shlex.quote(tmp)} {shlex.quote(destination)}; sync")

    def _arm_guard(self) -> None:
        destination = self.plan.flash_targets["rc.local"]
        tmp = str(PurePosixPath(destination).with_name(".rc.local.deploy-new"))
        self._guard_paths([destination, tmp])
        self._command(
            f"printf %s {shlex.quote(BOOT_GUARD)} > {shlex.quote(tmp)}; "
            f"chmod 755 {shlex.quote(tmp)}; sync; mv -f {shlex.quote(tmp)} {shlex.quote(destination)}; sync"
        )
        if self._read(destination) != BOOT_GUARD.encode():
            raise RuntimeError("Could not verify deployment boot guard")

    def commit(self) -> None:
        self.journal["phase"] = "committing"
        self._write_journal()
        self.armed = True
        self._arm_guard()
        self.stop_runtime()
        rc_local = self.plan.flash_targets["rc.local"]
        # The boot entry point is the final change across both filesystems.
        entries = sorted(self.journal["entries"], key=lambda e: e["destination"] == rc_local)
        for entry in entries:
            self._install(f"{self.root}/new/{entry['index']}", entry["destination"], entry["new_sha256"], entry["mode"])
        self.verify_installed()
        self.journal["phase"] = "installed"
        self._write_journal()

    def verify_installed(self) -> None:
        for entry in self.journal["entries"]:
            if _digest(self._read(entry["destination"])) != entry["new_sha256"]:
                raise RuntimeError(f"Installed content verification failed: {entry['destination']}")

    def rollback(self) -> None:
        if not self.armed:
            return  # Staging never modifies an active program or boot hook.
        lock_state = run_ssh(self.connection, f"test -d {shlex.quote(self.lock)}", check=False, timeout=30)
        if lock_state.returncode == 1:
            self.resume_after_reboot()
        elif lock_state.returncode != 0:
            raise RuntimeError("Could not inspect deployment ownership for recovery")
        # A failed copy can consume all remaining Flash/disk space. Free only
        # known temporary replacement files before writing the recovery guard.
        temporaries = [
            str(PurePosixPath(t.destination).with_name(f".{PurePosixPath(t.destination).name}.deploy-new"))
            for t in self.plan.uploads
        ]
        self._guard_paths([str(PurePosixPath(path).parent) for path in temporaries])
        self._command("rm -f " + " ".join(shlex.quote(path) for path in temporaries))
        self._arm_guard()
        self.stop_runtime()
        self.journal["phase"] = "rolling_back"
        self._write_journal()
        for entry in self.journal["entries"]:
            if entry["destination"] == self.plan.flash_targets["rc.local"]:
                continue  # Never automatically boot a potentially unsafe old installation.
            if entry["old_sha256"] is None:
                self._command(f"rm -f {shlex.quote(entry['destination'])}")
            else:
                self._install(f"{self.root}/old/{entry['index']}", entry["destination"], entry["old_sha256"])
        self.journal["phase"] = "recovered"
        self._write_journal()
        self.armed = False

    def rollback_after_error(self, error: BaseException) -> None:
        was_armed = self.armed
        try:
            self.rollback()
        except Exception as recovery_error:
            raise RuntimeError(
                f"Deployment failed and recovery could not finish ({recovery_error}). "
                f"Recovery files remain at {self.root}; reconnect and rerun tcapsule deploy."
            ) from error
        if was_armed:
            self.report(
                "Previous program files were restored. Managed startup remains disabled to avoid "
                "running an unsafe previous installation. Reconnect and rerun tcapsule deploy. "
                f"Recovery files: {self.root}"
            )

    def finalize(self) -> None:
        self.verify_installed()
        self._archive()
        self.armed = False


def deploy_transaction(
    plan: DeploymentPlan, *, connection: SshConnection, source_resolver: Mapping[str, Path],
    before_commit: Callable[[], None], on_uploading: Callable[[FileTransfer], None] | None = None,
    on_uploaded: Callable[[FileTransfer], None] | None = None,
    on_recovery: Callable[[str], None] | None = None,
) -> DeploymentTransaction:
    # Resolve every source before changing even staging state on the device.
    for transfer in plan.uploads:
        if transfer.source_id not in source_resolver:
            raise KeyError(f"No local source for planned transfer {transfer.source_id!r}")
        if not source_resolver[transfer.source_id].is_file():
            raise ValueError(f"Missing deployment source: {source_resolver[transfer.source_id]}")
    transaction = DeploymentTransaction(plan, connection, before_commit, on_recovery)
    try:
        transaction.prepare()
        transaction.stage(source_resolver, on_uploading, on_uploaded)
        transaction.commit()
    except BaseException as error:
        try:
            transaction.rollback_after_error(error)
        finally:
            transaction.release()
        raise
    return transaction
