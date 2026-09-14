"""Run the production transaction's generated shell against a local fake device."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from unittest import mock

import pytest

from timecapsulesmb.deploy.executor import upload_deployment_payload
from timecapsulesmb.deploy.planner import build_deployment_plan
from timecapsulesmb.deploy.transaction import BOOT_GUARD, DeploymentRecoveryRequired, DeploymentTransaction
from timecapsulesmb.transport.errors import SshCommandTimeout, SshNetworkError, ScpError
from timecapsulesmb.device.storage import PayloadHome
from timecapsulesmb.services.deploy import complete_deployment_after_upload
from timecapsulesmb.services.deploy import DeployRuntimeConfig, upload_and_verify_deployment_payload
from timecapsulesmb.core.config import AppConfig
from timecapsulesmb.device.storage import PayloadVerificationResult
from timecapsulesmb.deploy.commands import RemovePayloadProgramsAction, render_remote_action
from timecapsulesmb.transport.ssh import SshConnection


@pytest.fixture
def device(tmp_path, monkeypatch):
    flash = tmp_path / "mnt/Flash"
    flash.mkdir(parents=True)
    (flash.parent / "Memory").mkdir()
    home = PayloadHome(str(tmp_path / "disk ' with spaces"), "/dev/dk2", ".samba4")
    plan = build_deployment_plan("host", home, Path("smbd"), Path("mdns"), Path("nbns"), service_path=Path("service"))
    def destination(path):
        return path.replace("/mnt/Flash", str(flash))
    plan = replace(
        plan, flash_targets={k: destination(v) for k, v in plan.flash_targets.items()},
        uploads=[replace(t, destination=destination(t.destination)) for t in plan.uploads],
        permissions=[replace(p, path=destination(p.path)) for p in plan.permissions],
    )
    programs = tmp_path / "programs"
    programs.mkdir()
    sources = {}
    old = {}
    for index, transfer in enumerate(plan.uploads):
        source = programs / transfer.source_id.replace(":", "-")
        source.write_bytes(f"new {transfer.source_id}\n".encode())
        sources[transfer.source_id] = source
        target = Path(transfer.destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        old[target] = f"old {index}\n".encode()
        target.write_bytes(old[target])
        target.chmod(0o600 if target.name.endswith(".conf") else 0o755)
    metadata = Path(plan.private_dir) / "xattr.tdb"
    metadata.parent.mkdir()
    metadata.write_bytes(b"irreplaceable metadata\0\xff")
    # The test device has no real disk to flush. All other generated shell
    # commands (cp, chmod, mv, dd, mkdir, rm, guards) run unmodified.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "sync").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "sync").chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    def ssh(_connection, command, *, check=True, **_kwargs):
        return subprocess.run(command, shell=True, check=check, capture_output=True, text=True, env=env)
    def capture(_connection, command, **_kwargs):
        return subprocess.run(command, shell=True, check=True, capture_output=True, env=env).stdout
    def scp(_connection, source, target, **_kwargs):
        shutil.copyfile(source, target)
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.run_ssh", ssh)
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.run_ssh_capture_bytes", capture)
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.run_scp", scp)
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.ensure_volume_root_mounted_conn", lambda *a, **k: True)
    connection = SshConnection("host", "", "")
    stops = []
    def stop():
        assert Path(plan.flash_targets["rc.local"]).read_text() == BOOT_GUARD
        stops.append(True)
    return plan, sources, old, metadata, connection, stop, stops


def deploy(device):
    plan, sources, _, _, connection, stop, _ = device
    return upload_deployment_payload(plan, connection=connection, source_resolver=sources, before_commit=stop)


def assert_recovered(device):
    plan, _, old, metadata, _, _, _ = device
    for path, content in old.items():
        if str(path) == plan.flash_targets["rc.local"]:
            assert path.read_text() == BOOT_GUARD
        else:
            assert path.read_bytes() == content
    assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"


def test_complete_deployment_retains_previous_programs_and_metadata(device):
    transaction = deploy(device)
    plan, sources, old, metadata, _, _, stops = device
    for transfer in plan.uploads:
        assert Path(transfer.destination).read_bytes() == sources[transfer.source_id].read_bytes()
    assert len(stops) == 1
    assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"
    transaction.finalize()
    transaction.release()
    assert not Path(transaction.root).exists()
    for index, transfer in enumerate(plan.uploads):
        assert (Path(transaction.previous) / f"old/{index}").read_bytes() == old[Path(transfer.destination)]
    assert Path(plan.flash_targets["tcapsulesmb.conf"]).stat().st_mode & 0o777 == 0o600


def test_uninstall_cannot_erase_active_deployment_recovery(device, monkeypatch):
    from types import SimpleNamespace
    from timecapsulesmb.deploy import executor, transaction as transaction_module
    from timecapsulesmb.device import maintenance_lock

    plan, sources, _, metadata, connection, stop, _ = device
    transaction = DeploymentTransaction(plan, connection, stop)
    transaction.prepare()
    transaction.stage(sources)
    transaction.commit()
    journal = (Path(transaction.root) / "journal.json").read_bytes()
    monkeypatch.setattr(maintenance_lock, "MAINTENANCE_LOCK", transaction.lock)
    monkeypatch.setattr(executor, "run_ssh", transaction_module.run_ssh)
    other_client = SshConnection(connection.host, "", "")
    with pytest.raises(RuntimeError, match="maintenance lock"):
        executor.remote_uninstall_payload(other_client, SimpleNamespace(
            remote_actions=[RemovePayloadProgramsAction(plan.payload_dir)],
        ))
    assert (Path(transaction.root) / "journal.json").read_bytes() == journal
    assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"
    transaction.rollback()
    assert_recovered(device)
    transaction.release()


def test_surviving_upload_blocks_competing_mutations_after_client_timeout(device, monkeypatch, tmp_path):
    from timecapsulesmb.deploy import executor, transaction as transaction_module
    from timecapsulesmb.deploy.commands import RemovePathAction
    from timecapsulesmb.device import maintenance_lock

    plan, _, old, metadata, connection, _, _ = device
    lock = Path(plan.flash_targets["rc.local"]).parent.parent / "Memory/.tcapsulesmb-deploy-lock"
    monkeypatch.setattr(maintenance_lock, "MAINTENANCE_LOCK", str(lock))
    monkeypatch.setattr(executor, "run_ssh", transaction_module.run_ssh)
    gate = tmp_path / "upload-gate"
    gate.touch()
    started = tmp_path / "upload-started"
    child = None

    def upload(_connection, source, destination, **kwargs):
        nonlocal child
        child = subprocess.Popen([
            "/bin/sh", "-c",
            'touch "$1"; while test -f "$2"; do sleep 0.02; done; cp "$3" "$4"',
            "remote-upload", str(started), str(gate), str(source), destination,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists()
        raise SshCommandTimeout("client timed out; remote upload survives")

    monkeypatch.setattr(transaction_module, "run_scp", upload)
    try:
        with pytest.raises(DeploymentRecoveryRequired, match="Remote work may still be running"):
            deploy(device)
        assert child.poll() is None
        assert lock.is_dir()
        assert maintenance_lock.active_lock(connection) is None
        journal = Path(plan.payload_dir) / ".deploy-transaction/journal.json"
        retained = journal.read_bytes()
        sentinel = tmp_path / "competing-mutation"
        sentinel.touch()
        for other in (connection, SshConnection(connection.host, "", "")):
            with pytest.raises(RuntimeError, match="maintenance lock"):
                executor.run_remote_actions(other, [RemovePathAction(str(sentinel))])
        assert sentinel.exists()
        with pytest.raises(RuntimeError, match="maintenance lock"):
            deploy(device)
        assert journal.read_bytes() == retained
        assert all(path.read_bytes() == content for path, content in old.items())
        assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"
    finally:
        gate.unlink(missing_ok=True)
        if child is not None:
            stdout, stderr = child.communicate(timeout=10)
            assert child.returncode == 0, (stdout, stderr)


@pytest.mark.parametrize("error", [
    SshCommandTimeout("timeout"), SshNetworkError("connection lost"), ScpError("upload failed"),
    subprocess.TimeoutExpired("ssh", 1), TimeoutError("timeout"),
    KeyboardInterrupt(), SystemExit(1), subprocess.CalledProcessError(255, "ssh"),
])
def test_uncertain_failure_never_attempts_rollback_or_releases_remote_lock(device, error):
    from timecapsulesmb.device.maintenance_lock import active_lock

    plan, _, _, _, connection, stop, _ = device
    transaction = DeploymentTransaction(plan, connection, stop)
    transaction.prepare()
    transaction.armed = True
    wrapped = RuntimeError("outer operation failed")
    wrapped.__cause__ = error
    with mock.patch.object(transaction, "rollback") as rollback:
        with pytest.raises(DeploymentRecoveryRequired):
            try:
                transaction.rollback_after_error(wrapped)
            finally:
                transaction.release()
        rollback.assert_not_called()
    assert Path(transaction.lock).is_dir()
    assert active_lock(connection) is None


@pytest.mark.parametrize("phase", ["commit", "post_upload", "activation", "finalize", "rollback", "previous_install"])
def test_uncertain_failure_retains_journal_across_deployment_phases(device, monkeypatch, phase):
    plan, sources, _, _, connection, stop, _ = device
    error = SshCommandTimeout("remote work may still run")
    if phase == "commit":
        transaction = DeploymentTransaction(plan, connection, stop)
        transaction.prepare()
        transaction.stage(sources)
        monkeypatch.setattr(DeploymentTransaction, "_arm_guard", mock.Mock(side_effect=error))
        operation = lambda: transaction.commit()
    else:
        transaction = deploy(device)
        if phase == "previous_install":
            transaction.release()
            monkeypatch.setattr(DeploymentTransaction, "verify_installed", mock.Mock(side_effect=error))
            operation = lambda: deploy(device)
        elif phase == "post_upload":
            prepared = mock.Mock(plan=plan, payload_home=PayloadHome(plan.volume_root, plan.device_path, ".samba4"))
            operation = lambda: upload_and_verify_deployment_payload(
                AppConfig.from_values({}), connection, prepared, DeployRuntimeConfig(nbns_enabled=False),
                run_remote_actions_func=mock.Mock(side_effect=error),
                upload_payload_func=lambda *a, **k: transaction,
            )
        elif phase == "rollback":
            monkeypatch.setattr(transaction, "_arm_guard", mock.Mock(side_effect=error))
            operation = lambda: transaction.rollback_after_error(RuntimeError("runtime unhealthy"))
        else:
            monkeypatch.setattr("timecapsulesmb.services.deploy._complete_deployment_after_upload",
                                mock.Mock(side_effect=error) if phase == "activation" else mock.Mock(return_value=mock.Mock(verified=True)))
            if phase == "finalize":
                monkeypatch.setattr(transaction, "_archive", mock.Mock(side_effect=error))
            operation = lambda: complete_deployment_after_upload(connection, mock.Mock(), no_wait=False, transaction=transaction)
    journal = Path(transaction.root) / "journal.json"
    rollback = mock.Mock(side_effect=AssertionError("must not roll back after uncertain completion"))
    if phase != "rollback":
        monkeypatch.setattr(DeploymentTransaction, "rollback", rollback)
    with pytest.raises(DeploymentRecoveryRequired):
        try:
            operation()
        except BaseException as caught:
            # commit() itself is owned by deploy_transaction's outer handler.
            if phase == "commit":
                transaction.rollback_after_error(caught)
            raise
        finally:
            transaction.release()
    assert Path(transaction.lock).is_dir()
    assert journal.is_file()
    assert device[3].read_bytes() == b"irreplaceable metadata\0\xff"
    if phase != "rollback":
        rollback.assert_not_called()


@pytest.mark.parametrize("failed_index", range(11))
@pytest.mark.parametrize("corruption", [False, True])
def test_failed_or_corrupt_upload_never_changes_live_files(device, monkeypatch, failed_index, corruption):
    _, _, old, metadata, _, _, stops = device
    calls = 0
    def scp(_connection, source, target, **_kwargs):
        nonlocal calls
        current = calls
        calls += 1
        if current == failed_index:
            content = source.read_bytes()
            Path(target).write_bytes(b"x" * len(content) if corruption else content[:2])
            if not corruption:
                raise RuntimeError("connection lost during upload")
        else:
            shutil.copyfile(source, target)
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.run_scp", scp)
    with pytest.raises(RuntimeError, match="connection lost|content verification"):
        deploy(device)
    for path, content in old.items():
        assert path.read_bytes() == content
    assert stops == []
    assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"


@pytest.mark.parametrize("failed_index", range(11))
def test_every_failed_install_restores_previous_programs_and_disables_boot(device, monkeypatch, failed_index):
    original = DeploymentTransaction._install
    calls = 0
    def install(self, source, destination, digest, mode=None):
        nonlocal calls
        current = calls
        calls += 1
        original(self, source, destination, digest, mode)
        if current == failed_index:
            raise RuntimeError("failed after rename")
    monkeypatch.setattr(DeploymentTransaction, "_install", install)
    with pytest.raises(RuntimeError, match="failed after rename"):
        deploy(device)
    assert_recovered(device)
    # A retry does not need the previous process or its in-memory state.
    monkeypatch.setattr(DeploymentTransaction, "_install", original)
    deploy(device).finalize()


@pytest.mark.parametrize("phase", ["staging", "prepared", "committing", "installed", "rolling_back"])
def test_fresh_process_recovers_after_interruption(device, phase):
    plan, sources, _, _, connection, stop, _ = device
    interrupted = DeploymentTransaction(plan, connection, stop)
    interrupted.prepare()
    if phase != "staging":
        interrupted.stage(sources)
    if phase in {"committing", "rolling_back"}:
        interrupted.journal["phase"] = phase
        interrupted._write_journal()
        interrupted._arm_guard()
        entry = interrupted.journal["entries"][0]
        interrupted._install(f"{interrupted.root}/new/0", entry["destination"], entry["new_sha256"], entry["mode"])
    elif phase == "installed":
        interrupted.commit()
    interrupted.release()  # Simulate the RAM lock disappearing on reboot.
    fresh = deploy(device)
    fresh.finalize()
    assert json.loads((Path(fresh.previous) / "journal.json").read_text())["phase"] == "installed"


def test_failed_first_install_removes_new_programs_but_preserves_data(device, monkeypatch):
    plan, _, old, metadata, _, _, _ = device
    for path in old:
        path.unlink()
    original = DeploymentTransaction._install
    def install(self, source, destination, digest, mode=None):
        original(self, source, destination, digest, mode)
        if destination == plan.payload_targets["service"]:
            raise RuntimeError("install failed")
    monkeypatch.setattr(DeploymentTransaction, "_install", install)
    with pytest.raises(RuntimeError, match="install failed"):
        deploy(device)
    for target in plan.payload_targets.values():
        assert not Path(target).exists()
    assert metadata.read_bytes() == b"irreplaceable metadata\0\xff"
    assert Path(plan.flash_targets["rc.local"]).read_text() == BOOT_GUARD


def test_runtime_activation_failure_restores_programs(device):
    transaction = deploy(device)
    _, _, _, _, connection, _, _ = device
    with mock.patch("timecapsulesmb.services.deploy._complete_deployment_after_upload", side_effect=RuntimeError("runtime unhealthy")):
        with pytest.raises(RuntimeError, match="runtime unhealthy"):
            complete_deployment_after_upload(connection, mock.Mock(), no_wait=False, transaction=transaction)
    assert_recovered(device)


def test_recovery_rejects_modified_snapshot_before_installing_it(device):
    transaction = deploy(device)
    (Path(transaction.root) / "old/0").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="verification failed"):
        transaction.rollback()
    assert Path(transaction.plan.flash_targets["rc.local"]).read_text() == BOOT_GUARD


def test_symlinked_private_directory_is_rejected_without_touching_programs(device, tmp_path):
    plan, _, old, _, _, _, _ = device
    private = Path(plan.private_dir)
    private.rename(tmp_path / "private-data")
    private.symlink_to(tmp_path / "private-data", target_is_directory=True)
    with pytest.raises(subprocess.CalledProcessError):
        deploy(device)
    for path, content in old.items():
        assert path.read_bytes() == content


def test_second_deployment_cannot_replace_an_active_transactions_files(device):
    plan, _, _, _, connection, stop, _ = device
    first = DeploymentTransaction(plan, connection, stop)
    first.prepare()
    journal = Path(first.root) / "journal.json"
    content = journal.read_bytes()
    with pytest.raises(RuntimeError, match="maintenance lock"):
        deploy(device)
    assert journal.read_bytes() == content
    assert (Path(first.lock) / "owner").read_text().split()[0] == first.token
    first.release()


def test_reboot_clears_lock_but_old_client_cannot_write_into_new_transaction(device):
    plan, _, _, _, connection, stop, _ = device
    old = DeploymentTransaction(plan, connection, stop)
    old.prepare()
    shutil.rmtree(old.lock)  # Only the fake device RAM is reset on reboot.
    fresh = deploy(device)
    with pytest.raises(subprocess.CalledProcessError):
        old._command("exit 0")
    old.release()
    assert (Path(fresh.lock) / "owner").read_text().split()[0] == fresh.token
    fresh.finalize()
    fresh.release()


def test_reboot_completion_reacquires_lock_and_checks_journal_identity(device):
    transaction = deploy(device)
    shutil.rmtree(transaction.lock)
    transaction.resume_after_reboot()
    transaction.finalize()
    transaction.release()


def test_late_client_cannot_roll_back_a_new_deployment_after_reboot(device):
    old = deploy(device)
    shutil.rmtree(old.lock)
    fresh = deploy(device)
    fresh.release()
    programs = {Path(t.destination): Path(t.destination).read_bytes() for t in fresh.plan.uploads}
    with pytest.raises(RuntimeError, match="changed while rebooting"):
        old.resume_after_reboot()
    old.rollback()
    old.release()
    for path, content in programs.items():
        assert path.read_bytes() == content


def test_missing_volume_stops_before_staging_or_modifying_programs(device, monkeypatch):
    monkeypatch.setattr("timecapsulesmb.deploy.transaction.ensure_volume_root_mounted_conn", lambda *a, **k: False)
    with pytest.raises(RuntimeError, match="not mounted"):
        deploy(device)
    for path, content in device[2].items():
        assert path.read_bytes() == content


def test_recovery_journal_cannot_target_unrelated_files(device, tmp_path):
    transaction = deploy(device)
    transaction.release()
    unrelated = tmp_path / "user data"
    unrelated.write_text("keep me")
    journal = Path(transaction.root) / "journal.json"
    data = json.loads(journal.read_text())
    data["entries"][0]["destination"] = str(unrelated)
    journal.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="recovery destination"):
        deploy(device)
    assert unrelated.read_text() == "keep me"


def test_no_wait_keeps_recovery_snapshot_and_releases_lock(device):
    transaction = deploy(device)
    result = mock.Mock(verified=False)
    with mock.patch("timecapsulesmb.services.deploy._complete_deployment_after_upload", return_value=result):
        complete_deployment_after_upload(device[4], mock.Mock(), no_wait=True, transaction=transaction)
    assert Path(transaction.root).exists()
    assert not Path(transaction.lock).exists()


def test_post_upload_verification_failure_rolls_back_and_releases_lock(device):
    transaction = deploy(device)
    plan = device[0]
    prepared = mock.Mock(plan=plan, payload_home=PayloadHome(plan.volume_root, plan.device_path, ".samba4"))
    with pytest.raises(Exception, match="verification failed|Payload verification|missing"):
        upload_and_verify_deployment_payload(
            AppConfig.from_values({}), device[4], prepared, DeployRuntimeConfig(nbns_enabled=False),
            run_remote_actions_func=mock.Mock(), upload_payload_func=lambda *a, **k: transaction,
            flush_remote_writes=mock.Mock(),
            verify_payload_home=mock.Mock(return_value=PayloadVerificationResult(False, "missing payload")),
        )
    assert_recovered(device)
    assert not Path(transaction.lock).exists()


def test_upload_wrapper_preserves_deferred_recovery_policy(device):
    plan = device[0]
    prepared = mock.Mock(plan=plan, payload_home=PayloadHome(plan.volume_root, plan.device_path, ".samba4"))
    error = DeploymentRecoveryRequired("Remote work may still be running")
    error.__cause__ = SshCommandTimeout("upload timed out")

    def upload(plan, *, on_uploading, **kwargs):
        on_uploading(plan.uploads[0])
        raise error

    with pytest.raises(DeploymentRecoveryRequired) as caught:
        upload_and_verify_deployment_payload(
            AppConfig.from_values({}), device[4], prepared, DeployRuntimeConfig(nbns_enabled=False),
            upload_payload_func=upload,
        )
    assert caught.value is error
    assert caught.value.code == "deployment_recovery_required"


def test_uninstall_snapshot_cleanup_allows_reinstall_and_retains_metadata(device):
    transaction = deploy(device)
    transaction.finalize()
    transaction.release()
    from timecapsulesmb.deploy.transaction import run_ssh
    run_ssh(device[4], render_remote_action(RemovePayloadProgramsAction(device[0].payload_dir)))
    assert not Path(transaction.previous).exists()
    assert device[3].read_bytes() == b"irreplaceable metadata\0\xff"
    deploy(device).release()


def test_recovery_frees_partial_flash_copy_before_rewriting_guard(device, monkeypatch):
    flash_mdns = Path(device[0].flash_targets["mdns"])
    partial = flash_mdns.with_name(f".{flash_mdns.name}.deploy-new")
    original_install = DeploymentTransaction._install
    original_guard = DeploymentTransaction._arm_guard
    failed = False
    def install(self, source, destination, digest, mode=None):
        nonlocal failed
        if destination == str(flash_mdns) and not failed:
            failed = True
            partial.write_bytes(b"partial upload consuming the remaining Flash blocks")
            raise OSError("No space left on device")
        original_install(self, source, destination, digest, mode)
    def guard(self):
        if partial.exists():
            raise OSError("No space left for the recovery guard")
        original_guard(self)
    monkeypatch.setattr(DeploymentTransaction, "_install", install)
    monkeypatch.setattr(DeploymentTransaction, "_arm_guard", guard)
    with pytest.raises(OSError, match="No space left on device"):
        deploy(device)
    assert_recovered(device)
    assert not partial.exists()


def test_snapshot_rotation_preserves_unrecognized_contents_and_journal(device):
    first = deploy(device)
    first.finalize()
    first.release()
    note = Path(first.previous) / "recovery-notes"
    note.write_bytes(b"keep this information")
    current = deploy(device)
    with pytest.raises(subprocess.CalledProcessError):
        current.finalize()
    current.release()
    assert note.read_bytes() == b"keep this information"
    assert (Path(first.previous) / "journal.json").exists()
    assert (Path(current.root) / "journal.json").exists()


def test_snapshot_rotation_recovers_after_final_empty_directory_cleanup(device):
    transaction = deploy(device)
    Path(transaction.previous).mkdir()  # Power loss between unlink(journal) and rmdir.
    transaction.finalize()
    transaction.release()
    assert (Path(transaction.previous) / "journal.json").exists()
