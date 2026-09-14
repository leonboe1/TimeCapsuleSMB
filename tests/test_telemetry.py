from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from timecapsulesmb.cli.context import (
    COMMAND_FIELD_BLACKLIST,
    COMMAND_VALUE_BLACKLIST,
    CommandContext,
)
from timecapsulesmb.services.context import render_operation_debug_lines
from timecapsulesmb.core.config import AppConfig, ConfigError
from timecapsulesmb.device.compat import DeviceCompatibility
from timecapsulesmb.device.errors import DeviceError
from timecapsulesmb.device.probe import ProbeResult, ProbedDeviceState, RemoteInterfaceProbeResult, SshAccessStatus
from timecapsulesmb.discovery.bonjour import BonjourResolvedService
from timecapsulesmb.services.runtime import ManagedTargetState
from timecapsulesmb.telemetry import TelemetryClient
from timecapsulesmb.telemetry.debug import render_debug_mapping
from timecapsulesmb.transport.ssh import SshConnection, SshError


def telemetry_client_from_values(
    values: dict[str, str] | None = None,
    **kwargs: object,
) -> TelemetryClient:
    return TelemetryClient.from_config(AppConfig.from_values(values or {}), **kwargs)


class TelemetryTests(unittest.TestCase):
    def test_legacy_settings_cannot_enable_collection_or_network_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bootstrap = Path(tmp) / ".bootstrap"
            bootstrap.write_text("INSTALL_ID=old-install\nTELEMETRY=true\n")
            with mock.patch.dict(os.environ, {"TCAPSULE_TELEMETRY_URL": "https://example.invalid", "TCAPSULE_TELEMETRY_TOKEN": "old-token"}):
                with mock.patch("urllib.request.urlopen") as network, mock.patch("subprocess.run") as collect:
                    client = telemetry_client_from_values({}, bootstrap_path=bootstrap)
                    client.emit("deploy_finished", synchronous=True, error="sensitive details")
                    self.assertFalse(client.enabled)
                    self.assertIsNone(client.context)
                    network.assert_not_called()
                    collect.assert_not_called()

    def test_command_context_records_normalized_options_and_details(self) -> None:
        telemetry = mock.Mock()
        args = SimpleNamespace(dry_run=False, no_reboot=False, no_wait=True, volume="Data", password="secret")

        command = CommandContext(telemetry, "fsck", "fsck_started", "fsck_finished", args=args)
        command.update_fields(
            fsck_device="/dev/dk2",
            fsck_mountpoint="/Volumes/Data",
            reboot_was_attempted=True,
            device_came_back_after_reboot=False,
        )
        command.finish(result="success")

        started_kwargs = telemetry.emit.call_args_list[0].kwargs
        finished_kwargs = telemetry.emit.call_args_list[1].kwargs
        self.assertEqual(started_kwargs["options"], {
            "dry_run": False,
            "no_reboot": False,
            "no_wait": True,
        })
        self.assertNotIn("password", started_kwargs["options"])
        self.assertEqual(finished_kwargs["details"]["volume"], "Data")
        self.assertEqual(finished_kwargs["details"]["fsck_device"], "/dev/dk2")
        self.assertEqual(finished_kwargs["details"]["fsck_mountpoint"], "/Volumes/Data")
        self.assertTrue(finished_kwargs["details"]["reboot_requested"])
        self.assertFalse(finished_kwargs["details"]["verified"])
        self.assertEqual(finished_kwargs["execution"]["version"], 1)

    def test_command_context_records_execution_stages_and_measurements(self) -> None:
        telemetry = mock.Mock()

        command = CommandContext(telemetry, "deploy", "deploy_started", "deploy_finished")
        command.set_stage("resolve_managed_target")
        command.set_stage("verify_runtime_activation")
        command.record_execution_measurement(
            "runtime_verification",
            stage="verify_runtime_activation",
            timeout_sec=200,
            ready=False,
            password="secret",
        )
        command.finish(result="failure")

        finished_kwargs = telemetry.emit.call_args_list[1].kwargs
        execution = finished_kwargs["execution"]
        self.assertEqual(execution["version"], 1)
        self.assertEqual(
            [stage["name"] for stage in execution["stages"]],
            ["resolve_managed_target", "verify_runtime_activation"],
        )
        self.assertEqual(execution["stages"][-1]["result"], "failure")
        self.assertEqual(execution["stage_totals"]["verify_runtime_activation"]["count"], 1)
        self.assertEqual(execution["measurements"]["runtime_verification"][0]["timeout_sec"], 200)
        self.assertNotIn("password", execution["measurements"]["runtime_verification"][0])

    def test_operation_telemetry_renames_reserved_legacy_fields(self) -> None:
        telemetry = mock.Mock()

        command = CommandContext(telemetry, "flash", "flash_started", "flash_finished")
        command.update_fields(operation="read")
        command.finish(result="success")

        finished_kwargs = telemetry.emit.call_args_list[1].kwargs
        self.assertEqual(finished_kwargs["operation"], "flash")
        self.assertEqual(finished_kwargs["legacy_operation"], "read")

    def test_command_context_ignores_started_telemetry_exception(self) -> None:
        telemetry = mock.Mock()
        telemetry.emit.side_effect = RuntimeError("telemetry unavailable")

        command = CommandContext(telemetry, "doctor", "doctor_started", "doctor_finished")
        command.succeed()

        self.assertEqual(command.result, "success")
        telemetry.emit.assert_called_once()

    def test_command_context_ignores_finished_telemetry_exception(self) -> None:
        telemetry = mock.Mock()
        telemetry.emit.side_effect = [None, RuntimeError("telemetry unavailable")]

        with CommandContext(telemetry, "doctor", "doctor_started", "doctor_finished") as command:
            command.succeed()

        self.assertEqual(command.result, "success")
        self.assertEqual(telemetry.emit.call_count, 2)

    def test_command_context_inspect_managed_connection_records_probe_state(self) -> None:
        telemetry = mock.Mock()
        connection = SshConnection("root@10.0.0.2", "pw", "-o foo")
        compatibility = DeviceCompatibility(
            os_name="NetBSD",
            os_release="6.0",
            arch="earmv4",
            elf_endianness="little",
            payload_family="netbsd6_samba4",
            device_generation="gen5",
            supported=True,
            reason_code="supported_netbsd6",
        )
        probe_state = ProbedDeviceState(
            probe_result=ProbeResult(
                ssh_status=SshAccessStatus.OPEN_AUTHENTICATED,
                error=None,
                os_name="NetBSD",
                os_release="6.0",
                arch="earmv4",
                elf_endianness="little",
                airport_model="TimeCapsule8,119",
                airport_syap="119",
            ),
            compatibility=compatibility,
        )
        interface_probe = RemoteInterfaceProbeResult(
            iface="bridge0",
            exists=True,
            detail="interface bridge0 exists",
        )
        target = ManagedTargetState(
            connection=connection,
            interface_probe=interface_probe,
            probe_state=probe_state,
        )
        config = AppConfig.from_values({
            "TC_HOST": connection.host,
            "TC_PASSWORD": connection.password,
            "TC_SSH_OPTS": connection.ssh_opts,
        })

        context = CommandContext(
            telemetry,
            "doctor",
            "doctor_started",
            "doctor_finished",
            config=config,
        )
        with mock.patch(
            "timecapsulesmb.cli.context.service_runtime.resolve_env_connection",
            return_value=connection,
        ) as resolve_mock:
            with mock.patch(
                "timecapsulesmb.cli.context.service_runtime.inspect_managed_connection",
                return_value=target,
            ) as inspect_mock:
                result = context.inspect_managed_connection(iface="bridge0", include_probe=True)

        self.assertIs(result, target)
        self.assertIs(context.connection, connection)
        self.assertIs(context.interface_probe, interface_probe)
        self.assertIs(context.probe_state, probe_state)
        self.assertIs(context.compatibility, compatibility)
        self.assertEqual(context.finish_fields["device_family"], "netbsd6_samba4")
        self.assertEqual(context.finish_fields["device_os_version"], "NetBSD 6.0 (earmv4)")
        self.assertEqual(context.finish_fields["device_model"], "TimeCapsule8,119")
        self.assertEqual(context.finish_fields["device_syap"], "119")
        resolve_mock.assert_called_once()
        inspect_mock.assert_called_once_with(connection, "bridge0", include_probe=True)

    def test_command_context_finish_harvests_fast_optional_airport_identity_probe(self) -> None:
        telemetry = mock.Mock()
        connection = SshConnection("root@10.0.0.2", "pw", "-o foo")
        context = CommandContext(
            telemetry,
            "fsck",
            "fsck_started",
            "fsck_finished",
        )

        with mock.patch(
            "timecapsulesmb.cli.context.probe_remote_airport_identity_conn",
            return_value=SimpleNamespace(model="AirPort7,120", syap="120"),
        ):
            context.start_optional_airport_identity_probe(connection)
            context.finish(result="success")

        payload = telemetry.emit.call_args_list[-1].kwargs
        self.assertEqual(payload["device_model"], "AirPort7,120")
        self.assertEqual(payload["device_syap"], "120")

    def test_command_context_finish_only_waits_briefly_for_slow_optional_airport_identity_probe(self) -> None:
        telemetry = mock.Mock()
        connection = SshConnection("root@10.0.0.2", "pw", "-o foo")
        release_probe = threading.Event()

        def slow_probe(_connection: SshConnection) -> SimpleNamespace:
            release_probe.wait(1)
            return SimpleNamespace(model="AirPort7,120", syap="120")

        context = CommandContext(
            telemetry,
            "fsck",
            "fsck_started",
            "fsck_finished",
        )

        with mock.patch("timecapsulesmb.cli.context.probe_remote_airport_identity_conn", side_effect=slow_probe):
            context.start_optional_airport_identity_probe(connection)
            started = time.monotonic()
            context.finish(result="success")
            elapsed = time.monotonic() - started
            release_probe.set()

        payload = telemetry.emit.call_args_list[-1].kwargs
        self.assertLess(elapsed, 0.5)
        self.assertNotIn("device_model", payload)
        self.assertNotIn("device_syap", payload)

    def test_command_context_resolve_env_connection_requires_config(self) -> None:
        command = CommandContext(
            mock.Mock(),
            "deploy",
            "deploy_started",
            "deploy_finished",
            values={"TC_HOST": "root@10.0.0.2"},
        )

        with self.assertRaisesRegex(RuntimeError, "CommandContext config is not set"):
            command.resolve_env_connection()

    def test_command_context_render_debug_mapping_applies_password_and_duplicate_blacklists(self) -> None:
        lines = render_debug_mapping(
            {
                "TC_HOST": "root@192.168.1.217",
                "TC_PASSWORD": "secret",
                "TC_MDNS_HOST_LABEL": "legacy-host",
                "TC_MDNS_INSTANCE_NAME": "Legacy Instance",
                "TC_NETBIOS_NAME": "LegacyNetbios",
                "TC_CONFIGURE_ID": "config-id",
                "TC_INTERNAL_SHARE_USE_DISK_ROOT": "true",
            },
            blacklist=COMMAND_VALUE_BLACKLIST,
        )

        self.assertEqual(lines, ["TC_HOST=root@192.168.1.217", "TC_INTERNAL_SHARE_USE_DISK_ROOT=true"])

        lines = render_debug_mapping(
            {
                "device_os_version": "NetBSD 6.0 (earmv4)",
                "device_family": "netbsd6_samba4",
                "selected_net_iface": "bridge0",
            },
            blacklist=COMMAND_FIELD_BLACKLIST,
        )

        self.assertEqual(lines, ["selected_net_iface=bridge0"])

    def test_render_operation_debug_lines_combines_context_sources(self) -> None:
        state = ProbedDeviceState(
            probe_result=ProbeResult(
                ssh_status=SshAccessStatus.AUTH_REJECTED,
                error="SSH authentication failed.",
                os_name="",
                os_release="",
                arch="",
                elf_endianness="unknown",
            ),
            compatibility=None,
        )
        lines = render_operation_debug_lines(
            operation_name="configure",
            stage="ssh_probe",
            connection=SshConnection("root@192.168.1.217", "secret", "-o ProxyJump=bastion"),
            values={
                "TC_HOST": "root@10.0.1.1",
                "TC_PASSWORD": "secret",
                "TC_SSH_OPTS": "-o ProxyJump=old",
                "TC_INTERNAL_SHARE_USE_DISK_ROOT": "true",
                "TC_MDNS_DEVICE_MODEL": "TimeCapsule8,119",
            },
            preflight_error="preflight failed",
            finish_fields={
                "device_family": "netbsd6_samba4",
                "reboot_was_attempted": True,
                "custom_finish": "kept",
            },
            probe_state=state,
            debug_fields={
                "device_model": "TimeCapsule8,119",
                "selected_net_iface": "bridge0",
            },
        )

        self.assertEqual(lines[0:3], ["Debug context:", "command=configure", "stage=ssh_probe"])
        self.assertIn("host=root@192.168.1.217", lines)
        self.assertIn("ssh_opts=-o ProxyJump=bastion", lines)
        self.assertIn("TC_HOST=root@10.0.1.1", lines)
        self.assertIn("TC_INTERNAL_SHARE_USE_DISK_ROOT=true", lines)
        self.assertIn("preflight_error=preflight failed", lines)
        self.assertIn("custom_finish=kept", lines)
        self.assertIn("probe_ssh_port_reachable=true", lines)
        self.assertIn("probe_ssh_authenticated=false", lines)
        self.assertIn("probe_error=SSH authentication failed.", lines)
        self.assertIn("selected_net_iface=bridge0", lines)
        self.assertNotIn("TC_PASSWORD=secret", lines)
        self.assertNotIn("TC_MDNS_DEVICE_MODEL=TimeCapsule8,119", lines)
        self.assertNotIn("device_family=netbsd6_samba4", lines)
        self.assertNotIn("reboot_was_attempted=true", lines)
        self.assertNotIn("device_model=TimeCapsule8,119", lines)

    def test_render_operation_debug_lines_uses_values_when_connection_is_missing(self) -> None:
        lines = render_operation_debug_lines(
            operation_name="doctor",
            stage=None,
            connection=None,
            values={"TC_HOST": "root@10.0.0.1", "TC_SSH_OPTS": "-o ConnectTimeout=5"},
            preflight_error=None,
            finish_fields={},
            probe_state=None,
            debug_fields={},
        )

        self.assertIn("host=root@10.0.0.1", lines)
        self.assertIn("ssh_opts=-o ConnectTimeout=5", lines)

    def test_render_operation_debug_lines_includes_env_path_when_config_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            lines = render_operation_debug_lines(
                operation_name="deploy",
                stage="validate_config",
                connection=None,
                values={},
                preflight_error=None,
                finish_fields={},
                probe_state=None,
                debug_fields={},
                config=AppConfig.from_values({}, path=env_path, exists=False, file_values={}),
            )

        self.assertIn(f"env_path={env_path}", lines)


if __name__ == "__main__":
    unittest.main()
