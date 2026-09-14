from __future__ import annotations

import platform
import subprocess
from pathlib import Path

from timecapsulesmb.core.config import AppConfig


class TelemetryClient:
    """Compatibility sink for local operation instrumentation; never sends data."""

    enabled = False
    context = None

    @classmethod
    def from_config(
        cls,
        config: AppConfig,
        *,
        nbns_enabled: bool | None = None,
        bootstrap_path: Path | None = None,
        include_device_identity: bool = True,
    ) -> "TelemetryClient":
        # Do not collect host/device identity or honor legacy endpoint overrides.
        return cls()

    def emit(self, event: str, **fields: object) -> None:
        pass


def build_device_os_version(os_name: str | None, os_release: str | None, arch: str | None) -> str | None:
    if not os_name or not os_release or not arch:
        return None
    return f"{os_name} {os_release} ({arch})"


def detect_host_os() -> str:
    if sys_platform_is_macos():
        return "macOS"
    if sys_platform_is_linux():
        return detect_linux_id() or "Linux"
    return platform.system() or "unknown"


def detect_host_os_version() -> str:
    if sys_platform_is_macos():
        version = run_text_command(["sw_vers", "-productVersion"])
        if version:
            return version
        return platform.mac_ver()[0] or "unknown"
    if sys_platform_is_linux():
        return detect_linux_version_id() or platform.release() or "unknown"
    return platform.release() or "unknown"


def sys_platform_is_macos() -> bool:
    return platform.system() == "Darwin"


def sys_platform_is_linux() -> bool:
    return platform.system() == "Linux"


def run_text_command(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        return None
    value = proc.stdout.strip()
    return value or None


def infer_operation_phase(event: str) -> tuple[str | None, str | None]:
    if event.endswith("_started"):
        return event.removesuffix("_started").replace("_", "-"), "started"
    if event.endswith("_finished"):
        return event.removesuffix("_finished").replace("_", "-"), "finished"
    return None, None


def parse_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def detect_linux_id() -> str | None:
    values = parse_os_release()
    return values.get("ID") or None


def detect_linux_version_id() -> str | None:
    values = parse_os_release()
    return values.get("VERSION_ID") or None
