import shlex
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("nbns_enabled", [0, 1])
@pytest.mark.parametrize("stop_status", [0, 1])
def test_samba_releases_apple_listener_independently_of_nbns(tmp_path, nbns_enabled, stop_status):
    manager = (Path(__file__).parents[1] / "src/timecapsulesmb/assets/boot/samba4/manager.sh").read_text()
    function = manager.split("tc_manager_start_smbd_if_needed() {", 1)[1].split(
        "tc_manager_apply_smbd_runtime_changes() {", 1,
    )[0]
    binary = tmp_path / "smbd"
    binary.write_text('#!/bin/sh\n[ ! -f "$APPLE_LISTENER" ] || exit 1\ntouch "$SAMBA_LISTENER"\n')
    binary.chmod(0o700)
    config = tmp_path / "smb.conf"
    config.touch()
    apple = tmp_path / "apple-listener"
    apple.touch()
    samba = tmp_path / "samba-listener"
    locks = tmp_path / "locks"
    locks.mkdir()
    script = f"""
        set -eu
        export APPLE_LISTENER={shlex.quote(str(apple))} SAMBA_LISTENER={shlex.quote(str(samba))}
        NBNS_ENABLED={nbns_enabled}
        TC_SMBD_BIN={shlex.quote(str(binary))}
        TC_SMBD_CONF={shlex.quote(str(config))}
        LOCKS_ROOT={shlex.quote(str(locks))}
        tc_log() {{ :; }}
        runtime_process_present_by_ucomm() {{ return 1; }}
        tc_manager_refresh_runtime_identity_for_recovery() {{ :; }}
        tc_manager_validate_smbd_runtime_state() {{ :; }}
        tc_log_smbd_socket_diagnostics() {{ :; }}
        stop_runtime_process_by_ucomm() {{
            [ "$2" = wcifsfs ] || exit 99
            [ {stop_status} = 0 ] || return 1
            rm "$APPLE_LISTENER"
        }}
        wait_for_process() {{ test -f "$SAMBA_LISTENER"; }}
        tc_wait_for_smbd_ipv4_445() {{ test -f "$SAMBA_LISTENER"; }}
        tc_manager_start_smbd_if_needed() {{{function}
        tc_manager_start_smbd_if_needed
    """
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
    assert result.returncode == stop_status, result.stderr
    assert samba.exists() == (stop_status == 0)
    assert apple.exists() == (stop_status != 0)
