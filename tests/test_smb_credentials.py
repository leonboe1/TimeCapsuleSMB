"""Exercise private password delivery with local child processes, without SMB/network access."""
import hashlib
import os
import subprocess
import sys
from unittest.mock import Mock

import pytest

from timecapsulesmb.checks import smb


@pytest.mark.parametrize("operation", ["listing", "file_ops"])
@pytest.mark.parametrize("password", ["dummy secret % ' \" $ value", "pässwörd-秘密", "x" * 127, "ü" * 63 + "x", ""])
def test_password_reaches_child_only_through_private_stdin(tmp_path, monkeypatch, operation, password):
    received = tmp_path / "credentials-received"
    child = tmp_path / "fake_smbclient.py"
    child.write_text(f"""
import hashlib, os, pathlib, stat, sys
assert stat.S_ISFIFO(os.fstat(0).st_mode)
assert not any(k in os.environ for k in ('PASSWD', 'PASSWD_FILE', 'USER', 'LOGNAME'))
data = sys.stdin.buffer.read()
assert hashlib.sha256(data).hexdigest() == {hashlib.sha256((password + chr(10) if password else '').encode()).hexdigest()!r}
if data:
    assert os.environ['PASSWD_FD'] == '0'
    secret = data[:-1].decode()
    assert all(secret not in arg for arg in sys.argv)
    assert all(secret not in value for value in os.environ.values())
else:
    assert 'PASSWD_FD' not in os.environ
    assert '-N' in sys.argv
pathlib.Path({str(received)!r}).touch()
print('Disk|Data|')
sys.exit({0 if operation == 'listing' else 1})
""")
    # A caller's ambient credentials must not override the pipe password.
    for key in ("PASSWD", "PASSWD_FD", "PASSWD_FILE", "USER", "LOGNAME"):
        monkeypatch.setenv(key, "unrelated-ambient-credential")
    monkeypatch.setattr(smb, "command_exists", lambda name: True)
    monkeypatch.setattr(smb, "_smbclient_base_args", lambda: [sys.executable, str(child)])
    if operation == "listing":
        result = smb.check_authenticated_smb_listing("root", password, "test.invalid")
        assert result.status == "PASS", result
    else:
        result = smb.check_authenticated_smb_file_ops_detailed("root", password, "test.invalid", "Data")
        # Intentionally end after the first command: no real share is accessed.
        assert result[0].status == "FAIL"
    assert received.exists()


def test_password_is_absent_from_timeout_and_child_is_reaped(tmp_path):
    child = tmp_path / "slow_smbclient.py"
    child.write_text("import os, sys, time\nsys.stdin.buffer.read()\nprint(os.getpid(), flush=True)\ntime.sleep(30)\n")
    password = "dummy-timeout-secret"
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        smb._run_authenticated_smbclient([sys.executable, str(child)], password, timeout=1)
    assert password not in str(caught.value)
    assert all(password not in arg for arg in caught.value.cmd)
    pid = int(caught.value.stdout.strip())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_password_is_absent_from_process_start_error(tmp_path):
    password = "dummy-start-error-secret"
    with pytest.raises(FileNotFoundError) as caught:
        smb._run_authenticated_smbclient([str(tmp_path / "missing-smbclient")], password, timeout=1)
    assert password not in str(caught.value)


@pytest.mark.parametrize("value", ["prefix\nsuffix", "prefix\rsuffix", "prefix\0suffix"])
def test_line_passwords_are_rejected_before_starting_a_process(monkeypatch, value):
    run = Mock()
    monkeypatch.setattr(smb, "run_local_capture", run)
    with pytest.raises(ValueError, match="SMB passwords"):
        smb._run_authenticated_smbclient(["smbclient"], value, timeout=1)
    run.assert_not_called()


def test_username_cannot_inject_an_argv_password():
    with pytest.raises(ValueError, match="SMB usernames"):
        smb._smbclient_listing_args(smb.SmbClientTarget("test.invalid"), "root%secret")


@pytest.mark.parametrize("password", ["x" * 128, "ü" * 64])
def test_password_beyond_samba_fd_limit_is_rejected_before_start(monkeypatch, password):
    run = Mock()
    monkeypatch.setattr(smb, "run_local_capture", run)
    with pytest.raises(ValueError, match="127-byte pipe limit"):
        smb._run_authenticated_smbclient(["smbclient"], password, timeout=1)
    run.assert_not_called()
