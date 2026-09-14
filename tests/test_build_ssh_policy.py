import os
from pathlib import Path
import subprocess
from unittest import mock

from timecapsulesmb.transport.ssh import host_verification_args


ROOT = Path(__file__).resolve().parents[1]


def test_build_ssh_policy_overrides_legacy_insecure_options(tmp_path):
    env = dict(os.environ, TC_ENV_FILE=str(tmp_path / "absent.env"),
               TC_NETBSD7_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=auto -o ControlPath=/tmp/old-master")
    result = subprocess.run(
        ["sh", "-c", '. "$1"; tc_ssh -G example.invalid', str(ROOT / "build/env.sh"), str(ROOT / "build/env.sh")],
        env=env, capture_output=True, text=True, check=True,
    )
    options = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    assert options["stricthostkeychecking"] == "true"
    assert options["controlmaster"] == "false"
    assert options.get("controlpath", "none") == "none"
    assert options["userknownhostsfile"] != "/dev/null"
    assert options["verifyhostkeydns"] == "false"
    assert options["updatehostkeys"] == "false"


def test_transport_preserves_known_hosts_path_with_spaces(tmp_path):
    path = tmp_path / "home with spaces" / ".ssh/known_hosts"
    with mock.patch("timecapsulesmb.transport.ssh.known_hosts_path", return_value=path):
        args = host_verification_args()
    result = subprocess.run(["ssh", *args, "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/old-master", "-G", "example.invalid"], capture_output=True, text=True, check=True)
    options = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    assert options["userknownhostsfile"] == str(path)
    assert options["controlmaster"] == "false"
    assert options.get("controlpath", "none") == "none"
