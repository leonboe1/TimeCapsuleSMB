from pathlib import Path
import shlex
import subprocess

import pytest

LOCK = Path(__file__).resolve().parents[1] / "build/_source_lock.sh"


@pytest.mark.parametrize("name", ["zlib-1.3.2.tar.gz", "gnutls-3.8.13.tar.xz", "nettle-3.10.2.tar.gz", "libtasn1-4.21.0.tar.gz", "gmp-6.3.0.tar.xz", "unreviewed.tar.gz"])
def test_source_lock_rejects_corrupt_and_unknown_archives(tmp_path, name):
    archive = tmp_path / name
    archive.write_bytes(b"modified download or cached archive")
    result = subprocess.run(["sh", "-c", f". {shlex.quote(str(LOCK))}; tc_verify_source_archive {shlex.quote(str(archive))}"], capture_output=True, text=True)
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr or "Unreviewed source" in result.stderr
