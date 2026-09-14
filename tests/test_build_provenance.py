import importlib.util
from pathlib import Path
import struct

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("record_provenance", ROOT / "build/record_provenance.py")
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


def test_static_arm_records_real_payload():
    path = ROOT / "bin/mdns/mdns-advertiser"
    record = PROVENANCE.static_arm_record(path, "netbsd7")
    assert record["sha256"] == PROVENANCE.digest(path)
    assert record["bytes"] == path.stat().st_size


def test_linked_archive_records_include_sdk_runtime_inputs(tmp_path):
    library = tmp_path / "libc.a"
    library.write_bytes(b"SDK runtime fixture")
    link_map = tmp_path / "smbd-link.map"
    link_map.write_text(f"{library}(exit.o)\nLOAD {library}\n")
    assert PROVENANCE.linked_archive_records(link_map) == {str(library): PROVENANCE.digest(library)}
    library.unlink()
    with pytest.raises(FileNotFoundError):
        PROVENANCE.linked_archive_records(link_map)


@pytest.mark.parametrize("change", ["endian", "dynamic", "interpreter", "telemetry"])
def test_provenance_rejects_wrong_or_unsafe_payloads(tmp_path, change):
    data = bytearray((ROOT / "bin/mdns/mdns-advertiser").read_bytes())
    if change == "endian":
        data[5] = 2
    elif change in {"dynamic", "interpreter"}:
        offset = struct.unpack_from("<I", data, 28)[0]
        struct.pack_into("<I", data, offset, 2 if change == "dynamic" else 3)
    else:
        data.extend(b"http://timecapsulesmb.jamesyc.com/v1/router-heartbeats")
    path = tmp_path / "payload"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        PROVENANCE.static_arm_record(path, "netbsd7")
