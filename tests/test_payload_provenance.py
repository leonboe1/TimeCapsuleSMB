import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("payload_provenance", ROOT / "build/record_provenance.py")
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)
LANES = ["netbsd7", "netbsd4le", "netbsd4be"]
PAYLOADS = {
    "mdns": "mdns-advertiser.stripped",
    "nbns": "nbns-advertiser.stripped",
    "service": "service.stripped",
    "smbd": "sbin/smbd.stripped",
}


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("key", PAYLOADS)
def test_packaged_payload_matches_independent_build(lane, key):
    build = json.loads((ROOT / "build/provenance" / lane / "manifest.json").read_text())
    packaged = json.loads((ROOT / "src/timecapsulesmb/assets/artifact-manifest.json").read_text())
    suffix = "" if lane == "netbsd7" else "-" + lane
    record = packaged["artifacts"][key + suffix]
    actual = PROVENANCE.static_arm_record(ROOT / record["path"], lane)
    assert actual == build["artifacts"][PAYLOADS[key]]
    assert actual["sha256"] == record["sha256"]
    if key == "smbd":
        assert actual["bytes"] <= 10 * 1024 * 1024


@pytest.mark.parametrize("lane", LANES)
def test_build_evidence_matches_recorded_hashes(lane):
    directory = ROOT / "build/provenance" / lane
    build = json.loads((directory / "manifest.json").read_text())
    for name, record in build["evidence"].items():
        path = directory / name
        assert PROVENANCE.digest(path) == record["sha256"], name
        digest = hashlib.sha256()
        size = 0
        with gzip.open(path, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        assert digest.hexdigest() == record["uncompressed_sha256"], name
        assert size == record["uncompressed_bytes"], name
    assert build["evidence"]["smbd-link.map.gz"]["uncompressed_sha256"] == build["link_map_sha256"]
    for source in ["sdk", "samba"]:
        assert build["evidence"][source + ".patch.gz"]["uncompressed_sha256"] == build[source + "_source"]["patch_sha256"]
