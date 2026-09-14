#!/usr/bin/env python3
"""Record a clean checkout, SDK, link map and static ARM outputs without running them."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def source_record(root, inventory=False):
    record = {
        "commit": git(root, "rev-parse", "HEAD").decode().strip(),
        "patch_sha256": hashlib.sha256(git(root, "diff", "--binary", "HEAD")).hexdigest(),
    }
    if inventory:
        paths = git(root, "ls-files", "-z", "build", "tests/samba").decode().split("\0")
        record["files"] = {name: digest(root / name) for name in paths if name and (root / name).is_file()}
    return record


def static_arm_record(path, lane):
    data = path.read_bytes()
    endian = 2 if lane == "netbsd4be" else 1
    if data[:6] != b"\x7fELF\x01" + bytes([endian]):
        raise ValueError(f"Unexpected ELF architecture or endianness: {path}")
    order = ">" if endian == 2 else "<"
    header = struct.unpack_from(order + "HHIIIIIHHHHHH", data, 16)
    if header[0:2] != (2, 40):
        raise ValueError(f"Expected an ARM executable: {path}")
    offset, size, count = header[4], header[8], header[9]
    for index in range(count):
        kind = struct.unpack_from(order + "I", data, offset + index * size)[0]
        if kind in (2, 3):
            raise ValueError(f"Dynamic ELF segment in {path}")
    if b"timecapsulesmb.jamesyc.com" in data or b"/v1/router-heartbeats" in data:
        raise ValueError(f"Legacy telemetry endpoint in {path}")
    return {"sha256": digest(path), "bytes": len(data), "format": "static ELF32 ARM", "lane": lane}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--sdk-source", required=True, type=Path)
    parser.add_argument("--sdk-out", required=True, type=Path)
    parser.add_argument("--samba-source", required=True, type=Path)
    parser.add_argument("--samba-build", required=True, type=Path)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--lane", required=True, choices=["netbsd7", "netbsd4le", "netbsd4be"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if git(args.repo, "status", "--porcelain").strip():
        raise ValueError("Build checkout must be clean before recording provenance")
    artifacts = {name: static_arm_record(args.stage / name, args.lane) for name in (
        "mdns-advertiser.stripped", "nbns-advertiser.stripped", "service.stripped", "sbin/smbd.stripped",
    )}
    toolchain = {p.name: digest(p) for p in sorted((args.sdk_out / "tools/bin").iterdir()) if p.is_file()}
    compiler = next((args.sdk_out / "tools/bin").glob("*netbsd*-gcc"))
    link_map = args.samba_build / "smbd-link.map"
    if not link_map.is_file():
        raise ValueError("Samba link map is required")
    manifest = {
        "schema": 1,
        "builder": platform.platform(),
        "compiler": subprocess.check_output([str(compiler), "--version"]).decode().splitlines()[0],
        "lane": args.lane,
        "fork_source": source_record(args.repo, inventory=True),
        "sdk_source": source_record(args.sdk_source),
        "samba_source": source_record(args.samba_source),
        "toolchain_sha256": toolchain,
        "static_dependency_sha256": {p.name: digest(p) for p in sorted((args.samba_build / "deps/lib").glob("*.a"))},
        "source_archive_sha256": {p.name: digest(p) for p in sorted((args.samba_build / "distfiles").glob("*")) if p.is_file()},
        "link_map_sha256": digest(link_map),
        "artifacts": artifacts,
        "device_tests_performed": False,
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
