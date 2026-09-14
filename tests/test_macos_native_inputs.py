from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "macos/TimeCapsuleSMB/tools/native_inputs.py"


@pytest.fixture
def native():
    spec = importlib.util.spec_from_file_location("tested_native_inputs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, kind, value in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
            else:
                info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                info.linkname = value
                tar.addfile(info)
    return path


@pytest.mark.parametrize("entries", [
    [("../escape", "file", b"outside")],
    [("/absolute", "file", b"outside")],
    [("link", "symlink", "../outside")],
    [("link", "hardlink", "../outside")],
    [("same", "file", b"first"), ("same", "file", b"second")],
])
def test_archive_rejects_escapes_and_replacements(native, tmp_path, entries):
    with pytest.raises(RuntimeError):
        native.extract_archive(archive(tmp_path / "input.tgz", entries), tmp_path / "output")
    assert not (tmp_path / "escape").exists()


def test_archive_keeps_safe_library_links(native, tmp_path):
    source = archive(tmp_path / "input.tgz", [("lib/actual.dylib", "file", b"library"),
        ("lib/alias.dylib", "symlink", "actual.dylib")])
    native.extract_archive(source, tmp_path / "output")
    assert (tmp_path / "output/lib/alias.dylib").read_bytes() == b"library"


def test_cached_download_rehashed_before_use(native, tmp_path):
    original = b"publisher archive"
    expected = hashlib.sha256(original).hexdigest()
    cached = tmp_path / (expected + ".archive")
    cached.write_bytes(original)
    record = {"url": "https://example.invalid/archive", "sha256": expected}
    assert native.verified_download(record, tmp_path) == cached
    cached.write_bytes(b"modified cache")
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        native.verified_download(record, tmp_path)


def test_bundle_rejects_local_overrides_before_download(native, monkeypatch, tmp_path):
    monkeypatch.setenv("TCAPSULE_PACKAGE_SMBCLIENT", "/unapproved/smbclient")
    with pytest.raises(RuntimeError, match="overrides are disabled"):
        native.bundle(tmp_path, ("arm64",), tmp_path, None)


def test_bundle_rejects_architecture_without_reviewed_graph(native, tmp_path):
    with pytest.raises(RuntimeError, match="No reviewed native dependency set"):
        native.bundle(tmp_path, ("x86_64",), tmp_path, None)


def test_dependency_resolution_never_uses_local_homebrew(native, tmp_path):
    keg = tmp_path / "gmp/6.3.0"
    (keg / "lib").mkdir(parents=True)
    library = keg / "lib/libgmp.dylib"
    library.write_bytes(b"authenticated library")
    assert native.resolve_library(tmp_path / "smbclient", "/opt/homebrew/opt/gmp/lib/libgmp.dylib", {"gmp": keg}, tmp_path) == library
    with pytest.raises(RuntimeError, match="Unapproved or missing"):
        native.resolve_library(tmp_path / "smbclient", "/opt/homebrew/opt/unreviewed/lib/unapproved.dylib", {"gmp": keg}, tmp_path)


def test_dependency_resolution_rejects_escaping_loader_path(native, tmp_path):
    root = tmp_path / "extracted"
    root.mkdir()
    (tmp_path / "unapproved.dylib").write_bytes(b"unexpected")
    with pytest.raises(RuntimeError, match="Unapproved or missing"):
        native.resolve_library(root / "tool", "@loader_path/../unapproved.dylib", {}, root)


def test_copy_closure_rewrites_recursive_dependencies_and_records_hashes(native, monkeypatch, tmp_path):
    root = tmp_path / "inputs"
    keg = root / "samba/1"
    (keg / "lib").mkdir(parents=True)
    tool = keg / "client"
    library = keg / "lib/a.dylib"
    child = keg / "lib/b.dylib"
    for path in (tool, library, child):
        path.write_bytes(path.name.encode())
    dependencies = {tool: ["/opt/homebrew/opt/samba/lib/a.dylib"], library: ["@loader_path/b.dylib"], child: ["/usr/lib/libSystem.B.dylib"]}
    changes = []
    api = SimpleNamespace(macho_dependencies=lambda p: dependencies[p],
        run_quiet=lambda cmd: changes.append(cmd), set_macho_id_if_supported=lambda path: None)
    monkeypatch.setattr(native, "rpaths", lambda loader: [])
    app = tmp_path / "output.app"
    records = native.copy_closure({"smbclient": tool}, app, {"samba": keg}, root, api)
    assert len(records) == 3
    assert all(native.digest(root / r["input_path"]) == r["input_sha256"] for r in records)
    assert len(changes) == 2
    assert all(cmd[3].startswith("@loader_path/") for cmd in changes)


@pytest.mark.parametrize("minimum,accepted", [("14.0", True), ("14.8", True), ("14.8.1", False), ("15.0", False)])
def test_macos_minimum_matches_actual_library_requirements(native, monkeypatch, tmp_path, minimum, accepted):
    monkeypatch.setattr(native.subprocess, "check_output", lambda *args, **kwargs: f"cmd LC_BUILD_VERSION\n minos {minimum}\n")
    files = [{"output_path": "library.dylib"}]
    if accepted:
        native.validate_minimum_macos(tmp_path, files, "14.8")
    else:
        with pytest.raises(RuntimeError, match="exceeds the declared"):
            native.validate_minimum_macos(tmp_path, files, "14.8")
