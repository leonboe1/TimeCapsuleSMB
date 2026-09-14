from pathlib import Path

import pytest

from timecapsulesmb.repair_xattrs import RepairSummary, iter_scan_paths


@pytest.mark.parametrize("directory", ["Laptop.sparsebundle", "Backups.backupdb", ".timemachine", ".samba4"])
@pytest.mark.parametrize("selection", ["root", "subdirectory", "file", "symlink"])
@pytest.mark.parametrize("include_time_machine", [False, True])
def test_selected_root_preserves_protected_ancestors(tmp_path, directory, selection, include_time_machine):
    protected = tmp_path / directory
    nested = protected / "private" / "bands"
    nested.mkdir(parents=True)
    target = nested / "0"
    target.write_bytes(b"irreplaceable data")
    root = {"root": protected, "subdirectory": nested, "file": target}.get(selection)
    if selection == "symlink":
        root = tmp_path / "ordinary-looking-link"
        root.symlink_to(nested, target_is_directory=True)
    summary = RepairSummary()
    scanned = list(iter_scan_paths(
        root, recursive=True, max_depth=None, include_hidden=True,
        include_time_machine=include_time_machine, include_directories=True,
        include_root_directory=True, summary=summary,
    ))
    if directory == ".samba4" or not include_time_machine:
        assert scanned == []
        assert summary.skipped == 1
    else:
        assert (target.resolve(), "file") in scanned
    assert target.read_bytes() == b"irreplaceable data"


def test_ordinary_scan_still_excludes_nested_backups_and_metadata(tmp_path):
    for name in ("Laptop.sparsebundle", ".samba4", "ordinary"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "file").touch()
    scanned = list(iter_scan_paths(
        tmp_path, recursive=True, max_depth=None, include_hidden=True,
        include_time_machine=False, summary=RepairSummary(),
    ))
    assert scanned == [(Path(tmp_path / "ordinary/file").resolve(), "file")]
