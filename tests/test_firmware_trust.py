import gzip
import hashlib
from unittest import mock

import pytest

from timecapsulesmb import apple_firmware as firmware, flash


@pytest.fixture
def approved(monkeypatch):
    entry = {"productID": "119", "version": "7.9.1", "location": "https://apsu.apple.com/firmware.basebinary", "sizeInBytes": 4, "sha256": hashlib.sha256(b"good").hexdigest()}
    monkeypatch.setattr(firmware, "pinned_firmware_entries", lambda: [entry])
    return entry


@pytest.mark.parametrize("url", ["https://evil.invalid/image", "file:///tmp/image", "http://apsu.apple.com.evil.invalid/image", "https://user@apsu.apple.com/image", "https://apsu.apple.com:444/image"])
def test_untrusted_origins_rejected_before_request(url):
    with mock.patch.object(firmware, "build_opener") as opener:
        with pytest.raises(firmware.FlashAnalysisError, match="approved Apple origin"):
            firmware.download_url(url)
        opener.assert_not_called()


def test_http_catalog_url_is_upgraded_and_redirects_rejected():
    assert firmware.trusted_apple_url("http://apsu.apple.com/image") == "https://apsu.apple.com/image"
    with pytest.raises(firmware.FlashAnalysisError, match="redirects"):
        firmware._NoRedirect().redirect_request(None, None, 302, "", {}, "http://apsu.apple.com/image")


def test_same_size_cache_poisoning_is_detected(approved, tmp_path, monkeypatch):
    path = firmware.firmware_template_cache_path(cache_dir=tmp_path, product_id="119", version="7.9.1", url=approved["location"])
    path.parent.mkdir()
    path.write_bytes(b"evil")
    monkeypatch.setattr(firmware, "download_url", lambda *a, **k: b"good")
    candidate = firmware.read_cached_or_download_template(approved, cache_dir=tmp_path)
    assert candidate.data == b"good" and not candidate.from_cache
    assert path.read_bytes() == b"good"


def test_tampered_download_is_never_cached(approved, tmp_path, monkeypatch):
    monkeypatch.setattr(firmware, "download_url", lambda *a, **k: b"evil")
    with pytest.raises(firmware.FlashAnalysisError, match="checksum"):
        firmware.read_cached_or_download_template(approved, cache_dir=tmp_path)
    assert not list(tmp_path.rglob("*.basebinary"))


def test_local_template_is_pinned_to_device(approved, tmp_path):
    path = tmp_path / "local.basebinary"
    path.write_bytes(b"good")
    assert len(list(firmware.resolve_firmware_template_candidates(syap="119", firmware_template=path))) == 1
    with pytest.raises(firmware.FlashAnalysisError, match="reviewed image"):
        list(firmware.resolve_firmware_template_candidates(syap="120", firmware_template=path))
    path.write_bytes(b"evil")
    with pytest.raises(firmware.FlashAnalysisError, match="reviewed image"):
        list(firmware.resolve_firmware_template_candidates(syap="119", firmware_template=path))


def test_gzip_rejects_truncation_and_expansion_limit(monkeypatch):
    compressed = gzip.compress(b"A" * 128)
    assert flash._decompress_gzip_member(compressed, 0).decompressed == b"A" * 128
    assert flash._decompress_gzip_member(compressed[:-4], 0) is None
    monkeypatch.setattr(flash, "MAX_GZIP_MEMBER_BYTES", 32)
    assert flash._decompress_gzip_member(compressed, 0) is None
