from __future__ import annotations

import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from timecapsulesmb.apple_firmware import (
    FlashAnalysisError,
    download_firmware_template_to_cache,
    firmware_template_cache_path,
    load_apple_firmware_catalog,
)


class AppleFirmwareTests(unittest.TestCase):
    def test_cache_path_sanitizes_dot_dot_components(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)

            path = firmware_template_cache_path(
                cache_dir=cache_dir,
                product_id="..",
                version="..",
                url="https://example.invalid/../firmware.basebinary",
            )

        self.assertNotIn("..", path.relative_to(cache_dir).parts)
        self.assertEqual(path.parent.name, "device")
        self.assertTrue(path.name.startswith("device-"))

    def test_catalog_uses_reviewed_manifest_despite_poisoned_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            (cache_dir / "version.xml").write_bytes(plistlib.dumps({"firmwareUpdates": [{"location": "http://attacker.invalid"}]}))
            with mock.patch("timecapsulesmb.apple_firmware.download_url") as download:
                entries = load_apple_firmware_catalog(cache_dir=cache_dir)
            self.assertEqual(len(entries), 110)
            self.assertTrue(all(entry["location"].startswith("https://apsu.apple.com/") for entry in entries))
            self.assertTrue(all(len(entry["sha256"]) == 64 for entry in entries))
            download.assert_not_called()


    def test_template_cache_write_failure_does_not_leave_target_or_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            path = cache_dir / "113" / "7.8.1.basebinary"

            import hashlib
            entry = {"location": "https://apsu.apple.com/7.8.1.basebinary", "productID": "113", "version": "7.8.1", "sizeInBytes": 8, "sha256": hashlib.sha256(b"template").hexdigest()}
            with mock.patch("timecapsulesmb.apple_firmware.pinned_firmware_entries", return_value=[entry]), mock.patch("timecapsulesmb.apple_firmware.download_url", return_value=b"template"):
                with mock.patch("timecapsulesmb.apple_firmware.os.replace", side_effect=OSError("disk full")):
                    with self.assertRaises(FlashAnalysisError) as raised:
                        download_firmware_template_to_cache(
                            url="https://apsu.apple.com/7.8.1.basebinary",
                            path=path,
                            product_id="113",
                            version="7.8.1",
                            expected_size=len(b"template"),
                        )

            leftovers = list(path.parent.glob(f".{path.name}.*.tmp"))
            target_exists = path.exists()

        self.assertIn("failed to write Apple firmware template cache", str(raised.exception))
        self.assertFalse(target_exists)
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
