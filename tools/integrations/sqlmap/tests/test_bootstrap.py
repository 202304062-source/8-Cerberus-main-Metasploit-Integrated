from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.integrations.sqlmap.bootstrap import _safe_extract


class SafeArchiveExtractionTests(unittest.TestCase):
    def test_extracts_valid_sqlmap_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            archive_path = temp_root / "sqlmap.zip"
            extraction_root = temp_root / "extracted"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("sqlmap-master/sqlmap.py", "# sqlmap stub\\n")
                archive.writestr("sqlmap-master/LICENSE", "license stub\\n")
            with zipfile.ZipFile(archive_path) as archive:
                extracted = _safe_extract(archive, extraction_root)
            self.assertIsNotNone(extracted)
            self.assertTrue((extracted / "sqlmap.py").is_file())
            self.assertTrue((extracted / "LICENSE").is_file())

    def test_rejects_posix_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            archive_path = temp_root / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.txt", "not allowed")
            with zipfile.ZipFile(archive_path) as archive:
                with self.assertRaises(RuntimeError):
                    _safe_extract(archive, temp_root / "extracted")
            self.assertFalse((temp_root / "outside.txt").exists())

    def test_rejects_windows_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            archive_path = temp_root / "bad-windows.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(r"..\outside.txt", "not allowed")
            with zipfile.ZipFile(archive_path) as archive:
                with self.assertRaises(RuntimeError):
                    _safe_extract(archive, temp_root / "extracted")
            self.assertFalse((temp_root / "outside.txt").exists())


if __name__ == "__main__":
    unittest.main()
