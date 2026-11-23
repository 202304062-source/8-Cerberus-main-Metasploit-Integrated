from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.integrations.sqlmap.runner import (
    TargetValidationError,
    build_sqlmap_command,
    validate_target_url,
)


class ValidateTargetUrlTests(unittest.TestCase):
    def test_accepts_http_and_https_urls(self) -> None:
        self.assertEqual(validate_target_url("https://example.test/item?id=7"), "https://example.test/item?id=7")
        self.assertEqual(validate_target_url("http://127.0.0.1:8080/shop?id=1"), "http://127.0.0.1:8080/shop?id=1")

    def test_trims_surrounding_whitespace(self) -> None:
        self.assertEqual(validate_target_url("  https://example.test/  "), "https://example.test/")

    def test_rejects_empty_target(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url(" ")

    def test_rejects_non_http_scheme(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url("ftp://example.test/file")

    def test_rejects_missing_host(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url("https:///path")

    def test_rejects_embedded_credentials(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url("https://user:password@example.test/")

    def test_rejects_malformed_port(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url("https://example.test:not-a-port/")

    def test_rejects_whitespace_inside_url(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target_url("https://example.test/a b")


class CommandConstructionTests(unittest.TestCase):
    def test_builds_constrained_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sqlmap_home = root / "sqlmap"
            sqlmap_home.mkdir()
            (sqlmap_home / "sqlmap.py").write_text("# test stub\n", encoding="utf-8")
            output = root / "scan output"

            command = build_sqlmap_command(
                sqlmap_home,
                "https://example.test/product?id=3",
                output,
                python_executable="python-test",
            )

        self.assertEqual(command[0], "python-test")
        self.assertIn("--batch", command)
        self.assertIn("--level=1", command)
        self.assertIn("--risk=1", command)
        self.assertIn("--technique=BE", command)
        self.assertIn("--threads=1", command)
        self.assertIn("--ignore-redirects", command)
        self.assertIn("https://example.test/product?id=3", command)
        self.assertTrue(any(arg.startswith("--output-dir=") for arg in command))

    def test_does_not_add_data_extraction_or_os_access_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sqlmap_home = root / "sqlmap"
            sqlmap_home.mkdir()
            (sqlmap_home / "sqlmap.py").write_text("# test stub\n", encoding="utf-8")
            command = build_sqlmap_command(sqlmap_home, "https://example.test/?id=1", root / "reports")

        forbidden = {"--dump", "--dbs", "--tables", "--columns", "--os-shell", "--sql-shell", "--file-read", "--file-write", "--crawl", "--forms"}
        self.assertTrue(forbidden.isdisjoint(set(command)))

    def test_requires_sqlmap_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                build_sqlmap_command(Path(temporary), "https://example.test/", Path(temporary) / "reports")


if __name__ == "__main__":
    unittest.main()
