"""Offline unit tests for the OWASP ZAP integration."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.integrations.owasp_zap.runner import (
    DEFAULT_ZAP_IMAGE,
    ZAPBaselineRunner,
    ZAPExecutionError,
    validate_target_url,
)


class TargetValidationTests(unittest.TestCase):
    def test_accepts_https_url(self) -> None:
        self.assertEqual(
            validate_target_url("  https://example.com/path  "),
            "https://example.com/path",
        )

    def test_accepts_local_development_url(self) -> None:
        self.assertEqual(
            validate_target_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        )

    def test_rejects_non_http_scheme(self) -> None:
        with self.assertRaises(ValueError):
            validate_target_url("ftp://example.com")

    def test_rejects_missing_host(self) -> None:
        with self.assertRaises(ValueError):
            validate_target_url("https:///missing-host")

    def test_rejects_url_credentials(self) -> None:
        with self.assertRaises(ValueError):
            validate_target_url("https://user:password@example.com")

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            validate_target_url("https://example.com:70000")


class RunnerCommandTests(unittest.TestCase):
    def test_uses_official_stable_image(self) -> None:
        self.assertEqual(DEFAULT_ZAP_IMAGE, "ghcr.io/zaproxy/zaproxy:stable")

    def test_command_is_baseline_only_and_writes_three_reports(self) -> None:
        runner = ZAPBaselineRunner(
            output_directory=Path("tmp-zap-reports"),
            timeout_seconds=60,
        )
        command = runner.build_scan_command(
            docker="docker",
            target="https://example.com",
            report_stem="zap_test",
            container_name="cerberus-zap-test",
            minutes=2,
        )

        self.assertIn("zap-baseline.py", command)
        self.assertIn("-r", command)
        self.assertIn("-J", command)
        self.assertIn("-x", command)
        self.assertIn("2", command)
        self.assertIn("--pull=never", command)
        self.assertNotIn("zap-full-scan.py", command)
        self.assertNotIn("-active", command)
        self.assertNotIn("--script", command)

    def test_requires_explicit_authorization(self) -> None:
        runner = ZAPBaselineRunner()
        with self.assertRaises(ZAPExecutionError):
            runner.run("https://example.com", authorized=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
