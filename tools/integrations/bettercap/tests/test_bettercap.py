from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from tools.integrations.bettercap.bootstrap import (
    BettercapBootstrapError,
    _select_asset,
    ensure_bettercap,
)
from tools.integrations.bettercap.runner import (
    BettercapExecutionError,
    BettercapRunner,
    build_eval_commands,
    validate_interface,
    validate_target_url,
)


class TargetValidationTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(validate_target_url("example.com").display_url, "https://example.com")

    def test_accepts_http_and_port(self):
        target = validate_target_url("http://192.0.2.10:8080/path")
        self.assertEqual(target.hostname, "192.0.2.10")
        self.assertEqual(target.port, 8080)

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            validate_target_url("ftp://example.com")

    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://user:pass@example.com")

    def test_rejects_ipv6_literal(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://[2001:db8::1]/")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://example.com:99999")

    def test_interface_validation(self):
        self.assertEqual(validate_interface("Wi-Fi"), "Wi-Fi")
        with self.assertRaises(ValueError):
            validate_interface('Wi-Fi; arp.spoof on')


class FixedCommandTests(unittest.TestCase):
    def test_eval_command_is_fixed_read_only_module(self):
        command = build_eval_commands("192.0.2.12", 4)
        self.assertEqual(command, "net.recon on; sleep 4; net.recon off; net.show 192.0.2.12; q")
        for forbidden in ("net.probe", "net.sniff", "arp.spoof", "dns.spoof", "http.proxy"):
            self.assertNotIn(forbidden, command)

    def test_rejects_invalid_wait(self):
        with self.assertRaises(ValueError):
            build_eval_commands("192.0.2.12", 11)

    def test_release_asset_selection(self):
        release = {"assets": [
            {"name": "checksums.txt", "browser_download_url": "https://example.invalid/checksums"},
            {"name": "bettercap_windows_amd64_v2.42.0.zip", "browser_download_url": "https://example.invalid/bettercap.zip"},
        ]}
        selected = _select_asset(release, "windows", "amd64")
        self.assertIn("windows_amd64", selected["name"])


class BootstrapTests(unittest.TestCase):
    def _archive(self) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("release/bettercap.exe", b"mock bettercap executable")
            archive.writestr("release/README.txt", b"ignored file")
        return stream.getvalue()

    @patch("tools.integrations.bettercap.bootstrap._platform_asset_tokens", return_value=("windows", "amd64", "bettercap.exe"))
    @patch("tools.integrations.bettercap.bootstrap._request_bytes")
    def test_bootstrap_downloads_and_extracts_only_executable(self, request_bytes, platform_tokens):
        archive = self._archive()
        metadata = {
            "tag_name": "v2.42.0",
            "assets": [{
                "name": "bettercap_windows_amd64_v2.42.0.zip",
                "browser_download_url": "https://example.invalid/bettercap.zip",
                "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
            }],
        }
        request_bytes.side_effect = [json.dumps(metadata).encode(), archive]
        with tempfile.TemporaryDirectory() as temporary:
            binary = ensure_bettercap(integration_dir=Path(temporary))
            self.assertEqual(binary.name, "bettercap.exe")
            self.assertEqual(binary.read_bytes(), b"mock bettercap executable")

    @patch("tools.integrations.bettercap.bootstrap._platform_asset_tokens", return_value=("windows", "amd64", "bettercap.exe"))
    @patch("tools.integrations.bettercap.bootstrap._request_bytes")
    def test_bootstrap_rejects_bad_release_digest(self, request_bytes, platform_tokens):
        archive = self._archive()
        metadata = {
            "tag_name": "v2.42.0",
            "assets": [{
                "name": "bettercap_windows_amd64_v2.42.0.zip",
                "browser_download_url": "https://example.invalid/bettercap.zip",
                "digest": "sha256:" + ("0" * 64),
            }],
        }
        request_bytes.side_effect = [json.dumps(metadata).encode(), archive]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BettercapBootstrapError):
                ensure_bettercap(integration_dir=Path(temporary))
            self.assertFalse((Path(temporary) / ".runtime" / "bettercap.exe").exists())


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "bettercap.exe"
        self.binary.write_bytes(b"mock executable")

    @patch("tools.integrations.bettercap.runner.subprocess.run")
    @patch("tools.integrations.bettercap.runner._resolve_ipv4", return_value="192.0.2.44")
    def test_runs_only_pinned_net_recon_workflow(self, resolve, run_process):
        run_process.return_value = Mock(returncode=0, stdout="local ARP results", stderr="")
        output = Path(self.temp.name) / "reports"
        runner = BettercapRunner(self.binary, output)
        result = runner.run("https://example.com", authorized=True, wait_seconds=2)
        args = run_process.call_args.args[0]
        self.assertIn("-eval", args)
        evaluation = args[args.index("-eval") + 1]
        self.assertEqual(evaluation, "net.recon on; sleep 2; net.recon off; net.show 192.0.2.44; q")
        self.assertEqual(result.status, "completed")
        saved = json.loads(Path(result.report_json).read_text(encoding="utf-8"))
        self.assertEqual(saved["resolved_ipv4"], "192.0.2.44")
        resolve.assert_called()

    def test_requires_authorization(self):
        runner = BettercapRunner(self.binary, Path(self.temp.name) / "reports")
        with self.assertRaises(BettercapExecutionError):
            runner.run("https://example.com", authorized=False)

    @patch("tools.integrations.bettercap.runner._resolve_ipv4", return_value="192.0.2.44")
    @patch("tools.integrations.bettercap.runner.subprocess.run")
    def test_nonzero_bettercap_exit_is_reported_as_failed(self, run_process, resolve):
        run_process.return_value = Mock(returncode=2, stdout="", stderr="pcap unavailable")
        runner = BettercapRunner(self.binary, Path(self.temp.name) / "reports")
        result = runner.run("https://example.com", authorized=True)
        self.assertEqual(result.status, "failed")
        self.assertIn("pcap unavailable", result.output)


if __name__ == "__main__":
    unittest.main()
