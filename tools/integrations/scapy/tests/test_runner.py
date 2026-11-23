from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.integrations.scapy.runner import (
    ScapyExecutionError,
    ScapyRunner,
    _classify_tcp_response,
    validate_ports,
    validate_target_url,
)


class TargetValidationTests(unittest.TestCase):
    def test_https_url_normalizes_hostname_and_default_port(self):
        target = validate_target_url("HTTPS://Example.COM/a/b?token=secret#fragment")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.request_path, "/a/b?token=secret")
        self.assertNotIn("token=secret", target.display_url)

    def test_custom_port_is_preserved(self):
        target = validate_target_url("http://127.0.0.1:8088/health")
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertEqual(target.port, 8088)
        self.assertEqual(target.display_url, "http://127.0.0.1:8088/health")

    def test_rejects_unsupported_schemes_and_credentials(self):
        invalid = (
            "ftp://example.com/file",
            "https://user:pass@example.com/",
            "https://[2001:db8::1]/",
            "https://bad host.example/",
            "https://example.com:99999/",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_target_url(value)

    def test_requires_http_or_https_url(self):
        with self.assertRaises(ValueError):
            validate_target_url("example.com")


class PortValidationTests(unittest.TestCase):
    def test_default_ports_include_url_port_and_are_bounded(self):
        self.assertEqual(validate_ports(None, 9443), (9443, 80, 443, 8080, 8443))

    def test_explicit_ports_deduplicate(self):
        self.assertEqual(validate_ports("443,80,443", 443), (443, 80))

    def test_ranges_and_large_lists_are_rejected(self):
        for value in ("1-1024", "80,,443", "0", "65536", "1,2,3,4,5,6"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_ports(value, 443)


class ResponseClassificationTests(unittest.TestCase):
    def test_none_response_is_no_response(self):
        self.assertEqual(_classify_tcp_response(None), "no_response")


class RunnerTests(unittest.TestCase):
    def test_authorization_is_required(self):
        runner = ScapyRunner()
        with self.assertRaises(ScapyExecutionError):
            runner.run("https://example.com/", authorized=False)

    @patch("tools.integrations.scapy.runner._scapy_tcp_probe")
    @patch("tools.integrations.scapy.runner._http_head")
    @patch("tools.integrations.scapy.runner._resolve_ipv4", return_value="192.0.2.25")
    def test_writes_json_report_without_network_access(self, resolve, http_head, tcp_probe):
        http_head.return_value = {"method": "HEAD", "status_code": 200, "headers": {}}
        tcp_probe.return_value = (
            {"port": 443, "protocol": "tcp", "status": "open", "rtt_seconds": 0.02},
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = ScapyRunner(output_directory=temporary)
            result = runner.run("https://example.com/", authorized=True, ports=(443,))
            report_path = Path(result.report_json)
            self.assertTrue(report_path.is_file())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["resolved_ipv4"], "192.0.2.25")
            self.assertEqual(report["tcp_probes"][0]["status"], "open")
            self.assertEqual(result.status, "completed")
            resolve.assert_called_once()
            http_head.assert_called_once()
            tcp_probe.assert_called_once()


if __name__ == "__main__":
    unittest.main()
