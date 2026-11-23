from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.integrations.nmap.runner import NmapExecutionError, NmapRunner, validate_target


class ValidateTargetTests(unittest.TestCase):
    def test_domain_is_normalized(self):
        self.assertEqual(validate_target("Example.COM."), "example.com")

    def test_ipv4_and_ipv6(self):
        self.assertEqual(validate_target("192.0.2.4"), "192.0.2.4")
        self.assertEqual(validate_target("2001:db8::1"), "2001:db8::1")

    def test_cidr_is_normalized(self):
        self.assertEqual(validate_target("192.0.2.7/24"), "192.0.2.0/24")

    def test_cidr_limit(self):
        with self.assertRaisesRegex(ValueError, "contains"):
            validate_target("10.0.0.0/16")

    def test_invalid_target_expressions_are_rejected(self):
        for target in ("-sS", "example.com;whoami", "example.com,example.net", "https://example.com", "bad host"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    validate_target(target)


class NmapRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runner = NmapRunner(output_directory=self.temp.name, nmap_path="/usr/bin/nmap")

    def test_standard_profile_uses_bounded_tcp_service_scan(self):
        command = self.runner.build_command("192.0.2.10", "standard", str(Path(self.temp.name) / "out"))
        self.assertIn("-sT", command)
        self.assertIn("-sV", command)
        self.assertIn("--version-light", command)
        self.assertIn("--top-ports", command)
        self.assertNotIn("--script", command)
        self.assertEqual(command[-1], "192.0.2.10")

    def test_discovery_profile_does_not_scan_ports(self):
        command = self.runner.build_command("192.0.2.10", "discovery", "out")
        self.assertIn("-sn", command)
        self.assertNotIn("-sV", command)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            self.runner.build_command("192.0.2.10", "custom", "out")

    def test_explicit_authorization_is_required(self):
        with self.assertRaises(NmapExecutionError):
            self.runner.run("192.0.2.10", authorized=False)

    @patch("tools.integrations.nmap.runner.subprocess.Popen")
    def test_output_paths_and_summary_are_created(self, popen):
        class FakeProcess:
            def wait(self, timeout=None):
                return 0
        popen.return_value = FakeProcess()
        result = self.runner.run("192.0.2.10", authorized=True, profile="quick")
        self.assertEqual(result.status, "completed")
        self.assertTrue(Path(result.summary_json).is_file())
        self.assertTrue(any(str(arg).endswith("nmap_scan") for arg in popen.call_args.args[0]))
        self.assertFalse(popen.call_args.kwargs.get("shell", False))

    def test_ipv6_command_enables_ipv6_mode(self):
        command = self.runner.build_command("2001:db8::1", "quick", "out")
        self.assertIn("-6", command)


if __name__ == "__main__":
    unittest.main()
