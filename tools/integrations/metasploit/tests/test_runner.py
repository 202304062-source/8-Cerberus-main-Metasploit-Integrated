from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.integrations.metasploit import runner
from tools.integrations.metasploit.runner import (
    FIXED_MODULE,
    MetasploitExecutionError,
    MetasploitRunner,
    build_msf_commands,
    build_process_command,
    resolve_ipv4,
    validate_target_url,
)


class TargetValidationTests(unittest.TestCase):
    def test_https_host_default_port(self):
        target = validate_target_url("https://example.com/path?q=secret")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.display_url, "https://example.com/")

    def test_domain_without_scheme_defaults_to_https(self):
        target = validate_target_url("example.com")
        self.assertEqual(target.scheme, "https")

    def test_custom_port_is_retained(self):
        target = validate_target_url("http://example.com:8080/")
        self.assertEqual(target.port, 8080)

    def test_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://user:pass@example.com")

    def test_non_http_schemes_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_target_url("ftp://example.com/file")

    def test_ipv6_literal_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://[2001:db8::1]/")

    def test_url_with_control_characters_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://example.com/\n")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_target_url("https://example.com:99999")


class CommandSafetyTests(unittest.TestCase):
    def test_commands_use_only_fixed_http_version_module(self):
        target = validate_target_url("https://example.com")
        commands = build_msf_commands(target, "192.0.2.10")
        self.assertIn(f"use {FIXED_MODULE}", commands)
        self.assertIn("set RHOSTS 192.0.2.10", commands)
        self.assertIn("set RPORT 443", commands)
        self.assertIn("set SSL true", commands)
        self.assertIn("set VHOST example.com", commands)
        self.assertIn("set THREADS 1", commands)
        self.assertNotIn("exploit", commands.lower())
        self.assertNotIn("payload", commands.lower())

    def test_ip_target_does_not_add_virtual_host_option(self):
        target = validate_target_url("http://192.0.2.15:8080")
        commands = build_msf_commands(target, "192.0.2.15")
        self.assertNotIn("VHOST", commands)

    def test_windows_batch_command_is_shell_wrapped_without_shell_true(self):
        command = build_process_command(
            r"C:\Metasploit-framework\bin\msfconsole.bat",
            "use auxiliary/scanner/http/http_version; run; exit -y",
            windows=True,
        )
        self.assertEqual(command[:3], ["cmd.exe", "/d", "/c"])
        self.assertIn("msfconsole.bat", command[3])

    def test_ipv4_resolution_uses_first_address(self):
        target_record = (None, None, None, None, ("198.51.100.14", 443))
        with patch.object(runner.socket, "getaddrinfo", return_value=[target_record]):
            self.assertEqual(resolve_ipv4("example.com", 443), "198.51.100.14")

    def test_authorization_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_console = Path(temporary) / "msfconsole"
            fake_console.write_text("test", encoding="utf-8")
            subject = MetasploitRunner(fake_console, output_directory=temporary)
            with self.assertRaises(MetasploitExecutionError):
                subject.run("https://example.com", authorized=False)

    def test_run_writes_json_report_and_captures_console_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_console = Path(temporary) / "msfconsole"
            fake_console.write_text("test", encoding="utf-8")
            output_dir = Path(temporary) / "reports"
            completed = SimpleNamespace(returncode=0, stdout="[+] HTTP service: nginx\n", stderr="")
            runner_instance = MetasploitRunner(fake_console, output_dir)
            with patch.object(runner.socket, "getaddrinfo", return_value=[(None, None, None, None, ("198.51.100.8", 443))]), \
                 patch.object(runner.subprocess, "run", return_value=completed) as run_mock:
                result = runner_instance.run("https://example.com", authorized=True)
            self.assertEqual(result.status, "completed")
            self.assertIn("nginx", result.output)
            self.assertFalse(run_mock.call_args.kwargs["shell"])
            report = json.loads(Path(result.report_json).read_text(encoding="utf-8"))
            self.assertEqual(report["module"], FIXED_MODULE)
            self.assertIn("scope_note", report)

    def test_missing_console_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-msfconsole"
            subject = MetasploitRunner(missing, output_directory=temporary)
            with self.assertRaises(MetasploitExecutionError):
                subject.run("https://example.com", authorized=True)


if __name__ == "__main__":
    unittest.main()
