from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.integrations.metasploit import bootstrap
from tools.integrations.metasploit.bootstrap import MetasploitBootstrapError, find_msfconsole


class FindMetasploitTests(unittest.TestCase):
    def test_finds_explicit_existing_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "msfconsole.bat"
            executable.write_text("@echo off", encoding="utf-8")
            self.assertEqual(find_msfconsole(str(executable)), str(executable.resolve()))

    def test_missing_explicit_path_returns_none(self):
        self.assertIsNone(find_msfconsole("/path/that/does/not/exist/msfconsole"))

    def test_environment_override_is_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "msfconsole"
            executable.write_text("test", encoding="utf-8")
            with patch.dict(os.environ, {"CERBERUS_MSFCONSOLE": str(executable)}):
                self.assertEqual(find_msfconsole(), str(executable.resolve()))


class InstallerVerificationTests(unittest.TestCase):
    def test_authenticode_requires_valid_rapid7_publisher(self):
        with tempfile.TemporaryDirectory() as temporary:
            installer = Path(temporary) / "setup.msi"
            installer.write_bytes(b"fake msi")
            success = type("Completed", (), {"returncode": 0, "stdout": "CN=Rapid7 LLC", "stderr": ""})()
            with patch.object(bootstrap.subprocess, "run", return_value=success):
                bootstrap._verify_rapid7_authenticode(installer)

    def test_authenticode_rejects_wrong_publisher(self):
        with tempfile.TemporaryDirectory() as temporary:
            installer = Path(temporary) / "setup.msi"
            installer.write_bytes(b"fake msi")
            invalid = type("Completed", (), {"returncode": 32, "stdout": "CN=Unknown Publisher", "stderr": ""})()
            with patch.object(bootstrap.subprocess, "run", return_value=invalid):
                with self.assertRaises(MetasploitBootstrapError):
                    bootstrap._verify_rapid7_authenticode(installer)

    def test_non_windows_install_is_refused(self):
        with patch.object(bootstrap.os, "name", "posix"):
            with self.assertRaises(MetasploitBootstrapError):
                bootstrap.install_official_windows_metasploit(Path("/tmp"))


if __name__ == "__main__":
    unittest.main()
