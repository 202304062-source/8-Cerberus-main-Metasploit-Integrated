import base64
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from tools.integrations.auth_security_audit.jwt_zap_runner import JWTZAPAuthRunner


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class _JWTInstaller:
    def run_local_decode(self, token, public_key=None):
        return CompletedProcess(["jwt_tool"], 0, stdout="Decoded JWT\n", stderr="")


class _Process:
    def wait(self, timeout=None):
        return 2


class JWTZAPRunnerTests(unittest.TestCase):
    def test_report_directory_is_scoped_to_new_integration(self):
        token = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"exp": 2000000000, "iat": 1000000000}) + ".signature"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "jwt_reports"
            runner = JWTZAPAuthRunner(output_directory=output, jwt_installer=_JWTInstaller())
            with patch("tools.integrations.auth_security_audit.jwt_zap_runner.ZAPBaselineRunner") as zap_cls, \
                 patch("tools.integrations.auth_security_audit.jwt_zap_runner.subprocess.Popen", return_value=_Process()) as popen:
                fake = zap_cls.return_value
                fake.image = "ghcr.io/zaproxy/zaproxy:stable"
                fake._docker_executable.return_value = "docker"
                fake.build_scan_command.return_value = ["docker", "run", "--mount", "source=REPORTS"]
                result = runner.run("https://app.example.test", token, authorized=True, refresh_image=False)
                self.assertTrue(str(output) in str(zap_cls.call_args.kwargs["output_directory"]))
                self.assertIn("-configfile /zap/wrk/", popen.call_args.args[0][-1])
                self.assertEqual(result["status"], "completed_with_warnings")
                summary = Path(result["reports"]["json"]).parent / "auth_audit_summary.json"
                self.assertTrue(summary.is_file())
                self.assertFalse(any(Path(summary.parent).glob(".zap-auth-*.properties")))


    def test_report_redaction_removes_bearer_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            token = "aaa.bbb.ccc"
            report = folder / "scan.html"
            report.write_text(f"Authorization: Bearer {token}", encoding="utf-8")
            JWTZAPAuthRunner._redact_token_from_reports(folder, token)
            stored = report.read_text(encoding="utf-8")
            self.assertNotIn(token, stored)
            self.assertIn("[REDACTED JWT]", stored)

    def test_authorization_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = JWTZAPAuthRunner(output_directory=tmp, jwt_installer=_JWTInstaller())
            with self.assertRaises(Exception):
                runner.run("https://app.example.test", "a.b.c", authorized=False)


if __name__ == "__main__":
    unittest.main()
