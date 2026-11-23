import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.integrations.auth_security_audit.hash_tools_installer import HashToolsInstaller
from tools.integrations.auth_security_audit.jwt_tool_installer import JWTToolInstaller
from subprocess import CompletedProcess


class InstallerTests(unittest.TestCase):
    def test_jwt_tool_uses_pinned_release_tag(self):
        self.assertIn("v2.3.0", JWTToolInstaller().source_dir.as_posix() + " " + "https://github.com/ticarpi/jwt_tool/archive/refs/tags/v2.3.0.zip")


    def test_jwt_token_is_piped_to_stdin_not_process_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            inst = JWTToolInstaller(Path(tmp))
            script = Path(tmp) / "jwt_tool.py"
            script.write_text("# fake script", encoding="utf-8")
            python = Path(tmp) / "python.exe"
            python.write_text("", encoding="utf-8")
            with patch.object(inst, "ensure_installed", return_value=(script, python)), \
                 patch("tools.integrations.auth_security_audit.jwt_tool_installer.subprocess.run", return_value=CompletedProcess([], 0, "ok", "")) as run:
                token = "head.payload.signature"
                inst.run_local_decode(token)
                args, kwargs = run.call_args
                self.assertNotIn(token, args[0])
                self.assertEqual(kwargs["input"], token)

    def test_hashcat_asset_digest_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            inst = HashToolsInstaller(Path(tmp))
            release = {"tag_name": "v0", "assets": [{"name": "hashcat-test.7z", "browser_download_url": "https://github.com/hashcat/hashcat/releases/download/v0/hashcat-test.7z", "digest": None}]}
            with patch.object(inst, "_github_json", return_value=release), patch.object(inst, "_download") as download:
                with self.assertRaises(Exception):
                    inst._install_hashcat_windows()
                download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
