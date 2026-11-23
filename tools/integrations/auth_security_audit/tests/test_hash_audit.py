import tempfile
import unittest
from pathlib import Path

from tools.integrations.auth_security_audit.hash_audit_runner import OfflineHashAuditRunner, validate_local_file


class HashAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.hash_file = self.root / "hashes.txt"
        self.hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="utf-8")
        self.wordlist = self.root / "wordlist.txt"
        self.wordlist.write_text("password\n", encoding="utf-8")
        self.runner = OfflineHashAuditRunner(output_directory=self.root / "reports")

    def tearDown(self):
        self.temp.cleanup()

    def test_accepts_local_regular_file(self):
        self.assertEqual(validate_local_file(self.hash_file, "hashes", max_bytes=100).name, "hashes.txt")

    def test_rejects_url(self):
        with self.assertRaises(ValueError):
            validate_local_file("https://example.test/hashes", "hashes", max_bytes=100)

    def test_rejects_missing_file(self):
        with self.assertRaises(ValueError):
            validate_local_file(self.root / "missing", "hashes", max_bytes=100)

    def test_hashcat_command_is_dictionary_only(self):
        command = self.runner.build_command(
            "hashcat", "hashcat.exe", self.hash_file, self.wordlist, self.root / "pot",
            max_runtime=300, hash_mode="0",
        )
        self.assertIn("-a", command)
        self.assertEqual(command[command.index("-a") + 1], "0")
        self.assertIn("--runtime", command)
        self.assertNotIn("-r", command)
        self.assertNotIn("--force", command)

    def test_hashcat_rejects_non_numeric_mode(self):
        with self.assertRaises(ValueError):
            self.runner.build_command(
                "hashcat", "hashcat.exe", self.hash_file, self.wordlist, self.root / "pot",
                max_runtime=300, hash_mode="md5",
            )

    def test_john_command_uses_dictionary_and_time_limit(self):
        command = self.runner.build_command(
            "john", "john.exe", self.hash_file, self.wordlist, self.root / "pot",
            max_runtime=300, john_format="raw-md5",
        )
        self.assertTrue(any(arg.startswith("--wordlist=") for arg in command))
        self.assertIn("--max-run-time=300", command)
        self.assertIn("--format=raw-md5", command)
        self.assertFalse(any("incremental" in arg.lower() for arg in command))

    def test_requires_explicit_authorization(self):
        with self.assertRaises(Exception):
            self.runner.run("john", self.hash_file, self.wordlist, authorized=False)

    def test_rejects_runtime_outside_bounds(self):
        with self.assertRaises(ValueError):
            self.runner.run("john", self.hash_file, self.wordlist, authorized=True, max_runtime=3600)


if __name__ == "__main__":
    unittest.main()
