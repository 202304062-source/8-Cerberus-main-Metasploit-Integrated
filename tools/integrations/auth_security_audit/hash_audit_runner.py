"""Bounded offline dictionary audits for local password-hash files."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.integrations.auth_security_audit.hash_tools_installer import HashToolsInstaller, HashToolInstallError


class HashAuditError(RuntimeError):
    """Raised when a local-only hash audit cannot be validated or executed."""


@dataclass(frozen=True)
class HashAuditResult:
    engine: str
    status: str
    exit_code: int
    hash_count: int
    recovered_count: int
    runtime_seconds: float
    report_path: str
    attack_mode: str = "dictionary-only (offline)"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_local_file(value: str | Path, label: str, *, max_bytes: int) -> Path:
    raw = str(value).strip()
    if not raw or raw.lower().startswith(("http://", "https://", "ftp://")):
        raise ValueError(f"{label} must be a local file path, not a URL.")
    if raw.startswith(("\\\\", "//")):
        raise ValueError(f"{label} must be stored on a local drive, not a network share.")
    path = Path(raw).expanduser()
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link.")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} does not exist or cannot be accessed: {exc}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular local file.")
    if resolved.stat().st_size <= 0:
        raise ValueError(f"{label} must not be empty.")
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds the configured size limit ({max_bytes} bytes).")
    return resolved


def count_hash_records(hash_file: Path) -> int:
    try:
        with hash_file.open("r", encoding="utf-8", errors="replace") as stream:
            return sum(1 for line in stream if line.strip() and not line.lstrip().startswith("#"))
    except OSError as exc:
        raise HashAuditError(f"Could not read the local hash file: {exc}") from exc


class OfflineHashAuditRunner:
    def __init__(
        self,
        output_directory: str | Path | None = None,
        installer: HashToolsInstaller | None = None,
    ) -> None:
        module_root = Path(__file__).resolve().parent
        self.output_directory = Path(output_directory or module_root / "reports" / "hashes").expanduser().resolve()
        self.installer = installer or HashToolsInstaller()

    def build_command(
        self,
        engine: str,
        executable: str,
        hash_file: Path,
        wordlist: Path,
        potfile: Path,
        *,
        max_runtime: int,
        hash_mode: str | None = None,
        john_format: str | None = None,
        session: str = "cerberus_offline_audit",
    ) -> list[str]:
        if engine == "john":
            command = [
                executable,
                f"--wordlist={wordlist}",
                f"--pot={potfile}",
                f"--session={session}",
                f"--max-run-time={max_runtime}",
            ]
            if john_format:
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", john_format):
                    raise ValueError("John format must contain only letters, digits, underscore, or hyphen.")
                command.append(f"--format={john_format}")
            command.append(str(hash_file))
            return command
        if engine == "hashcat":
            if not hash_mode or not re.fullmatch(r"\d{1,6}", str(hash_mode)):
                raise ValueError("Hashcat requires a numeric hash mode such as 0 for MD5 or 1000 for NTLM.")
            return [
                executable,
                "-m", str(hash_mode),
                "-a", "0",  # dictionary attack only; no masks, brute force, or rules
                "--runtime", str(max_runtime),
                "--session", session,
                "--potfile-path", str(potfile),
                "--status",
                "--status-timer", "15",
                str(hash_file),
                str(wordlist),
            ]
        raise ValueError("engine must be john or hashcat")

    def run(
        self,
        engine: str,
        hash_file: str | Path,
        wordlist: str | Path,
        *,
        authorized: bool,
        max_runtime: int = 600,
        hash_mode: str | None = None,
        john_format: str | None = None,
    ) -> HashAuditResult:
        if authorized is not True:
            raise HashAuditError("Hash audit blocked: ownership or explicit audit authorization is required.")
        if isinstance(max_runtime, bool) or not isinstance(max_runtime, int) or not 30 <= max_runtime <= 1800:
            raise ValueError("max_runtime must be between 30 and 1800 seconds.")
        local_hashes = validate_local_file(hash_file, "Hash file", max_bytes=50 * 1024 * 1024)
        local_wordlist = validate_local_file(wordlist, "Wordlist", max_bytes=4 * 1024 * 1024 * 1024)
        hash_count = count_hash_records(local_hashes)
        if hash_count == 0:
            raise ValueError("The hash file contains no non-empty hash records.")
        try:
            executable = self.installer.ensure_tool(engine)
        except (HashToolInstallError, ValueError) as exc:
            raise HashAuditError(str(exc)) from exc

        self.output_directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        session = f"cerberus_{engine}_{uuid.uuid4().hex[:8]}"
        state_dir = self.output_directory.parent.parent / ".runtime" / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        potfile = state_dir / f"{engine}.potfile"
        command = self.build_command(
            engine,
            executable,
            local_hashes,
            local_wordlist,
            potfile,
            max_runtime=max_runtime,
            hash_mode=hash_mode,
            john_format=john_format,
            session=session,
        )
        print(f"[CERBERUS][HASH] Engine: {engine}", flush=True)
        print(f"[CERBERUS][HASH] Local hashes: {hash_count}", flush=True)
        print(f"[CERBERUS][HASH] Attack: bounded dictionary-only, offline", flush=True)
        print(f"[CERBERUS][HASH] Time limit: {max_runtime} seconds", flush=True)
        started = time.monotonic()
        try:
            process = subprocess.Popen(command, cwd=str(Path(executable).resolve().parent), shell=False)
            try:
                exit_code = process.wait(timeout=max_runtime + 90)
            except subprocess.TimeoutExpired as exc:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise HashAuditError("Hash audit exceeded its enforced runtime; the process was stopped.") from exc
        except OSError as exc:
            raise HashAuditError(f"Could not start {engine}: {exc}") from exc
        duration = round(time.monotonic() - started, 2)
        if exit_code not in {0, 1}:
            raise HashAuditError(f"{engine} exited with code {exit_code}; see the terminal output for details.")
        recovered = self._count_recovered(engine, executable, local_hashes, potfile, hash_mode, john_format)
        report = {
            "engine": engine,
            "status": "completed_with_recovered_hashes" if recovered else "completed_no_dictionary_matches",
            "exit_code": exit_code,
            "hash_count": hash_count,
            "recovered_count": recovered,
            "runtime_seconds": duration,
            "attack_mode": "dictionary-only (offline)",
            "max_runtime_seconds": max_runtime,
            "hash_file_name": local_hashes.name,
            "wordlist_name": local_wordlist.name,
            "hash_mode": hash_mode if engine == "hashcat" else None,
            "john_format": john_format if engine == "john" else None,
            "note": "Recovered count only measures matches in the supplied wordlist; it is not a formal entropy or strength proof.",
            "sensitive_data": "Hash and pot files remain local in the project runtime directory; do not commit or share them.",
        }
        report_path = self.output_directory / f"{stamp}_{engine}_{session}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        result = HashAuditResult(
            engine=engine,
            status=str(report["status"]),
            exit_code=exit_code,
            hash_count=hash_count,
            recovered_count=recovered,
            runtime_seconds=duration,
            report_path=str(report_path),
        )
        print(f"[CERBERUS][HASH] Recovered: {recovered}/{hash_count}", flush=True)
        print(f"[CERBERUS][HASH] Summary: {report_path}", flush=True)
        print("[CERBERUS][HASH] Plaintext matches were not copied into the report.", flush=True)
        return result

    @staticmethod
    def _count_recovered(
        engine: str,
        executable: str,
        hash_file: Path,
        potfile: Path,
        hash_mode: str | None,
        john_format: str | None,
    ) -> int:
        if engine == "john":
            command = [executable, f"--pot={potfile}", "--show"]
            if john_format:
                command.append(f"--format={john_format}")
            command.append(str(hash_file))
        else:
            command = [executable, "-m", str(hash_mode), "--potfile-path", str(potfile), "--show", str(hash_file)]
        try:
            result = subprocess.run(command, cwd=str(Path(executable).resolve().parent), capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return 0
        # Do not persist or echo the returned output: it can contain plaintext passwords.
        if result.returncode not in {0, 1}:
            return 0
        if engine == "john":
            matches = re.findall(r"(\d+) password hashes? cracked", result.stdout + "\n" + result.stderr, flags=re.IGNORECASE)
            if matches:
                return int(matches[-1])
        return sum(1 for line in result.stdout.splitlines() if line.strip())
