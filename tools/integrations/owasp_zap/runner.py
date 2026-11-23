"""Docker-backed OWASP ZAP baseline scan runner.

The integration uses the official ZAP Docker image. It does not bundle or
modify ZAP itself, and it intentionally runs the passive baseline scan only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DEFAULT_TIMEOUT_SECONDS = 20 * 60


class ZAPExecutionError(RuntimeError):
    """Raised when Docker/ZAP cannot be started or the scan cannot complete."""


@dataclass(frozen=True)
class ZAPScanResult:
    target: str
    status: str
    exit_code: int
    output_directory: str
    html_report: str | None
    json_report: str | None
    xml_report: str | None
    image: str
    scan_mode: str = "baseline-passive"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_target_url(target: str) -> str:
    """Validate and normalize an HTTP(S) target URL.

    This checks syntax only. It does not establish ownership or authorization.
    """
    if not isinstance(target, str):
        raise ValueError("Target URL must be text.")
    target = target.strip()
    if not target:
        raise ValueError("Target URL is required.")
    if any(ord(char) < 32 for char in target):
        raise ValueError("Target URL contains control characters.")

    try:
        parsed = urlsplit(target)
        hostname = parsed.hostname
        # Accessing .port raises ValueError for malformed/out-of-range ports.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid target URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// target URLs are supported.")
    if not hostname:
        raise ValueError("Target URL must include a hostname.")
    if any(char.isspace() for char in hostname):
        raise ValueError("Target hostname must not contain whitespace.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Do not place usernames or passwords in the target URL.")
    if parsed.fragment:
        # Fragments are not sent to the web server and can be misleading here.
        target = target.split("#", 1)[0]

    return target.rstrip("/") or f"{parsed.scheme.lower()}://{hostname}"


class ZAPBaselineRunner:
    """Run ZAP's non-active baseline scan inside the official Docker image."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        image: str = DEFAULT_ZAP_IMAGE,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        package_root = Path(__file__).resolve().parent
        self.output_directory = Path(
            output_directory or package_root / "reports"
        ).expanduser().resolve()
        self.image = image
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _docker_executable() -> str:
        docker = shutil.which("docker")
        if not docker:
            raise ZAPExecutionError(
                "Docker CLI was not found. Install Docker Desktop/Engine and "
                "make sure the Docker daemon is running, then retry."
            )
        return docker

    def _run_process(self, command: list[str], timeout: int | None = None) -> int:
        """Run a command with stdout/stderr connected to the caller's terminal."""
        try:
            process = subprocess.Popen(command)
        except OSError as exc:
            raise ZAPExecutionError(f"Could not start Docker: {exc}") from exc

        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise ZAPExecutionError(
                f"Command timed out after {timeout} seconds."
            ) from exc

    def _pull_image(self, docker: str) -> None:
        print(f"[CERBERUS][ZAP] Pulling official image: {self.image}", flush=True)
        code = self._run_process([docker, "pull", self.image], timeout=600)
        if code != 0:
            raise ZAPExecutionError(
                f"Docker could not pull {self.image} (exit code {code})."
            )

    def build_scan_command(
        self,
        docker: str,
        target: str,
        report_stem: str,
        container_name: str,
        minutes: int,
    ) -> list[str]:
        """Build an argument-safe Docker command (no shell interpolation)."""
        mount_spec = (
            f"type=bind,source={self.output_directory},target=/zap/wrk"
        )
        return [
            docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--pull=never",
            "--mount",
            mount_spec,
            self.image,
            "zap-baseline.py",
            "-t",
            target,
            "-m",
            str(minutes),
            "-r",
            f"{report_stem}.html",
            "-J",
            f"{report_stem}.json",
            "-x",
            f"{report_stem}.xml",
        ]

    def run(
        self,
        target: str,
        *,
        authorized: bool,
        minutes: int = 1,
        refresh_image: bool = True,
    ) -> ZAPScanResult:
        """Execute a passive baseline scan after explicit authorization.

        Exit code mapping follows the ZAP baseline script:
        0 = completed without WARN/FAIL; 1 = FAIL; 2 = WARN; 3 = scanner error.
        """
        if authorized is not True:
            raise ZAPExecutionError(
                "Scan blocked: explicit authorization is required."
            )

        normalized_target = validate_target_url(target)
        if isinstance(minutes, bool) or not isinstance(minutes, int):
            raise ValueError("Scan duration must be an integer from 1 to 10.")
        if not 1 <= minutes <= 10:
            raise ValueError("Scan duration must be between 1 and 10 minutes.")

        self.output_directory.mkdir(parents=True, exist_ok=True)
        docker = self._docker_executable()

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = uuid.uuid4().hex[:8]
        report_stem = f"zap_baseline_{timestamp}_{run_id}"
        container_name = f"cerberus-zap-{os.getpid()}-{run_id}"

        if refresh_image:
            self._pull_image(docker)

        command = self.build_scan_command(
            docker=docker,
            target=normalized_target,
            report_stem=report_stem,
            container_name=container_name,
            minutes=minutes,
        )

        print("[CERBERUS][ZAP] Starting non-active baseline scan.", flush=True)
        print(f"[CERBERUS][ZAP] Target: {normalized_target}", flush=True)
        print(
            f"[CERBERUS][ZAP] Reports directory: {self.output_directory}",
            flush=True,
        )

        try:
            exit_code = self._run_process(
                command,
                timeout=self.timeout_seconds,
            )
        except ZAPExecutionError as exc:
            # Avoid leaving a named container running after an interrupted scan.
            try:
                subprocess.run(
                    [docker, "stop", container_name],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise exc

        report_paths = {
            "html_report": self.output_directory / f"{report_stem}.html",
            "json_report": self.output_directory / f"{report_stem}.json",
            "xml_report": self.output_directory / f"{report_stem}.xml",
        }

        if exit_code == 0:
            status = "completed"
        elif exit_code == 1:
            status = "completed_with_fail_findings"
        elif exit_code == 2:
            status = "completed_with_warnings"
        else:
            status = "scanner_error"

        existing_reports = {
            key: str(path) if path.is_file() else None
            for key, path in report_paths.items()
        }

        result = ZAPScanResult(
            target=normalized_target,
            status=status,
            exit_code=exit_code,
            output_directory=str(self.output_directory),
            image=self.image,
            **existing_reports,
        )

        print(f"[CERBERUS][ZAP] Status: {status} (exit code {exit_code})", flush=True)
        for label, path in existing_reports.items():
            if path:
                print(f"[CERBERUS][ZAP] {label}: {path}", flush=True)
            else:
                print(
                    f"[CERBERUS][ZAP] {label}: not generated",
                    flush=True,
                )

        if exit_code == 3:
            raise ZAPExecutionError(
                "ZAP reported an execution error (exit code 3). "
                "Review the terminal output and Docker status."
            )

        return result
