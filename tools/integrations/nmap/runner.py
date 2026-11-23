"""Controlled Nmap runner used by the Cerberus Nmap integration.

This module invokes an installed Nmap executable with an argument list (never a
shell), validates a single host/domain/CIDR target, requires an explicit
authorization assertion, and exposes only conservative scan profiles.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


DEFAULT_TIMEOUT_SECONDS = 30 * 60
DEFAULT_MAX_HOSTS = 256
_ALLOWED_PROFILES = {"discovery", "quick", "standard"}
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class NmapExecutionError(RuntimeError):
    """Raised when Nmap cannot be started or the scan cannot complete."""


@dataclass(frozen=True)
class NmapScanResult:
    target: str
    profile: str
    status: str
    exit_code: int
    output_directory: str
    normal_report: str | None
    grepable_report: str | None
    xml_report: str | None
    summary_json: str | None
    executable: str
    started_at_utc: str
    duration_seconds: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_target(target: str, *, max_hosts: int = DEFAULT_MAX_HOSTS) -> str:
    """Validate one IP, CIDR, or DNS hostname; reject Nmap target expressions.

    Network targets are bounded by max_hosts (256 by default). This is a
    guardrail against accidental scans of very large ranges, not authorization.
    """
    if not isinstance(target, str):
        raise ValueError("Target must be text.")
    value = target.strip()
    if not value:
        raise ValueError("Target is required.")
    if any(ord(ch) < 32 or ch.isspace() for ch in value):
        raise ValueError("Target must not contain whitespace or control characters.")
    if any(ch in value for ch in ";,|&$`\\\"'<>!(){}[]"):
        raise ValueError("Only one hostname, IP address, or CIDR network is accepted.")
    if value.startswith("-") or value.startswith("/"):
        raise ValueError("Nmap options and path-like targets are not accepted.")
    if isinstance(max_hosts, bool) or not isinstance(max_hosts, int) or not 1 <= max_hosts <= 4096:
        raise ValueError("max_hosts must be an integer from 1 to 4096.")

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR target: {exc}") from exc
        if network.num_addresses > max_hosts:
            raise ValueError(
                f"Network contains {network.num_addresses} addresses; configured limit is "
                f"{max_hosts}. Narrow the CIDR or explicitly raise --max-hosts (up to 4096)."
            )
        return str(network)

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    # Domain/hostname validation; IDNA keeps internationalized DNS labels safe.
    try:
        ascii_name = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc
    if not ascii_name or len(ascii_name) > 253:
        raise ValueError("Hostname length must be between 1 and 253 characters.")
    labels = ascii_name.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Target is not a valid DNS hostname or IP/CIDR address.")
    # Disallow single-label names other than localhost to reduce accidental typos.
    if len(labels) == 1 and ascii_name.lower() != "localhost":
        raise ValueError("Use a fully-qualified hostname (or localhost), IP, or CIDR.")
    return ascii_name.lower()


def find_nmap(explicit_path: str | None = None) -> str | None:
    """Find Nmap on PATH or at common Windows install locations."""
    if explicit_path:
        candidate = Path(explicit_path).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        found = shutil.which(explicit_path)
        return found

    found = shutil.which("nmap") or shutil.which("nmap.exe")
    if found:
        return found

    import os
    if os.name == "nt":
        candidates = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(Path(base) / "Nmap" / "nmap.exe")
        candidates.extend([
            Path(r"C:\Program Files\Nmap\nmap.exe"),
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        ])
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    return None


class NmapRunner:
    """Run an Nmap scan using only the named built-in profiles."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        nmap_path: str | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_hosts: int = DEFAULT_MAX_HOSTS,
    ) -> None:
        package_root = Path(__file__).resolve().parent
        self.output_directory = Path(output_directory or package_root / "reports").expanduser().resolve()
        self.nmap_path = nmap_path
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 60:
            raise ValueError("timeout_seconds must be an integer of at least 60.")
        if isinstance(max_hosts, bool) or not isinstance(max_hosts, int) or not 1 <= max_hosts <= 4096:
            raise ValueError("max_hosts must be an integer from 1 to 4096.")
        self.timeout_seconds = timeout_seconds
        self.max_hosts = max_hosts

    def build_command(self, target: str, profile: str, report_prefix: str) -> list[str]:
        """Build an allow-listed, shell-free Nmap command."""
        normalized = validate_target(target, max_hosts=self.max_hosts)
        if profile not in _ALLOWED_PROFILES:
            raise ValueError(f"Unsupported profile. Choose one of: {', '.join(sorted(_ALLOWED_PROFILES))}.")
        executable = self.nmap_path or find_nmap()
        if not executable:
            raise NmapExecutionError("Nmap executable was not found. Run the CLI again and allow the integrated installer.")

        is_ipv6 = False
        try:
            is_ipv6 = ipaddress.ip_address(normalized).version == 6
        except ValueError:
            if "/" in normalized:
                is_ipv6 = ipaddress.ip_network(normalized, strict=False).version == 6
        if profile == "discovery":
            options = ["-sn", "-T3", "--reason"]
        elif profile == "quick":
            options = ["-sT", "-F", "-T3", "--reason", "--max-retries", "2"]
        else:
            options = [
                "-sT", "-sV", "--version-light", "--top-ports", "1000",
                "-T3", "--reason", "--max-retries", "2", "--host-timeout", "5m",
            ]
        if is_ipv6:
            options.insert(0, "-6")
        return [executable, *options, "-oA", report_prefix, normalized]

    def run(self, target: str, *, authorized: bool, profile: str = "standard") -> NmapScanResult:
        """Run a scan after explicit user/engagement authorization."""
        if authorized is not True:
            raise NmapExecutionError("Scan blocked: explicit authorization is required.")
        normalized = validate_target(target, max_hosts=self.max_hosts)
        if profile not in _ALLOWED_PROFILES:
            raise ValueError(f"Unsupported profile. Choose one of: {', '.join(sorted(_ALLOWED_PROFILES))}.")
        executable = self.nmap_path or find_nmap()
        if not executable:
            raise NmapExecutionError("Nmap executable was not found. Run the CLI again and allow the integrated installer.")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = uuid.uuid4().hex[:8]
        safe_target = re.sub(r"[^A-Za-z0-9]+", "-", normalized).strip("-")[:48] or "target"
        run_directory = self.output_directory / f"{timestamp}_{safe_target}_{run_id}"
        run_directory.mkdir(parents=True, exist_ok=False)
        prefix = str(run_directory / "nmap_scan")
        command = self.build_command(normalized, profile, prefix)

        started = datetime.now(timezone.utc)
        start_clock = time.monotonic()
        print("[CERBERUS][NMAP] Authorized scan starting.", flush=True)
        print(f"[CERBERUS][NMAP] Target: {normalized}", flush=True)
        print(f"[CERBERUS][NMAP] Profile: {profile}", flush=True)
        print(f"[CERBERUS][NMAP] Reports: {run_directory}", flush=True)
        print("[CERBERUS][NMAP] Output will stream in this terminal.", flush=True)

        try:
            process = subprocess.Popen(command, shell=False)
        except OSError as exc:
            raise NmapExecutionError(f"Could not start Nmap: {exc}") from exc
        try:
            exit_code = process.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise NmapExecutionError(
                f"Nmap exceeded the {self.timeout_seconds}-second timeout. Partial output, if any, is in {run_directory}."
            ) from exc

        duration = round(time.monotonic() - start_clock, 2)
        normal_path = run_directory / "nmap_scan.nmap"
        grep_path = run_directory / "nmap_scan.gnmap"
        xml_path = run_directory / "nmap_scan.xml"
        summary_path = run_directory / "summary.json"
        status = "completed" if exit_code == 0 else "completed_with_errors"

        summary = {
            "target": normalized,
            "profile": profile,
            "status": status,
            "exit_code": exit_code,
            "started_at_utc": started.isoformat(),
            "duration_seconds": duration,
            "reports": {
                "normal": str(normal_path) if normal_path.exists() else None,
                "grepable": str(grep_path) if grep_path.exists() else None,
                "xml": str(xml_path) if xml_path.exists() else None,
            },
            "note": "Nmap results are observations, not proof of exploitability. Validate findings safely.",
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        result = NmapScanResult(
            target=normalized,
            profile=profile,
            status=status,
            exit_code=exit_code,
            output_directory=str(run_directory),
            normal_report=str(normal_path) if normal_path.exists() else None,
            grepable_report=str(grep_path) if grep_path.exists() else None,
            xml_report=str(xml_path) if xml_path.exists() else None,
            summary_json=str(summary_path),
            executable=executable,
            started_at_utc=started.isoformat(),
            duration_seconds=duration,
        )
        print(f"\n[CERBERUS][NMAP] Scan finished with exit code {exit_code}.", flush=True)
        print(f"[CERBERUS][NMAP] Summary: {summary_path}", flush=True)
        return result
