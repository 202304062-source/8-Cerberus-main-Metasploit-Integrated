"""Bounded Metasploit Framework integration for HTTP service identification.

This integration invokes exactly one fixed auxiliary module:
auxiliary/scanner/http/http_version. It does not expose arbitrary module names,
exploit selection, payloads, sessions, post-exploitation, or custom MSF commands.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAX_OUTPUT_CHARS = 200_000
FIXED_MODULE = "auxiliary/scanner/http/http_version"


class MetasploitExecutionError(RuntimeError):
    """Raised when the bounded Metasploit check cannot run safely."""


@dataclass(frozen=True)
class HttpTarget:
    scheme: str
    hostname: str
    port: int
    display_url: str


@dataclass(frozen=True)
class MetasploitResult:
    target: str
    hostname: str
    resolved_ipv4: str
    port: int
    tls: bool
    module: str
    msfconsole_path: str
    exit_code: int
    output: str
    status: str
    started_at_utc: str
    duration_seconds: float
    report_json: str

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["scope_note"] = (
            "Only the fixed auxiliary/scanner/http/http_version module was invoked. "
            "This is a single-host HTTP service banner check, not exploitation or a "
            "full vulnerability assessment. It does not execute payloads, create "
            "sessions, brute-force credentials, or run post-exploitation modules."
        )
        return result


def validate_target_url(value: str) -> HttpTarget:
    """Accept one HTTP(S) URL and reduce it to a single host and TCP port."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter one non-empty HTTP(S) URL.")
    if any(ord(char) < 32 for char in value):
        raise ValueError("The URL must not contain control characters.")
    candidate = value.strip()
    if len(candidate) > 2048:
        raise ValueError("The URL is too long (maximum 2048 characters).")
    if any(char.isspace() for char in candidate):
        raise ValueError("The URL must not contain whitespace.")
    if "://" not in candidate:
        candidate = "https://" + candidate

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are accepted.")
    if not parsed.hostname:
        raise ValueError("The URL must contain a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing usernames or passwords are not accepted.")
    if parsed.fragment:
        raise ValueError("URL fragments are not accepted.")
    try:
        supplied_port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    hostname = parsed.hostname.rstrip(".")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            normalized_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("The hostname is not valid IDNA text.") from exc
        if not normalized_hostname or len(normalized_hostname) > 253:
            raise ValueError("The hostname length is invalid.")
        labels = normalized_hostname.split(".")
        if any(not HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("The URL hostname is invalid.")
        if len(labels) == 1 and normalized_hostname != "localhost":
            raise ValueError("Use a fully-qualified hostname, localhost, or an IPv4 address.")
        normalized_host = normalized_hostname
    else:
        if address.version != 4:
            raise ValueError("IPv6 URL literals are not supported by this integration.")
        normalized_host = str(address)

    port = supplied_port if supplied_port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("The target port must be between 1 and 65535.")
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    # Paths, query values, and fragments are intentionally not sent to Metasploit.
    display_url = f"{scheme}://{normalized_host}{suffix}/"
    return HttpTarget(scheme, normalized_host, port, display_url)


def resolve_ipv4(hostname: str, port: int) -> str:
    """Resolve a hostname once and return one validated IPv4 address."""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise MetasploitExecutionError("Only IPv4 targets are supported by this integration.")
        return str(address)

    try:
        records = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise MetasploitExecutionError(f"DNS resolution failed for {hostname}: {exc}") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise MetasploitExecutionError(f"DNS returned no IPv4 address for {hostname}.")
    try:
        return str(ipaddress.IPv4Address(addresses[0]))
    except ipaddress.AddressValueError as exc:
        raise MetasploitExecutionError("DNS returned an invalid IPv4 address.") from exc


def build_msf_commands(target: HttpTarget, target_ipv4: str) -> str:
    """Build a fixed allow-listed MSF console command sequence.

    User-controlled strings never become arbitrary console commands. The IP,
    hostname, and port have already passed strict parsers and are revalidated.
    """
    ipv4 = str(ipaddress.IPv4Address(target_ipv4))
    if not 1 <= target.port <= 65535:
        raise ValueError("Target port is outside the valid TCP range.")
    commands = [
        f"use {FIXED_MODULE}",
        f"set RHOSTS {ipv4}",
        f"set RPORT {target.port}",
        f"set SSL {'true' if target.scheme == 'https' else 'false'}",
        "set THREADS 1",
    ]
    try:
        ipaddress.ip_address(target.hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        # The validated hostname is used only for the HTTP virtual host header.
        commands.append(f"set VHOST {target.hostname}")
    commands.extend(["run", "exit -y"])
    return "; ".join(commands)


def build_process_command(
    executable: str | Path,
    console_commands: str,
    *,
    windows: bool | None = None,
) -> list[str]:
    """Return a shell-free process argument list for msfconsole."""
    executable_path = str(Path(executable).expanduser())
    is_windows = os.name == "nt" if windows is None else windows
    if is_windows and Path(executable_path).suffix.lower() in {".bat", ".cmd"}:
        # cmd.exe is required to start a Windows batch launcher. All target
        # values are validated and the console command sequence is allow-listed.
        inner = subprocess.list2cmdline([executable_path, "-q", "-x", console_commands])
        return ["cmd.exe", "/d", "/c", inner]
    return [executable_path, "-q", "-x", console_commands]


class MetasploitRunner:
    """Run only a single HTTP version-identification module against one host."""

    def __init__(
        self,
        msfconsole_path: str | Path,
        output_directory: str | Path | None = None,
        *,
        timeout_seconds: int = 300,
    ) -> None:
        self.msfconsole_path = Path(msfconsole_path).expanduser().resolve()
        package_root = Path(__file__).resolve().parent
        self.output_directory = Path(output_directory or package_root / "reports").expanduser().resolve()
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 30 <= timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be an integer from 30 to 600.")
        self.timeout_seconds = timeout_seconds

    def run(self, target_url: str, *, authorized: bool) -> MetasploitResult:
        if authorized is not True:
            raise MetasploitExecutionError("Execution blocked: explicit target authorization is required.")
        if not self.msfconsole_path.is_file():
            raise MetasploitExecutionError(f"msfconsole was not found: {self.msfconsole_path}")

        target = validate_target_url(target_url)
        resolved_ipv4 = resolve_ipv4(target.hostname, target.port)
        console_commands = build_msf_commands(target, resolved_ipv4)
        process_command = build_process_command(self.msfconsole_path, console_commands)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = uuid.uuid4().hex[:8]
        safe_host = re.sub(r"[^A-Za-z0-9]+", "-", target.hostname).strip("-")[:48] or "target"
        run_directory = self.output_directory / f"{timestamp}_{safe_host}_{run_id}"
        run_directory.mkdir(parents=True, exist_ok=False)
        started = datetime.now(timezone.utc)
        start_clock = time.monotonic()

        print("[CERBERUS][METASPLOIT] Starting the fixed HTTP version scanner.", flush=True)
        print(f"[CERBERUS][METASPLOIT] Target origin: {target.display_url}", flush=True)
        print(f"[CERBERUS][METASPLOIT] Resolved IPv4: {resolved_ipv4}", flush=True)
        print(f"[CERBERUS][METASPLOIT] Module: {FIXED_MODULE}", flush=True)
        print("[CERBERUS][METASPLOIT] No exploit, payload, session, or post module is enabled.", flush=True)
        print("[CERBERUS][METASPLOIT] Waiting for msfconsole output...", flush=True)

        try:
            completed = subprocess.run(
                process_command,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MetasploitExecutionError(
                f"msfconsole exceeded the {self.timeout_seconds}-second timeout. "
                f"Partial logs, if emitted by Metasploit itself, may be available in its local log directory."
            ) from exc
        except OSError as exc:
            raise MetasploitExecutionError(f"Unable to start msfconsole: {exc}") from exc

        duration = round(time.monotonic() - start_clock, 3)
        output = (completed.stdout or "")
        if completed.stderr:
            output += "\n[stderr]\n" + completed.stderr
        output = output[-MAX_OUTPUT_CHARS:]
        status = "completed" if completed.returncode == 0 else "failed"
        report_path = run_directory / "summary.json"
        result = MetasploitResult(
            target=target.display_url,
            hostname=target.hostname,
            resolved_ipv4=resolved_ipv4,
            port=target.port,
            tls=target.scheme == "https",
            module=FIXED_MODULE,
            msfconsole_path=str(self.msfconsole_path),
            exit_code=completed.returncode,
            output=output,
            status=status,
            started_at_utc=started.isoformat(),
            duration_seconds=duration,
            report_json=str(report_path),
        )
        report_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return result
