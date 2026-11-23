"""URL-to-local-ARP observation bridge using Bettercap's read-only net.recon module.

Important: Bettercap net.recon reads the machine's local ARP table. It is not a
website vulnerability scanner and does not probe a remote Internet host.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:{}-]{1,64}$")
MAX_LOG_CHARS = 500_000


class BettercapExecutionError(RuntimeError):
    """Raised when Bettercap cannot execute the bounded local observation."""


@dataclass(frozen=True)
class BettercapTarget:
    scheme: str
    hostname: str
    port: int
    display_url: str


@dataclass(frozen=True)
class BettercapResult:
    target: str
    hostname: str
    resolved_ipv4: str
    bettercap_version: str
    interface: str | None
    wait_seconds: int
    command: tuple[str, ...]
    return_code: int
    output: str
    status: str
    started_at_utc: str
    duration_seconds: float
    report_json: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "resolved_ipv4": self.resolved_ipv4,
            "bettercap_version": self.bettercap_version,
            "interface": self.interface,
            "wait_seconds": self.wait_seconds,
            "command": list(self.command),
            "return_code": self.return_code,
            "output": self.output,
            "status": self.status,
            "started_at_utc": self.started_at_utc,
            "duration_seconds": self.duration_seconds,
            "report_json": self.report_json,
            "scope_note": (
                "Bettercap net.recon reads the local ARP table. No port scan, packet capture, "
                "spoofing, proxy, credential collection, or active host probing is enabled. "
                "A public website IP normally will not appear in the local ARP table."
            ),
        }


def validate_target_url(value: str) -> BettercapTarget:
    """Accept one HTTP(S) URL; reject credentials, malformed DNS, and IPv6 literals."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a non-empty HTTP(S) URL.")
    candidate = value.strip()
    if len(candidate) > 2048:
        raise ValueError("The URL is too long (maximum 2048 characters).")
    if any(ord(char) < 32 for char in candidate):
        raise ValueError("The URL contains control characters.")
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
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("The hostname is not valid IDNA text.") from exc
        if len(ascii_host) > 253:
            raise ValueError("The hostname is too long.")
        labels = ascii_host.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("The hostname is not a valid DNS name.")
        if len(labels) == 1 and ascii_host.lower() != "localhost":
            raise ValueError("Use a fully-qualified domain name, localhost, or an IPv4 address.")
        normalized_host = ascii_host.lower()
    else:
        if address.version != 4:
            raise ValueError("IPv6 URL literals are not supported by this integration.")
        normalized_host = str(address)
    selected_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= selected_port <= 65535:
        raise ValueError("The URL port must be between 1 and 65535.")
    suffix = "" if selected_port == (443 if scheme == "https" else 80) else f":{selected_port}"
    return BettercapTarget(scheme, normalized_host, selected_port, f"{scheme}://{normalized_host}{suffix}")


def validate_interface(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    candidate = value.strip()
    if not _INTERFACE_PATTERN.fullmatch(candidate):
        raise ValueError("Interface names may contain only letters, digits, underscore, dot, colon, braces, and hyphen.")
    return candidate


def _resolve_ipv4(hostname: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(hostname)
        if address.version != 4:
            raise BettercapExecutionError("Only IPv4 target addresses are supported.")
        return str(address)
    except ValueError:
        pass
    try:
        records = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BettercapExecutionError(f"DNS resolution failed for {hostname}: {exc}") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise BettercapExecutionError(f"No IPv4 address was returned for {hostname}.")
    return str(ipaddress.IPv4Address(addresses[0]))


def build_eval_commands(target_ipv4: str, wait_seconds: int) -> str:
    """Build fixed read-only Bettercap commands using a validated IP literal."""
    target = str(ipaddress.IPv4Address(target_ipv4))
    if not 1 <= wait_seconds <= 10:
        raise ValueError("Wait time must be between 1 and 10 seconds.")
    return f"net.recon on; sleep {wait_seconds}; net.recon off; net.show {target}; q"


class BettercapRunner:
    def __init__(
        self,
        binary_path: str | Path,
        output_directory: str | Path | None = None,
        *,
        process_timeout: float = 25.0,
    ) -> None:
        self.binary_path = Path(binary_path).expanduser().resolve()
        self.output_directory = Path(output_directory) if output_directory else Path(__file__).resolve().parent / "reports"
        self.process_timeout = process_timeout

    def run(
        self,
        target_url: str,
        *,
        authorized: bool,
        wait_seconds: int = 3,
        interface: str | None = None,
    ) -> BettercapResult:
        if not authorized:
            raise BettercapExecutionError(
                "This integration requires explicit authorization for the supplied target and the local network."
            )
        if not self.binary_path.is_file():
            raise BettercapExecutionError(f"Bettercap executable was not found: {self.binary_path}")
        target = validate_target_url(target_url)
        selected_interface = validate_interface(interface)
        resolved_ipv4 = _resolve_ipv4(target.hostname, target.port)
        commands = build_eval_commands(resolved_ipv4, wait_seconds)
        started = datetime.now(timezone.utc)
        start_clock = time.monotonic()
        args: list[str] = [str(self.binary_path), "-no-colors", "-no-history", "-env-file", "", "-eval", commands]
        if selected_interface:
            args[1:1] = ["-iface", selected_interface]
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.process_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BettercapExecutionError(
                f"Bettercap exceeded the {self.process_timeout:g}-second process timeout."
            ) from exc
        except OSError as exc:
            raise BettercapExecutionError(f"Unable to start Bettercap: {exc}") from exc
        duration = time.monotonic() - start_clock
        output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        output = output[-MAX_LOG_CHARS:]
        status = "completed" if completed.returncode == 0 else "failed"
        self.output_directory.mkdir(parents=True, exist_ok=True)
        report_dir = self.output_directory / datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        report_dir.mkdir(parents=True, exist_ok=False)
        report_path = report_dir / "summary.json"
        result = BettercapResult(
            target=target.display_url,
            hostname=target.hostname,
            resolved_ipv4=resolved_ipv4,
            bettercap_version="v2.42.0 (pinned bootstrap target)",
            interface=selected_interface,
            wait_seconds=wait_seconds,
            command=tuple(args),
            return_code=completed.returncode,
            output=output,
            status=status,
            started_at_utc=started.isoformat(),
            duration_seconds=round(duration, 3),
            report_json=str(report_path),
        )
        report_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return result
