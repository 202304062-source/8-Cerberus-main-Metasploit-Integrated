"""Conservative URL-based network reconnaissance using Scapy.

The integration performs one HTTP(S) HEAD request and a small, bounded set of
TCP SYN probes against one IPv4 address resolved from one supplied URL. It does
not exploit services, crawl pages, brute-force credentials, or capture traffic.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


DEFAULT_PORTS = (80, 443, 8080, 8443)
MAX_PORTS = 5
DEFAULT_PACKET_TIMEOUT = 1.5
DEFAULT_HTTP_TIMEOUT = 5.0
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_AUTHORIZATION_ERROR = (
    "This integration only runs after explicit confirmation that the target is owned "
    "by you or covered by written authorization."
)


class ScapyExecutionError(RuntimeError):
    """Raised when the requested Scapy assessment cannot be prepared."""


@dataclass(frozen=True)
class ScapyTarget:
    """Validated HTTP(S) URL details used by the assessment."""

    scheme: str
    hostname: str
    port: int
    request_path: str
    display_url: str


@dataclass(frozen=True)
class ScapyScanResult:
    """Serializable result from one bounded Scapy assessment."""

    target: str
    resolved_ipv4: str
    port_list: tuple[int, ...]
    http: dict[str, Any]
    tcp_probes: tuple[dict[str, Any], ...]
    status: str
    started_at_utc: str
    duration_seconds: float
    report_json: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "resolved_ipv4": self.resolved_ipv4,
            "ports": list(self.port_list),
            "http": self.http,
            "tcp_probes": list(self.tcp_probes),
            "status": self.status,
            "started_at_utc": self.started_at_utc,
            "duration_seconds": self.duration_seconds,
            "report_json": self.report_json,
            "scope_note": (
                "Single URL, one resolved IPv4 address, one HTTP(S) HEAD request, "
                "and at most five sequential TCP SYN probes."
            ),
        }


def validate_target_url(value: str) -> ScapyTarget:
    """Validate and normalize one HTTP(S) URL; reject credentials and IPv6 literals."""
    if not isinstance(value, str):
        raise ValueError("Target URL must be text.")
    raw = value.strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Enter one HTTP(S) URL with a length from 1 to 2048 characters.")
    if any(ord(char) < 32 or char.isspace() for char in raw):
        raise ValueError("Target URL must not contain whitespace or control characters.")

    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Malformed target URL: {exc}") from exc

    if scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// target URLs are accepted.")
    if not hostname:
        raise ValueError("Target URL must include a hostname or IPv4 address.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing usernames or passwords are not accepted.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Target hostname is not valid IDNA text.") from exc
        if not ascii_host or len(ascii_host) > 253:
            raise ValueError("Target hostname length is invalid.")
        labels = ascii_host.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Target hostname is not a valid DNS name.")
        if len(labels) == 1 and ascii_host.lower() != "localhost":
            raise ValueError("Use a fully-qualified DNS hostname, localhost, or an IPv4 address.")
        normalized_host = ascii_host.lower()
    else:
        if address.version != 4:
            raise ValueError("IPv6 literals are not supported; use an IPv4 address or DNS hostname.")
        normalized_host = str(address)

    selected_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= selected_port <= 65535:
        raise ValueError("Target URL port must be between 1 and 65535.")

    path = parsed.path or "/"
    if "\r" in path or "\n" in path:
        raise ValueError("Target URL path contains invalid control characters.")
    request_path = path + (f"?{parsed.query}" if parsed.query else "")
    default_port = 443 if scheme == "https" else 80
    port_suffix = "" if selected_port == default_port else f":{selected_port}"
    # Do not retain a query string in report paths: it may contain tokens or personal data.
    display_url = f"{scheme}://{normalized_host}{port_suffix}{path}"

    return ScapyTarget(
        scheme=scheme,
        hostname=normalized_host,
        port=selected_port,
        request_path=request_path,
        display_url=display_url,
    )


def validate_ports(value: str | None, target_port: int) -> tuple[int, ...]:
    """Return a unique list of 1-5 TCP ports; ranges and port expressions are rejected."""
    if value is None or not value.strip():
        candidates = (target_port, *DEFAULT_PORTS)
    else:
        raw_items = value.split(",")
        if any(not item.strip() for item in raw_items):
            raise ValueError("--ports must be a comma-separated list of individual port numbers.")
        candidates_list: list[int] = []
        for item in raw_items:
            token = item.strip()
            if not token.isdecimal():
                raise ValueError("Only individual numeric TCP ports are accepted; ranges are not allowed.")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError("TCP port numbers must be between 1 and 65535.")
            if port not in candidates_list:
                candidates_list.append(port)
        candidates = tuple(candidates_list)

    deduplicated: list[int] = []
    for port in candidates:
        if port not in deduplicated:
            deduplicated.append(port)
    if not 1 <= len(deduplicated) <= MAX_PORTS:
        raise ValueError(f"Choose between 1 and {MAX_PORTS} individual TCP ports.")
    return tuple(deduplicated)


def _resolve_ipv4(hostname: str, port: int) -> str:
    """Resolve one IPv4 address and intentionally assess only that address."""
    try:
        records = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScapyExecutionError(f"DNS resolution failed for {hostname}: {exc}") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ScapyExecutionError(f"No IPv4 address was returned for {hostname}.")
    return str(ipaddress.IPv4Address(addresses[0]))


def _http_head(target: ScapyTarget, timeout: float = DEFAULT_HTTP_TIMEOUT) -> dict[str, Any]:
    """Send one TLS-verified HTTP(S) HEAD request without following redirects or reading a body."""
    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if target.scheme == "https":
        connection = http.client.HTTPSConnection(
            target.hostname,
            target.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(target.hostname, target.port, timeout=timeout)

    try:
        connection.request(
            "HEAD",
            target.request_path,
            headers={"User-Agent": "Cerberus-Scapy-Integration/1.0", "Connection": "close"},
        )
        response = connection.getresponse()
        received_headers = {name.lower(): value[:256] for name, value in response.getheaders()}
        selected_names = (
            "server",
            "content-type",
            "content-length",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        )
        return {
            "method": "HEAD",
            "status_code": response.status,
            "reason": response.reason[:120] if response.reason else "",
            "headers": {name: received_headers[name] for name in selected_names if name in received_headers},
            "redirect_followed": False,
            "body_downloaded": False,
        }
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return {
            "method": "HEAD",
            "status_code": None,
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
            "redirect_followed": False,
            "body_downloaded": False,
        }
    finally:
        connection.close()


def _classify_tcp_response(response: Any) -> str:
    """Classify a Scapy reply using TCP flag bits without assuming a vulnerability."""
    if response is None:
        return "no_response"
    try:
        from scapy.layers.inet import ICMP, TCP

        if response.haslayer(TCP):
            flags = int(response[TCP].flags)
            if flags & 0x12 == 0x12:  # SYN + ACK
                return "open"
            if flags & 0x04:  # RST
                return "closed"
            return "other_tcp_response"
        if response.haslayer(ICMP):
            return "icmp_unreachable_or_filtered"
    except Exception:
        return "unclassified_response"
    return "unclassified_response"


def _scapy_tcp_probe(
    destination: str,
    ports: tuple[int, ...],
    *,
    timeout: float = DEFAULT_PACKET_TIMEOUT,
) -> tuple[dict[str, Any], ...]:
    """Send sequential TCP SYN probes and reset any SYN-ACK response immediately."""
    try:
        from scapy.all import IP, TCP, send, sr1
    except ImportError as exc:
        raise ScapyExecutionError(
            "Scapy is not importable. Run the integration launcher to install its Python dependency."
        ) from exc

    results: list[dict[str, Any]] = []
    for port in ports:
        source_port = random.randint(32768, 60999)
        packet = IP(dst=destination) / TCP(sport=source_port, dport=port, flags="S")
        started = time.monotonic()
        try:
            response = sr1(packet, timeout=timeout, retry=0, verbose=0)
            elapsed = round(time.monotonic() - started, 3)
            status = _classify_tcp_response(response)
            entry: dict[str, Any] = {"port": port, "protocol": "tcp", "status": status, "rtt_seconds": elapsed}
            if response is not None and response.haslayer(TCP):
                entry["response_flags"] = str(response[TCP].flags)
                if status == "open":
                    reset = IP(dst=destination) / TCP(
                        sport=source_port,
                        dport=port,
                        flags="R",
                        seq=int(response[TCP].ack),
                    )
                    try:
                        send(reset, verbose=0)
                        entry["half_open_reset_sent"] = True
                    except Exception:
                        entry["half_open_reset_sent"] = False
            results.append(entry)
        except Exception as exc:  # Permission/Npcap/route errors are recorded per port.
            results.append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:300],
                }
            )
        time.sleep(0.15)
    return tuple(results)


class ScapyRunner:
    """Run the Cerberus Scapy check and persist a timestamped JSON report."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        *,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
        packet_timeout: float = DEFAULT_PACKET_TIMEOUT,
    ) -> None:
        package_root = Path(__file__).resolve().parent
        self.output_directory = Path(output_directory or package_root / "reports").expanduser().resolve()
        if not 1.0 <= http_timeout <= 30.0:
            raise ValueError("http_timeout must be between 1 and 30 seconds.")
        if not 0.2 <= packet_timeout <= 5.0:
            raise ValueError("packet_timeout must be between 0.2 and 5 seconds.")
        self.http_timeout = http_timeout
        self.packet_timeout = packet_timeout

    def run(
        self,
        target_url: str,
        *,
        authorized: bool,
        ports: tuple[int, ...] | None = None,
    ) -> ScapyScanResult:
        if authorized is not True:
            raise ScapyExecutionError(_AUTHORIZATION_ERROR)

        target = validate_target_url(target_url)
        selected_ports = ports if ports is not None else validate_ports(None, target.port)
        if not 1 <= len(selected_ports) <= MAX_PORTS or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in selected_ports
        ):
            raise ValueError(f"ports must contain 1-{MAX_PORTS} valid individual TCP ports.")
        if len(set(selected_ports)) != len(selected_ports):
            raise ValueError("ports must not contain duplicates.")

        started_at = datetime.now(timezone.utc)
        clock_start = time.monotonic()
        print(f"[CERBERUS][SCAPY] Target: {target.display_url}", flush=True)
        print(f"[CERBERUS][SCAPY] Resolving {target.hostname} to one IPv4 address...", flush=True)
        resolved_ip = _resolve_ipv4(target.hostname, target.port)
        print(f"[CERBERUS][SCAPY] Resolved IPv4: {resolved_ip}", flush=True)
        print("[CERBERUS][SCAPY] Sending one HTTP(S) HEAD request (no body, no redirects)...", flush=True)
        http_result = _http_head(target, timeout=self.http_timeout)
        if http_result.get("status_code") is not None:
            print(f"[CERBERUS][SCAPY] HTTP result: {http_result['status_code']}", flush=True)
        else:
            print(f"[CERBERUS][SCAPY] HTTP result: {http_result.get('error_type', 'unavailable')}", flush=True)

        print(
            f"[CERBERUS][SCAPY] Starting {len(selected_ports)} sequential TCP SYN probe(s): "
            f"{', '.join(str(port) for port in selected_ports)}",
            flush=True,
        )
        tcp_results = _scapy_tcp_probe(
            resolved_ip,
            tuple(selected_ports),
            timeout=self.packet_timeout,
        )
        for item in tcp_results:
            print(
                f"[CERBERUS][SCAPY] TCP/{item['port']}: {item['status']}",
                flush=True,
            )

        duration = round(time.monotonic() - clock_start, 2)
        any_tcp_success = any(item["status"] in {"open", "closed", "no_response", "icmp_unreachable_or_filtered", "other_tcp_response"} for item in tcp_results)
        overall_status = "completed" if any_tcp_success else "partial"
        self.output_directory.mkdir(parents=True, exist_ok=True)
        timestamp = started_at.astimezone().strftime("%Y%m%d_%H%M%S")
        safe_host = re.sub(r"[^A-Za-z0-9_-]+", "_", target.hostname).strip("_")[:48] or "target"
        run_dir = self.output_directory / f"{timestamp}_{safe_host}_{uuid.uuid4().hex[:8]}"
        run_dir.mkdir(parents=True, exist_ok=False)
        report_path = run_dir / "summary.json"
        report = {
            "target": target.display_url,
            "hostname": target.hostname,
            "resolved_ipv4": resolved_ip,
            "target_port": target.port,
            "ports": list(selected_ports),
            "http": http_result,
            "tcp_probes": list(tcp_results),
            "status": overall_status,
            "started_at_utc": started_at.isoformat(),
            "duration_seconds": duration,
            "authorization": "User confirmed the target is owned or covered by written permission.",
            "scope_note": (
                "One URL and one resolved IPv4 address only; one HEAD request; "
                "at most five sequential TCP SYN probes; no redirects or response body."
            ),
            "limitations": [
                "A closed or silent port result is not proof that a service is vulnerable.",
                "A HEAD response does not assess application vulnerabilities.",
                "Only the first resolved IPv4 address is assessed; alternate DNS addresses are not scanned.",
            ],
        }
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[CERBERUS][SCAPY] JSON report: {report_path}", flush=True)
        print(f"[CERBERUS][SCAPY] Finished in {duration:.2f} seconds ({overall_status}).", flush=True)

        return ScapyScanResult(
            target=target.display_url,
            resolved_ipv4=resolved_ip,
            port_list=tuple(selected_ports),
            http=http_result,
            tcp_probes=tcp_results,
            status=overall_status,
            started_at_utc=started_at.isoformat(),
            duration_seconds=duration,
            report_json=str(report_path),
        )
