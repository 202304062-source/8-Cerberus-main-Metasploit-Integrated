"""Interactive VS Code terminal launcher for the Cerberus Scapy integration."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.integrations.scapy.bootstrap import ScapyBootstrapError, ensure_scapy  # noqa: E402
from tools.integrations.scapy.runner import (  # noqa: E402
    ScapyExecutionError,
    ScapyRunner,
    validate_ports,
    validate_target_url,
)

AUTHORIZATION_PHRASE = "I HAVE AUTHORIZATION"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a small, authorized Scapy network check for one HTTP(S) URL: "
            "DNS resolution, one HTTP HEAD request, and up to five TCP SYN probes."
        )
    )
    parser.add_argument("--url", help="One authorized HTTP(S) URL. If omitted, the CLI prompts for it.")
    parser.add_argument(
        "--ports",
        help="Optional comma-separated list of 1-5 individual TCP ports (for example: 80,443).",
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Do not automatically install Scapy if it is missing from the active Python environment.",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="HTTP HEAD timeout in seconds (1-30; default: 5).",
    )
    parser.add_argument(
        "--packet-timeout",
        type=float,
        default=1.5,
        help="Timeout for each TCP SYN probe in seconds (0.2-5; default: 1.5).",
    )
    return parser


def _confirm_authorization(target: str) -> bool:
    print("\nAUTHORIZATION REQUIRED")
    print(f"Exact target: {target}")
    print("Run only against assets you own or have explicit written permission to assess.")
    print("URL validation does not verify ownership or read the Cerberus Scope of Engagement.")
    try:
        phrase = input(f'Type exactly "{AUTHORIZATION_PHRASE}" to continue: ').strip()
    except EOFError:
        return False
    return phrase == AUTHORIZATION_PHRASE


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1.0 <= args.http_timeout <= 30.0:
        parser.error("--http-timeout must be between 1 and 30 seconds.")
    if not 0.2 <= args.packet_timeout <= 5.0:
        parser.error("--packet-timeout must be between 0.2 and 5 seconds.")

    target_value = args.url
    if not target_value:
        try:
            target_value = input("Enter one authorized target URL (http:// or https://): ").strip()
        except EOFError:
            print("[CERBERUS][SCAPY] No target URL was provided.", file=sys.stderr)
            return 2

    try:
        target = validate_target_url(target_value)
        ports = validate_ports(args.ports, target.port)
    except ValueError as exc:
        print(f"[CERBERUS][SCAPY] Invalid input: {exc}", file=sys.stderr)
        return 2

    if not _confirm_authorization(target.display_url):
        print("[CERBERUS][SCAPY] Cancelled. No network requests were made.")
        return 4

    try:
        ensure_scapy(allow_install=not args.no_install)
        runner = ScapyRunner(
            http_timeout=args.http_timeout,
            packet_timeout=args.packet_timeout,
        )
        result = runner.run(
            target_value,
            authorized=True,
            ports=ports,
        )
    except (ScapyBootstrapError, ScapyExecutionError, OSError, ValueError) as exc:
        print(f"[CERBERUS][SCAPY] ERROR: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n[CERBERUS][SCAPY] Stop requested by user.", file=sys.stderr)
        return 130

    print("\n[CERBERUS][SCAPY] Result summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if result.status == "completed" else 5


if __name__ == "__main__":
    raise SystemExit(main())
