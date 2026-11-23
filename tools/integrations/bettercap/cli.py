"""Interactive VS Code terminal launcher for Cerberus Bettercap integration."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.integrations.bettercap.bootstrap import (  # noqa: E402
    BettercapBootstrapError,
    ensure_bettercap,
)
from tools.integrations.bettercap.runner import (  # noqa: E402
    BettercapExecutionError,
    BettercapRunner,
    validate_interface,
    validate_target_url,
)

AUTHORIZATION_PHRASE = "I HAVE AUTHORIZATION"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve one authorized HTTP(S) URL and use Bettercap net.recon to "
            "inspect whether its IPv4 address is present in the local ARP table. "
            "No active scan, sniffing, spoofing, or proxy module is enabled."
        )
    )
    parser.add_argument("--url", help="One authorized HTTP(S) URL; prompts if omitted.")
    parser.add_argument("--interface", help="Optional local network interface name (for example, Ethernet or wlan0).")
    parser.add_argument("--wait-seconds", type=int, default=3, help="Local ARP observation window (1-10; default: 3).")
    parser.add_argument("--no-install", action="store_true", help="Do not automatically download the pinned Bettercap binary.")
    return parser


def _confirm_authorization(target: str) -> bool:
    print("\nAUTHORIZATION REQUIRED")
    print(f"URL entered: {target}")
    print("Confirm that you own or have written permission to assess the target and that you are authorized to inspect this local network.")
    print("This tool only reads the local ARP table through Bettercap net.recon; it does not scan the website.")
    try:
        phrase = input(f'Type exactly "{AUTHORIZATION_PHRASE}" to continue: ').strip()
    except EOFError:
        return False
    return phrase == AUTHORIZATION_PHRASE


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.wait_seconds <= 10:
        parser.error("--wait-seconds must be between 1 and 10.")

    target_value = args.url
    if not target_value:
        try:
            target_value = input("Enter one authorized target URL (http:// or https://): ").strip()
        except EOFError:
            print("[CERBERUS][BETTERCAP] No target URL was provided.", file=sys.stderr)
            return 2
    try:
        target = validate_target_url(target_value)
        validate_interface(args.interface)
    except ValueError as exc:
        print(f"[CERBERUS][BETTERCAP] Invalid input: {exc}", file=sys.stderr)
        return 2

    if not _confirm_authorization(target.display_url):
        print("[CERBERUS][BETTERCAP] Cancelled. Bettercap was not started.")
        return 4

    try:
        print("[CERBERUS][BETTERCAP] Checking for the pinned official Bettercap binary...")
        binary = ensure_bettercap(allow_install=not args.no_install)
        print(f"[CERBERUS][BETTERCAP] Executable: {binary}")
        print("[CERBERUS][BETTERCAP] Resolving the URL and reading local ARP observations...")
        runner = BettercapRunner(binary)
        result = runner.run(
            target_value,
            authorized=True,
            wait_seconds=args.wait_seconds,
            interface=args.interface,
        )
    except (BettercapBootstrapError, BettercapExecutionError, OSError, ValueError) as exc:
        print(f"[CERBERUS][BETTERCAP] ERROR: {exc}", file=sys.stderr)
        print("[CERBERUS][BETTERCAP] On Windows, install Npcap from its official source and run with the permissions required by your system.", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n[CERBERUS][BETTERCAP] Stop requested by user.", file=sys.stderr)
        return 130

    print("\n[CERBERUS][BETTERCAP] Bettercap output:")
    print(result.output or "[No output returned by Bettercap]")
    print("\n[CERBERUS][BETTERCAP] Result summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    if result.status != "completed":
        return 5
    print("\n[CERBERUS][BETTERCAP] Note: a public website address normally is not present in your local ARP table; an empty match is expected for remote Internet hosts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
