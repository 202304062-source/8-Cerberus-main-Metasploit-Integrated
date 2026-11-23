"""Interactive VS Code terminal launcher for the Cerberus Metasploit integration."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.integrations.metasploit.bootstrap import (  # noqa: E402
    MetasploitBootstrapError,
    find_msfconsole,
    install_official_windows_metasploit,
)
from tools.integrations.metasploit.runner import (  # noqa: E402
    MetasploitExecutionError,
    MetasploitRunner,
    validate_target_url,
)

AUTHORIZATION_PHRASE = "I HAVE AUTHORIZATION"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one fixed, non-exploit Metasploit HTTP version check against one explicitly authorized URL. "
            "The integration does not provide arbitrary module or payload execution."
        )
    )
    parser.add_argument("--url", help="One authorized HTTP(S) URL; prompts when omitted.")
    parser.add_argument("--msfconsole-path", help="Optional explicit path to msfconsole or msfconsole.bat.")
    parser.add_argument("--timeout", type=int, default=300, help="msfconsole timeout in seconds (30-600; default 300).")
    parser.add_argument("--no-install", action="store_true", help="Do not download/launch the official Windows installer if Metasploit is missing.")
    return parser


def _confirm_authorization(target: str) -> bool:
    print("\nAUTHORIZATION REQUIRED")
    print(f"Target origin: {target}")
    print("Use this check only for a host you own or are explicitly authorized to assess.")
    print("The integration runs only auxiliary/scanner/http/http_version; it does not exploit the host.")
    try:
        supplied = input(f'Type exactly "{AUTHORIZATION_PHRASE}" to continue: ').strip()
    except EOFError:
        return False
    return supplied == AUTHORIZATION_PHRASE


def _offer_windows_install() -> bool:
    print("[CERBERUS][METASPLOIT] msfconsole was not found on this computer.")
    print("The official Rapid7 MSI can be downloaded into this project's ignored .runtime folder.")
    print("It will be signature-checked and started as a normal interactive installer (not silently).")
    print("Windows administrator permission and acceptance of the Rapid7 license may be required.")
    try:
        return input("Download and launch the official installer now? [y/N]: ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be from 30 to 600 seconds.")

    target_value = args.url
    if not target_value:
        try:
            target_value = input("Enter one authorized target URL (http:// or https://): ").strip()
        except EOFError:
            print("[CERBERUS][METASPLOIT] No target URL was supplied.", file=sys.stderr)
            return 2
    try:
        target = validate_target_url(target_value)
    except ValueError as exc:
        print(f"[CERBERUS][METASPLOIT] Invalid URL: {exc}", file=sys.stderr)
        return 2

    if not _confirm_authorization(target.display_url):
        print("[CERBERUS][METASPLOIT] Cancelled. msfconsole was not started.")
        return 4

    try:
        console_path = find_msfconsole(args.msfconsole_path)
        if not console_path:
            if args.no_install:
                raise MetasploitBootstrapError(
                    "msfconsole was not found. Install it from Rapid7's official installer or remove --no-install."
                )
            if os.name != "nt":
                raise MetasploitBootstrapError(
                    "msfconsole was not found. Automatic setup is Windows-only; follow the official Rapid7 guide for this OS."
                )
            if not _offer_windows_install():
                print("[CERBERUS][METASPLOIT] Setup cancelled. No installer was downloaded.")
                return 4
            console_path = install_official_windows_metasploit()

        print(f"[CERBERUS][METASPLOIT] Using: {console_path}")
        runner = MetasploitRunner(console_path, timeout_seconds=args.timeout)
        result = runner.run(target_value, authorized=True)
    except (MetasploitBootstrapError, MetasploitExecutionError, OSError, ValueError) as exc:
        print(f"[CERBERUS][METASPLOIT] ERROR: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n[CERBERUS][METASPLOIT] Stop requested.", file=sys.stderr)
        return 130

    print("\n[CERBERUS][METASPLOIT] msfconsole output:")
    print(result.output or "[No output returned by msfconsole]")
    print("\n[CERBERUS][METASPLOIT] Result summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    print(f"\n[CERBERUS][METASPLOIT] JSON report: {result.report_json}")
    return 0 if result.status == "completed" else 5


if __name__ == "__main__":
    raise SystemExit(main())
