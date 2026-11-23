"""Interactive command-line entry point for the Cerberus Nmap integration."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.integrations.nmap.installer import NmapInstallError, ensure_nmap  # noqa: E402
from tools.integrations.nmap.runner import NmapExecutionError, NmapRunner, find_nmap, validate_target  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a controlled Nmap scan against one explicitly authorized host, domain, or bounded CIDR network. "
            "Only discovery, quick TCP, and standard TCP/service profiles are exposed."
        )
    )
    parser.add_argument("-t", "--target", help="Authorized IP/domain/CIDR. If omitted, the CLI prompts for it.")
    parser.add_argument("--profile", choices=("discovery", "quick", "standard"), default="standard",
                        help="discovery: host discovery only; quick: top common ports; standard: top 1000 TCP ports plus light service detection.")
    parser.add_argument("--output-dir", help="Optional report directory; defaults to tools/integrations/nmap/reports.")
    parser.add_argument("--timeout", type=int, default=1800, help="Maximum scan runtime in seconds (default: 1800).")
    parser.add_argument("--max-hosts", type=int, default=256, help="Maximum addresses in a CIDR target (1-4096; default: 256).")
    parser.add_argument("--nmap-path", help="Optional explicit path to nmap or nmap.exe.")
    parser.add_argument("--authorized", action="store_true", help="Confirm that you own the target or have written permission to scan it.")
    parser.add_argument("--no-install", action="store_true", help="Do not offer automatic Nmap installation when the executable is missing.")
    return parser


def _confirm_authorization(target: str, supplied: bool) -> bool:
    if supplied:
        print("[CERBERUS][NMAP] Authorization flag supplied.")
        return True
    print("\nAUTHORIZATION REQUIRED")
    print("Scan only systems and networks that you own or are explicitly authorized to assess.")
    print(f"Exact target: {target}")
    try:
        return input("Type YES to confirm authorization and continue: ").strip() == "YES"
    except EOFError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout < 60:
        parser.error("--timeout must be at least 60 seconds.")
    if not 1 <= args.max_hosts <= 4096:
        parser.error("--max-hosts must be from 1 to 4096.")

    target = args.target
    if not target:
        try:
            target = input("Enter authorized target (IP / domain / CIDR): ").strip()
        except EOFError:
            print("[CERBERUS][NMAP] No target provided.", file=sys.stderr)
            return 3
    try:
        target = validate_target(target, max_hosts=args.max_hosts)
    except ValueError as exc:
        print(f"[CERBERUS][NMAP] Invalid target: {exc}", file=sys.stderr)
        return 3

    if not _confirm_authorization(target, args.authorized):
        print("[CERBERUS][NMAP] Cancelled: authorization was not confirmed.")
        return 4

    try:
        nmap_path = find_nmap(args.nmap_path) if args.nmap_path else find_nmap()
        if not nmap_path:
            nmap_path = ensure_nmap(allow_install=not args.no_install)
        runner = NmapRunner(
            output_directory=args.output_dir,
            nmap_path=args.nmap_path or nmap_path,
            timeout_seconds=args.timeout,
            max_hosts=args.max_hosts,
        )
        result = runner.run(target, authorized=True, profile=args.profile)
    except (NmapInstallError, NmapExecutionError, ValueError) as exc:
        print(f"[CERBERUS][NMAP] ERROR: {exc}", file=sys.stderr)
        return 3

    print("\n[CERBERUS][NMAP] Result summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if result.exit_code == 0 else 5


if __name__ == "__main__":
    raise SystemExit(main())
