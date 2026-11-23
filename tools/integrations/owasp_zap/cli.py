"""Interactive command-line entry point for Cerberus OWASP ZAP integration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Keep the command runnable from the repository root and from another
# current working directory (for example, a VS Code integrated terminal).
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.integrations.owasp_zap.runner import (  # noqa: E402
    ZAPBaselineRunner,
    ZAPExecutionError,
    validate_target_url,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run an OWASP ZAP passive baseline scan through the official "
            "Docker image. Active scanning is not enabled by this integration."
        )
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target URL, for example https://example.com. If omitted, you will be prompted.",
    )
    parser.add_argument(
        "-m",
        "--minutes",
        type=int,
        default=1,
        help="Spider duration in minutes (1-10; default: 1).",
    )
    parser.add_argument(
        "--output-dir",
        help="Optional report directory. Defaults to tools/integrations/owasp_zap/reports.",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you own the target or have written permission to test it.",
    )
    parser.add_argument(
        "--no-pull",
        action="store_true",
        help="Skip the explicit image refresh and use the locally cached Docker image.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20 * 60,
        help="Maximum scan runtime in seconds (default: 1200).",
    )
    return parser


def _confirm_authorization(target: str, already_confirmed: bool) -> bool:
    if already_confirmed:
        print("[CERBERUS][ZAP] Authorization flag supplied.", flush=True)
        return True

    print("\nIMPORTANT: Run this scan only against systems you own or are")
    print("explicitly authorized to assess.")
    print(f"Target: {target}")
    try:
        answer = input("Type YES to confirm authorization and continue: ")
    except EOFError:
        return False
    return answer.strip() == "YES"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not 1 <= args.minutes <= 10:
        parser.error("--minutes must be between 1 and 10.")
    if args.timeout < 60:
        parser.error("--timeout must be at least 60 seconds.")

    target = args.target
    if not target:
        try:
            target = input("Enter authorized target URL (http/https): ").strip()
        except EOFError:
            print("[CERBERUS][ZAP] No target provided.", file=sys.stderr)
            return 3

    try:
        target = validate_target_url(target)
    except ValueError as exc:
        print(f"[CERBERUS][ZAP] Invalid target: {exc}", file=sys.stderr)
        return 3

    if not _confirm_authorization(target, args.authorized):
        print("[CERBERUS][ZAP] Cancelled: authorization was not confirmed.")
        return 4

    runner = ZAPBaselineRunner(
        output_directory=args.output_dir,
        timeout_seconds=args.timeout,
    )

    try:
        result = runner.run(
            target,
            authorized=True,
            minutes=args.minutes,
            refresh_image=not args.no_pull,
        )
    except (ZAPExecutionError, ValueError) as exc:
        print(f"[CERBERUS][ZAP] ERROR: {exc}", file=sys.stderr)
        return 3

    print("\n[CERBERUS][ZAP] Result summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

    # ZAP exit code 2 indicates warnings, not a failure to run the scanner.
    return result.exit_code if result.exit_code in {0, 1, 2} else 3


if __name__ == "__main__":
    raise SystemExit(main())
