"""Interactive VS Code terminal launcher for the Cerberus sqlmap integration."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.integrations.sqlmap.bootstrap import ensure_sqlmap  # noqa: E402
from tools.integrations.sqlmap.runner import (  # noqa: E402
    TargetValidationError,
    build_sqlmap_command,
    validate_target_url,
)


REPORTS_DIR = PROJECT_ROOT / "tools" / "integrations" / "sqlmap" / "reports"
AUTHORIZATION_PHRASE = "I HAVE AUTHORIZATION"
DEFAULT_PROCESS_TIMEOUT = 900


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a limited sqlmap SQL-injection detection check against one authorized URL."
    )
    parser.add_argument("--url", help="One in-scope HTTP(S) URL. Omit to enter it interactively.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_PROCESS_TIMEOUT,
        help=f"Maximum scanner process time in seconds (default: {DEFAULT_PROCESS_TIMEOUT}).",
    )
    return parser.parse_args()


def _ask_for_target(argument_url: str | None) -> str:
    candidate = argument_url
    if not candidate:
        print("\nEnter one HTTP/HTTPS URL that is explicitly included in your approved test scope.")
        candidate = input("Target URL: ").strip()
    return validate_target_url(candidate)


def _confirm_authorization(target_url: str) -> bool:
    host = urlsplit(target_url).hostname or "unknown host"
    print("\nAUTHORIZATION REQUIRED")
    print(f"Target: {target_url}")
    print(f"Host:   {host}")
    print("Use this scanner only on systems you own or have written permission to test.")
    print("URL validation does not verify ownership or the Cerberus Scope of Engagement.")
    print("The default profile performs limited SQLi detection only; it does not request database dumps.")
    confirmation = input(f'Type exactly "{AUTHORIZATION_PHRASE}" to continue: ').strip()
    return confirmation == AUTHORIZATION_PHRASE


def _create_run_directory(target_url: str) -> Path:
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "target").lower()
    host_slug = re.sub(r"[^a-z0-9_-]+", "_", host).strip("_")[:48] or "target"
    digest = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:10]
    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    run_dir = REPORTS_DIR / f"{timestamp}_{host_slug}_{digest}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def _run_process(command: list[str], working_directory: Path, timeout: int) -> int:
    print("\nStarting sqlmap. Its raw output is streamed directly to this terminal.\n")
    print("Command profile: level=1, risk=1, techniques=BE, one thread, no data-dump options.")
    print("Press Ctrl+C to stop the scan.\n")

    process = subprocess.Popen(command, cwd=str(working_directory), shell=False)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"\n[sqlmap] Process timeout reached ({timeout} seconds); stopping scanner...")
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 124
    except KeyboardInterrupt:
        print("\n[sqlmap] Stop requested. Terminating scanner...")
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 130


def main() -> int:
    args = _parse_args()
    if not 30 <= args.timeout <= 3600:
        print("Error: --timeout must be between 30 and 3600 seconds.", file=sys.stderr)
        return 2

    try:
        target_url = _ask_for_target(args.url)
    except TargetValidationError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2
    except EOFError:
        print("No target URL was provided.", file=sys.stderr)
        return 2

    try:
        if not _confirm_authorization(target_url):
            print("Authorization was not confirmed. No scan was started.")
            return 4
        sqlmap_home = ensure_sqlmap()
        run_dir = _create_run_directory(target_url)
        command = build_sqlmap_command(sqlmap_home, target_url, run_dir)
    except (EOFError, OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Unable to prepare sqlmap: {exc}", file=sys.stderr)
        return 3

    print(f"\nCerberus output directory: {run_dir}")
    exit_code = _run_process(command, sqlmap_home, args.timeout)
    print(f"\n[sqlmap] Finished with exit code {exit_code}.")
    print(f"[sqlmap] Review the upstream output/session files under: {run_dir}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
