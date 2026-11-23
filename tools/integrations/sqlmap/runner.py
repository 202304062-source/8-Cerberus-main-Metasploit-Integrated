"""Safe command construction and target validation for the sqlmap CLI.

This module deliberately does not parse sqlmap output. The upstream program is
launched as a separate process and writes its raw output directly to the user's
terminal, matching sqlmap's published guidance for external shell launchers.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit


class TargetValidationError(ValueError):
    """Raised when a target is not a single valid HTTP(S) URL."""


def validate_target_url(value: str) -> str:
    """Validate and return one HTTP(S) URL without changing its value.

    URL syntax validation is not proof of authorization. Authorization is
    separately confirmed by the interactive CLI before the scanner is started.
    """
    if not isinstance(value, str):
        raise TargetValidationError("The target must be a text URL.")

    target = value.strip()
    if not target:
        raise TargetValidationError("The target URL cannot be empty.")
    if any(ord(char) < 32 or char.isspace() for char in target):
        raise TargetValidationError("The target URL must not contain whitespace or control characters.")

    try:
        parsed = urlsplit(target)
        _ = parsed.port  # Force validation of an explicitly supplied port.
    except ValueError as exc:
        raise TargetValidationError(f"Malformed target URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// target URLs are accepted.")
    if not parsed.hostname:
        raise TargetValidationError("The URL must include a host name or IP address.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("URLs containing embedded usernames or passwords are not accepted.")

    return target


def build_sqlmap_command(
    sqlmap_home: Path,
    target_url: str,
    output_dir: Path,
    python_executable: str | None = None,
) -> list[str]:
    """Build a constrained, detection-only sqlmap command.

    No database enumeration, data dumping, file access, OS command execution,
    crawling, forms discovery, tamper scripts, or arbitrary user flags are added.
    """
    target = validate_target_url(target_url)
    sqlmap_script = Path(sqlmap_home).resolve() / "sqlmap.py"
    if not sqlmap_script.is_file():
        raise FileNotFoundError(f"sqlmap.py was not found at: {sqlmap_script}")

    report_path = Path(output_dir).resolve()
    interpreter = python_executable or sys.executable

    return [
        interpreter,
        str(sqlmap_script),
        "-u",
        target,
        "--batch",
        "--level=1",
        "--risk=1",
        "--technique=BE",
        "--threads=1",
        "--timeout=10",
        "--retries=1",
        "--ignore-redirects",
        f"--output-dir={report_path}",
    ]
