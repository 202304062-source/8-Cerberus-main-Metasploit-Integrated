"""JWT metadata review followed by an authenticated, passive ZAP Baseline scan."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from tools.integrations.owasp_zap.runner import ZAPBaselineRunner, ZAPExecutionError, validate_target_url
from tools.integrations.auth_security_audit.jwt_inspector import inspect_jwt
from tools.integrations.auth_security_audit.jwt_tool_installer import JWTToolInstaller, ToolInstallError


class JWTZAPError(RuntimeError):
    """Raised when JWT/ZAP workflow validation or execution fails."""


def validate_compact_token(token: str) -> str:
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise ValueError("JWT must be non-empty text no longer than 16 KiB.")
    if any(ch.isspace() or ord(ch) < 32 for ch in token):
        raise ValueError("JWT must not contain whitespace or control characters.")
    if len(token.split(".")) != 3:
        raise ValueError("JWT must use three-part compact serialization.")
    return token


def build_zap_replacer_config(target: str, token: str, header_name: str = "Authorization") -> str:
    """Create a ZAP Replacer config limited to the target's scheme/host/port."""
    normalized = validate_target_url(target)
    token = validate_compact_token(token)
    if header_name != "Authorization":
        raise ValueError("Only the Authorization request header is supported in this version.")
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    host_pattern = re.escape(host).replace("\\", "\\\\")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    url_regex = f"^{parsed.scheme.lower()}://{host_pattern}:{port}/.*$"
    replacement = f"Bearer {token}"
    if any(ch in replacement for ch in "\r\n\x00"):
        raise ValueError("JWT cannot contain line breaks or NUL bytes.")
    lines = [
        "# Temporary Cerberus Authorization rule; deleted after the ZAP process exits.",
        "replacer.full_list(0).description=Cerberus JWT Authorization Header",
        "replacer.full_list(0).enabled=true",
        "replacer.full_list(0).matchtype=REQ_HEADER",
        "replacer.full_list(0).matchstr=Authorization",
        "replacer.full_list(0).regex=false",
        f"replacer.full_list(0).replacement={replacement}",
        f"replacer.full_list(0).url={url_regex}",
    ]
    return "\n".join(lines) + "\n"


class JWTZAPAuthRunner:
    """Runs jwt_tool locally, then ZAP Baseline with a target-scoped Bearer header."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        timeout_seconds: int = 20 * 60,
        jwt_installer: JWTToolInstaller | None = None,
        zap_runner: ZAPBaselineRunner | None = None,
    ) -> None:
        module_root = Path(__file__).resolve().parent
        self.output_root = Path(output_directory or module_root / "reports" / "jwt_zap").expanduser().resolve()
        self.timeout_seconds = timeout_seconds
        self.jwt_installer = jwt_installer or JWTToolInstaller()
        self.zap_runner = zap_runner or ZAPBaselineRunner(timeout_seconds=timeout_seconds)

    @staticmethod
    def _redact_token_from_reports(run_dir: Path, token: str) -> None:
        """Remove any echoed Bearer JWT from text reports before they are retained."""
        for report in run_dir.iterdir():
            if not report.is_file() or report.suffix.lower() not in {".html", ".json", ".xml", ".md", ".txt"}:
                continue
            try:
                content = report.read_text(encoding="utf-8", errors="replace")
                content = content.replace(f"Bearer {token}", "Bearer [REDACTED JWT]")
                content = content.replace(token, "[REDACTED JWT]")
                report.write_text(content, encoding="utf-8")
            except OSError:
                # Keep the scan result even if an optional report cannot be scrubbed.
                print(f"[CERBERUS][JWT+ZAP] WARNING: Could not inspect/redact {report.name}.", flush=True)

    def run(
        self,
        target: str,
        token: str,
        *,
        authorized: bool,
        public_key_path: str | Path | None = None,
        minutes: int = 1,
        refresh_image: bool = True,
    ) -> dict[str, object]:
        if authorized is not True:
            raise JWTZAPError("Workflow blocked: explicit authorization is required.")
        normalized_target = validate_target_url(target)
        token = validate_compact_token(token)
        if not 1 <= minutes <= 10:
            raise ValueError("ZAP spider duration must be between 1 and 10 minutes.")
        jwt_metadata = inspect_jwt(token)
        try:
            jwt_result = self.jwt_installer.run_local_decode(token, public_key_path)
        except ToolInstallError as exc:
            raise JWTZAPError(str(exc)) from exc
        print("[CERBERUS][JWT] Local jwt_tool output (may contain sensitive claims):", flush=True)
        if jwt_result.stdout:
            safe_stdout = jwt_result.stdout.replace(token, "[REDACTED JWT]")
            print(safe_stdout, end="" if safe_stdout.endswith("\n") else "\n", flush=True)
        if jwt_result.stderr:
            safe_stderr = jwt_result.stderr.replace(token, "[REDACTED JWT]")
            print(safe_stderr, flush=True)
        if jwt_result.returncode != 0:
            raise JWTZAPError(f"jwt_tool exited with code {jwt_result.returncode}; ZAP was not started.")

        self.output_root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        host_label = re.sub(r"[^A-Za-z0-9]+", "-", urlsplit(normalized_target).hostname or "target")[:36].strip("-") or "target"
        run_dir = self.output_root / f"{stamp}_{host_label}_{uuid.uuid4().hex[:8]}"
        run_dir.mkdir(parents=True, exist_ok=False)
        report_stem = "jwt_zap_baseline"
        config_path = run_dir / f".zap-auth-{uuid.uuid4().hex}.properties"
        container_name = f"cerberus-jwt-zap-{uuid.uuid4().hex[:12]}"
        config_path.write_text(build_zap_replacer_config(normalized_target, token), encoding="ascii")
        started = datetime.now(timezone.utc)
        tick = time.monotonic()
        exit_code: int | None = None
        command: list[str] = []
        try:
            # Build a fresh ZAP runner bound to this workflow's report directory.
            # This keeps authenticated reports/config inside the new integration
            # and does not alter the pre-existing ZAP integration's output path.
            zap_runner = ZAPBaselineRunner(
                output_directory=run_dir,
                image=self.zap_runner.image,
                timeout_seconds=self.timeout_seconds,
            )
            docker = zap_runner._docker_executable()
            if refresh_image:
                zap_runner._pull_image(docker)
            command = zap_runner.build_scan_command(
                docker,
                normalized_target,
                report_stem,
                container_name,
                minutes,
            )
            # -z is forwarded by zap-baseline.py to the ZAP process. The config file
            # keeps the JWT out of the process command line and is removed in finally.
            command.extend(["-z", f"-configfile /zap/wrk/{config_path.name}"])
            print("[CERBERUS][JWT+ZAP] Starting authenticated passive baseline scan.", flush=True)
            print(f"[CERBERUS][JWT+ZAP] Target: {normalized_target}", flush=True)
            print(f"[CERBERUS][JWT+ZAP] Reports: {run_dir}", flush=True)
            process = subprocess.Popen(command, shell=False)
            try:
                exit_code = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise JWTZAPError(f"ZAP exceeded {self.timeout_seconds} seconds; partial reports may remain in {run_dir}.") from exc
        except (OSError, ZAPExecutionError) as exc:
            raise JWTZAPError(str(exc)) from exc
        finally:
            config_path.unlink(missing_ok=True)
            self._redact_token_from_reports(run_dir, token)

        duration = round(time.monotonic() - tick, 2)
        status_map = {0: "completed", 1: "completed_with_fail_alerts", 2: "completed_with_warnings"}
        status = status_map.get(exit_code, "scanner_error")
        if exit_code not in {0, 1, 2}:
            raise JWTZAPError(f"ZAP baseline failed with exit code {exit_code}.")
        result: dict[str, object] = {
            "target": normalized_target,
            "status": status,
            "exit_code": exit_code,
            "scan_mode": "authenticated-baseline-passive",
            "authentication": "Bearer JWT sent only to the configured target origin by ZAP Replacer",
            "jwt_tool_release": "v2.3.0",
            "jwt_signature_verification": "performed_with_public_key" if public_key_path else "not_performed",
            "jwt_metadata": jwt_metadata,
            "started_at_utc": started.isoformat(),
            "duration_seconds": duration,
            "reports": {
                "html": str(run_dir / f"{report_stem}.html"),
                "json": str(run_dir / f"{report_stem}.json"),
                "xml": str(run_dir / f"{report_stem}.xml"),
            },
            "limitations": [
                "ZAP Baseline performs spidering and passive analysis only; it does not run active attacks.",
                "This workflow reuses an existing JWT. It does not perform login, refresh-token rotation, logout, or server-side revocation tests.",
                "JWT metadata inspection is not a substitute for server-side signature, issuer, audience, or authorization checks.",
            ],
        }
        (run_dir / "auth_audit_summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[CERBERUS][JWT+ZAP] Finished: {status} (exit {exit_code}).", flush=True)
        return result
