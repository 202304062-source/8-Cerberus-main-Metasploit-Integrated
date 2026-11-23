"""Project-local bootstrap for the pinned upstream jwt_tool release."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

JWT_TOOL_TAG = "v2.3.0"
JWT_TOOL_ZIP = f"https://github.com/ticarpi/jwt_tool/archive/refs/tags/{JWT_TOOL_TAG}.zip"
USER_AGENT = "Cerberus-Auth-Audit/1.0"


class ToolInstallError(RuntimeError):
    """Raised when an upstream tool cannot be prepared locally."""


class JWTToolInstaller:
    def __init__(self, runtime_root: str | Path | None = None) -> None:
        module_root = Path(__file__).resolve().parent
        self.runtime_root = Path(runtime_root or module_root / ".runtime").resolve()
        self.source_dir = self.runtime_root / "external" / "jwt_tool"
        self.venv_dir = self.runtime_root / "venvs" / "jwt_tool"

    @property
    def python_executable(self) -> Path:
        if os.name == "nt":
            return self.venv_dir / "Scripts" / "python.exe"
        return self.venv_dir / "bin" / "python"

    def ensure_installed(self) -> tuple[Path, Path]:
        script = self.source_dir / "jwt_tool.py"
        requirements = self.source_dir / "requirements.txt"
        if not script.is_file():
            self.source_dir.parent.mkdir(parents=True, exist_ok=True)
            archive = self.runtime_root / "downloads" / f"jwt_tool-{JWT_TOOL_TAG}.zip"
            self._download(JWT_TOOL_ZIP, archive, max_bytes=20 * 1024 * 1024)
            staging = self.source_dir.parent / "jwt_tool-staging"
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(parents=True, exist_ok=True)
            self._safe_extract_zip(archive, staging)
            extracted = next((p for p in staging.iterdir() if p.is_dir()), None)
            if not extracted or not (extracted / "jwt_tool.py").is_file():
                raise ToolInstallError("The pinned jwt_tool archive did not contain jwt_tool.py.")
            shutil.rmtree(self.source_dir, ignore_errors=True)
            extracted.rename(self.source_dir)
            shutil.rmtree(staging, ignore_errors=True)
        if not requirements.is_file():
            raise ToolInstallError("jwt_tool requirements.txt is missing from the downloaded source.")
        if not self.python_executable.is_file():
            self.venv_dir.parent.mkdir(parents=True, exist_ok=True)
            self._run_checked([sys.executable, "-m", "venv", str(self.venv_dir)], timeout=180)
        dependency_marker = self.venv_dir / ".cerberus_jwt_tool_requirements_ready"
        if not dependency_marker.is_file():
            self._run_checked(
                [str(self.python_executable), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(requirements)],
                timeout=600,
            )
            dependency_marker.write_text(JWT_TOOL_TAG, encoding="ascii")
        return script, self.python_executable

    def run_local_decode(self, token: str, public_key: str | Path | None = None) -> subprocess.CompletedProcess[str]:
        script, python = self.ensure_installed()
        extra_args: list[str] = []
        if public_key is not None:
            key_candidate = Path(public_key).expanduser()
            if key_candidate.is_symlink():
                raise ToolInstallError("The public-key file must not be a symbolic link.")
            key_path = key_candidate.resolve()
            if not key_path.is_file():
                raise ToolInstallError("The public-key file must be a local regular file.")
            extra_args.extend(["-V", "-pk", str(key_path)])
        state_root = self.runtime_root / "state"
        state_root.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        # jwt_tool may create a logfile, config, or key material on first run.
        # A temporary working directory removes those artifacts when this call ends.
        # A tiny bridge feeds the token over stdin rather than exposing it in the OS argv.
        bridge_source = (
            "import os, runpy, sys\n"
            "script = os.path.abspath(sys.argv[1])\n"
            "extra = sys.argv[2:]\n"
            "sys.path.insert(0, os.path.dirname(script))\n"
            "token = sys.stdin.read().strip()\n"
            "sys.argv = [script, token, *extra]\n"
            "runpy.run_path(script, run_name='__main__')\n"
        )
        try:
            with tempfile.TemporaryDirectory(prefix="jwt-tool-run-", dir=state_root) as temporary_home:
                bridge = Path(temporary_home) / "jwt_tool_stdin_bridge.py"
                bridge.write_text(bridge_source, encoding="utf-8")
                env["HOME"] = temporary_home
                env["USERPROFILE"] = temporary_home
                env["APPDATA"] = temporary_home
                return subprocess.run(
                    [str(python), str(bridge), str(script), *extra_args],
                    input=token,
                    cwd=temporary_home,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolInstallError(f"jwt_tool execution failed: {exc}") from exc

    @staticmethod
    def _download(url: str, destination: Path, *, max_bytes: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        temporary = destination.with_suffix(destination.suffix + ".part")
        total = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as out:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ToolInstallError("Upstream archive exceeded the configured download size limit.")
                    out.write(chunk)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _safe_extract_zip(archive: Path, destination: Path) -> None:
        base = destination.resolve()
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                member = PurePosixPath(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise ToolInstallError("Unsafe path found in jwt_tool archive.")
                target = (destination / Path(*member.parts)).resolve()
                if base not in target.parents and target != base:
                    raise ToolInstallError("Archive extraction escaped the destination directory.")
            zf.extractall(destination)

    @staticmethod
    def _run_checked(command: list[str], *, timeout: int) -> None:
        try:
            process = subprocess.run(command, check=False, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolInstallError(f"Could not prepare jwt_tool dependencies: {exc}") from exc
        if process.returncode != 0:
            raise ToolInstallError(f"jwt_tool setup command failed with exit code {process.returncode}.")
