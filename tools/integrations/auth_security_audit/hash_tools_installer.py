"""Project-local bootstrap for official John the Ripper and Hashcat releases."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

USER_AGENT = "Cerberus-Auth-Audit/1.0"
GITHUB_API = "https://api.github.com"


class HashToolInstallError(RuntimeError):
    """Raised when an offline hash-audit tool cannot be installed or located."""


class HashToolsInstaller:
    def __init__(self, runtime_root: str | Path | None = None) -> None:
        module_root = Path(__file__).resolve().parent
        self.runtime_root = Path(runtime_root or module_root / ".runtime").resolve()
        self.external_dir = self.runtime_root / "external"
        self.download_dir = self.runtime_root / "downloads"
        self.python_packages = self.runtime_root / "python_packages"

    def find_tool(self, engine: str) -> str | None:
        names = {"john": ("john.exe", "john"), "hashcat": ("hashcat.exe", "hashcat")}.get(engine)
        if not names:
            raise ValueError("engine must be john or hashcat")
        for name in names:
            found = shutil.which(name)
            if found:
                return found
        search_root = self.external_dir / engine
        if search_root.is_dir():
            for name in names:
                matches = list(search_root.rglob(name))
                if matches:
                    return str(matches[0].resolve())
        return None

    def ensure_tool(self, engine: str) -> str:
        found = self.find_tool(engine)
        if found:
            return found
        if os.name != "nt":
            raise HashToolInstallError(
                f"{engine} was not found. Install it with your OS package manager or place its executable on PATH. "
                "On Windows this integration can bootstrap the official prebuilt release into the project runtime folder."
            )
        if platform.architecture()[0] != "64bit":
            raise HashToolInstallError("Automatic Windows installation currently supports 64-bit Windows only.")
        if engine == "john":
            self._install_john_windows()
        elif engine == "hashcat":
            self._install_hashcat_windows()
        else:
            raise ValueError("engine must be john or hashcat")
        found = self.find_tool(engine)
        if not found:
            raise HashToolInstallError(f"{engine} installer finished but its executable was not found.")
        return found

    def _install_john_windows(self) -> None:
        release = self._github_json(f"{GITHUB_API}/repos/openwall/john-packages/releases/latest")
        assets = release.get("assets", [])
        asset = next((x for x in assets if x.get("name") == "winX64_1_JtR.zip"), None)
        if not asset:
            raise HashToolInstallError("Official Openwall release did not publish a winX64_1_JtR.zip asset.")
        url = asset.get("browser_download_url", "")
        if not url.startswith("https://github.com/openwall/john-packages/releases/download/"):
            raise HashToolInstallError("Unexpected John download URL; refusing to download.")
        archive = self.download_dir / "john-win64.zip"
        self._download(url, archive, max_bytes=150 * 1024 * 1024)
        observed_digest = self._sha256(archive)
        destination = self.external_dir / "john"
        staging = self.external_dir / "john-staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        self._safe_extract_zip(archive, staging)
        if not list(staging.rglob("john.exe")):
            shutil.rmtree(staging, ignore_errors=True)
            raise HashToolInstallError("The official John archive did not contain john.exe.")
        shutil.rmtree(destination, ignore_errors=True)
        staging.rename(destination)
        self._write_manifest("john", release.get("tag_name"), url, observed_digest, verified=False)

    def _install_hashcat_windows(self) -> None:
        release = self._github_json(f"{GITHUB_API}/repos/hashcat/hashcat/releases/latest")
        assets = release.get("assets", [])
        asset = next((x for x in assets if str(x.get("name", "")).lower().endswith(".7z") and str(x.get("name", "")).startswith("hashcat-")), None)
        if not asset:
            raise HashToolInstallError("Official Hashcat release did not publish its .7z binary package.")
        digest = asset.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise HashToolInstallError("Hashcat release metadata did not provide a SHA-256 digest; download was refused.")
        url = asset.get("browser_download_url", "")
        if not url.startswith("https://github.com/hashcat/hashcat/releases/download/"):
            raise HashToolInstallError("Unexpected Hashcat download URL; refusing to download.")
        archive = self.download_dir / str(asset["name"])
        self._download(url, archive, max_bytes=250 * 1024 * 1024)
        actual = self._sha256(archive)
        expected = digest.split(":", 1)[1].lower()
        if actual.lower() != expected:
            archive.unlink(missing_ok=True)
            raise HashToolInstallError("Hashcat archive SHA-256 does not match official GitHub release metadata.")
        self._extract_7z(archive, self.external_dir / "hashcat")
        if not list((self.external_dir / "hashcat").rglob("hashcat.exe")):
            raise HashToolInstallError("The official Hashcat archive did not contain hashcat.exe.")
        self._write_manifest("hashcat", release.get("tag_name"), url, actual, verified=True)

    def _extract_7z(self, archive: Path, destination: Path) -> None:
        seven_zip = shutil.which("7z") or shutil.which("7zz")
        if seven_zip:
            staging = destination.with_name(destination.name + "-staging")
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(parents=True, exist_ok=True)
            try:
                proc = subprocess.run([seven_zip, "x", str(archive), f"-o{staging}", "-y"], check=False, timeout=300)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HashToolInstallError(f"7-Zip extraction failed: {exc}") from exc
            if proc.returncode != 0:
                raise HashToolInstallError("7-Zip could not extract Hashcat archive.")
            self._replace_directory(staging, destination)
            return
        self.python_packages.mkdir(parents=True, exist_ok=True)
        if not (self.python_packages / "py7zr").is_dir():
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-warn-script-location", "--target", str(self.python_packages), "py7zr>=1.0,<2"],
                    check=False,
                    timeout=300,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HashToolInstallError(f"Could not prepare the project-local 7z extractor: {exc}") from exc
            if proc.returncode != 0:
                raise HashToolInstallError("Could not install the project-local py7zr extractor.")
        sys.path.insert(0, str(self.python_packages))
        try:
            import py7zr  # type: ignore[import-not-found]
            staging = destination.with_name(destination.name + "-staging")
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(parents=True, exist_ok=True)
            with py7zr.SevenZipFile(archive, mode="r") as package:
                for name in package.getnames():
                    member = Path(name)
                    if member.is_absolute() or ".." in member.parts or (member.parts and ":" in member.parts[0]) or name.startswith(("\\", "/")):
                        raise HashToolInstallError("Unsafe path found in Hashcat archive.")
                package.extractall(path=staging)
            self._replace_directory(staging, destination)
        except Exception as exc:
            raise HashToolInstallError(f"Could not extract the official Hashcat archive: {exc}") from exc

    @staticmethod
    def _replace_directory(staging: Path, destination: Path) -> None:
        shutil.rmtree(destination, ignore_errors=True)
        staging.rename(destination)

    def _write_manifest(self, name: str, version: str | None, url: str, sha256: str | None, *, verified: bool) -> None:
        manifests = self.runtime_root / "install_manifest.json"
        try:
            data: dict[str, Any] = json.loads(manifests.read_text(encoding="utf-8")) if manifests.exists() else {}
        except json.JSONDecodeError:
            data = {}
        data[name] = {"version": version, "source_url": url, "sha256_observed": sha256, "sha256_verified_against_upstream_digest": verified}
        manifests.parent.mkdir(parents=True, exist_ok=True)
        manifests.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _github_json(url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read(2 * 1024 * 1024 + 1)
            if len(content) > 2 * 1024 * 1024:
                raise HashToolInstallError("GitHub release metadata exceeded the size limit.")
            value = json.loads(content.decode("utf-8"))
            if not isinstance(value, dict):
                raise HashToolInstallError("Unexpected GitHub release metadata.")
            return value
        except Exception as exc:
            if isinstance(exc, HashToolInstallError):
                raise
            raise HashToolInstallError(f"Could not read official release metadata: {exc}") from exc

    @staticmethod
    def _download(url: str, destination: Path, *, max_bytes: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        temporary = destination.with_suffix(destination.suffix + ".part")
        total = 0
        try:
            with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as out:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise HashToolInstallError("Tool archive exceeded the configured download size limit.")
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
                if member.is_absolute() or ".." in member.parts or (member.parts and ":" in member.parts[0]) or info.filename.startswith(("\\", "/")):
                    raise HashToolInstallError("Unsafe path found in John archive.")
                target = (destination / Path(*member.parts)).resolve()
                if base not in target.parents and target != base:
                    raise HashToolInstallError("John archive extraction escaped the destination directory.")
            zf.extractall(destination)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
