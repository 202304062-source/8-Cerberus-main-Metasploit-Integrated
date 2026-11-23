"""Download the official pinned Bettercap release into this integration's runtime folder.

No Bettercap binary is committed to the repository. A fresh clone can bootstrap the
official prebuilt executable on first run, keeping the GitHub repository source-only.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

BETTERCAP_VERSION = "v2.42.0"
GITHUB_API_URL = (
    "https://api.github.com/repos/bettercap/bettercap/releases/tags/"
    + BETTERCAP_VERSION
)
MAX_DOWNLOAD_BYTES = 120 * 1024 * 1024
USER_AGENT = "Cerberus-Bettercap-Integration/1.0"


class BettercapBootstrapError(RuntimeError):
    """Raised when the Bettercap executable cannot be located or bootstrapped."""


def _platform_asset_tokens() -> tuple[str, str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "windows" and machine in {"amd64", "x86_64", "x64"}:
        return "windows", "amd64", "bettercap.exe"
    if system == "linux" and machine in {"amd64", "x86_64", "x64"}:
        return "linux", "amd64", "bettercap"
    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "darwin", "arm64", "bettercap"
    raise BettercapBootstrapError(
        "No pinned upstream prebuilt is configured for this platform. "
        "Supported bundles: Windows amd64, Linux amd64, and macOS arm64. "
        "Install Bettercap manually using its official installation guide, then "
        "extend this platform map if needed."
    )


def _request_bytes(url: str, *, limit: int, accept: str = "application/octet-stream") -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": accept},
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > limit:
                raise BettercapBootstrapError("Upstream download exceeds the configured size limit.")
            data = response.read(limit + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BettercapBootstrapError(f"Unable to download the official Bettercap release: {exc}") from exc
    if len(data) > limit:
        raise BettercapBootstrapError("Upstream download exceeds the configured size limit.")
    return data


def _select_asset(release: dict[str, Any], os_token: str, arch_token: str) -> dict[str, Any]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise BettercapBootstrapError("GitHub release metadata did not contain an asset list.")
    candidates = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", "")).lower()
        url = asset.get("browser_download_url")
        if (
            os_token in name
            and arch_token in name
            and name.endswith((".zip", ".tar.gz", ".tgz"))
            and isinstance(url, str)
        ):
            candidates.append(asset)
    if not candidates:
        raise BettercapBootstrapError(
            f"No {os_token}/{arch_token} archive was found in official release "
            f"{BETTERCAP_VERSION}. Check the Bettercap releases page."
        )
    # Prefer ZIP on Windows and tar.gz elsewhere; otherwise use the first exact platform match.
    preferred = ".zip" if os_token == "windows" else ".tar.gz"
    candidates.sort(key=lambda item: (not str(item.get("name", "")).lower().endswith(preferred), str(item.get("name", ""))))
    return candidates[0]


def _extract_executable(archive_bytes: bytes, archive_name: str, executable_name: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    found: bytes | None = None
    try:
        if archive_name.lower().endswith(".zip"):
            import io
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                for info in archive.infolist():
                    if not info.is_dir() and Path(info.filename.replace("\\", "/")).name.lower() == executable_name.lower():
                        found = archive.read(info)
                        break
        else:
            import io
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
                for member in archive.getmembers():
                    if member.isfile() and Path(member.name.replace("\\", "/")).name.lower() == executable_name.lower():
                        handle = archive.extractfile(member)
                        if handle:
                            found = handle.read(MAX_DOWNLOAD_BYTES)
                        break
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        raise BettercapBootstrapError(f"The downloaded Bettercap archive is invalid: {exc}") from exc
    if not found:
        raise BettercapBootstrapError(
            f"The official archive did not contain the expected {executable_name} executable."
        )
    if len(found) > MAX_DOWNLOAD_BYTES:
        raise BettercapBootstrapError("Extracted Bettercap executable exceeds the size limit.")
    with tempfile.NamedTemporaryFile(prefix="bettercap-", suffix=".tmp", dir=destination.parent, delete=False) as temp:
        temp.write(found)
        temp_path = Path(temp.name)
    try:
        temp_path.replace(destination)
    finally:
        temp_path.unlink(missing_ok=True)
    if os.name != "nt":
        destination.chmod(0o755)


def ensure_bettercap(*, allow_install: bool = True, integration_dir: Path | None = None) -> Path:
    """Return the project-local Bettercap binary, downloading official release if absent."""
    if integration_dir is None:
        integration_dir = Path(__file__).resolve().parent
    os_token, arch_token, executable_name = _platform_asset_tokens()
    runtime_dir = integration_dir / ".runtime"
    binary_path = runtime_dir / executable_name
    if binary_path.is_file() and binary_path.stat().st_size > 0:
        return binary_path
    if not allow_install:
        raise BettercapBootstrapError(
            f"Bettercap was not found at {binary_path}. Re-run without --no-install to bootstrap it."
        )

    runtime_dir.mkdir(parents=True, exist_ok=True)
    metadata_bytes = _request_bytes(
        GITHUB_API_URL,
        limit=5 * 1024 * 1024,
        accept="application/vnd.github+json",
    )
    try:
        release = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BettercapBootstrapError(f"GitHub returned invalid release metadata: {exc}") from exc
    if release.get("tag_name") != BETTERCAP_VERSION:
        raise BettercapBootstrapError(
            f"Expected release {BETTERCAP_VERSION}, received {release.get('tag_name')!r}."
        )
    asset = _select_asset(release, os_token, arch_token)
    archive_name = str(asset["name"])
    archive_bytes = _request_bytes(str(asset["browser_download_url"]), limit=MAX_DOWNLOAD_BYTES)

    # Verify the GitHub-provided SHA-256 digest when present in release metadata.
    digest = asset.get("digest")
    if isinstance(digest, str) and digest.lower().startswith("sha256:"):
        expected = digest.split(":", 1)[1].lower()
        actual = hashlib.sha256(archive_bytes).hexdigest()
        if actual != expected:
            raise BettercapBootstrapError("Bettercap release SHA-256 verification failed; archive was discarded.")

    _extract_executable(archive_bytes, archive_name, executable_name, binary_path)
    return binary_path
