"""First-run bootstrap for the official sqlmap source checkout.

sqlmap is fetched into a project-local runtime directory on first use. Its
upstream source and license remain separate from Cerberus; no sqlmap source is
vendored, modified, imported, or parsed by this integration.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_ROOT = PROJECT_ROOT / "tools" / "external" / "sqlmap_runtime"
SQLMAP_HOME = RUNTIME_ROOT / "sqlmap"
UPSTREAM_GIT = "https://github.com/sqlmapproject/sqlmap.git"
ARCHIVE_URLS = (
    "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
    "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/main.zip",
)


def _is_sqlmap_checkout(path: Path) -> bool:
    return (path / "sqlmap.py").is_file() and (path / "LICENSE").is_file()


def _clone_with_git(destination: Path) -> bool:
    git = shutil.which("git")
    if not git:
        return False

    result = subprocess.run(
        [git, "clone", "--depth", "1", UPSTREAM_GIT, str(destination)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
    )
    return result.returncode == 0 and _is_sqlmap_checkout(destination)


def _safe_extract(archive: zipfile.ZipFile, destination: Path) -> Path | None:
    """Extract a GitHub ZIP after rejecting path traversal entries."""
    destination.mkdir(parents=True, exist_ok=True)
    root_resolved = destination.resolve()

    for member in archive.infolist():
        # Normalize both separators so Windows-style traversal is rejected too.
        normalized_name = member.filename.replace("\\", "/")
        member_path = PurePosixPath(normalized_name)
        if (
            member_path.is_absolute()
            or ".." in member_path.parts
            or any(":" in part for part in member_path.parts)
        ):
            raise RuntimeError("The upstream archive contains an unsafe path entry.")
        target_path = (destination / Path(*member_path.parts)).resolve()
        if target_path != root_resolved and root_resolved not in target_path.parents:
            raise RuntimeError("The upstream archive contains an unsafe extraction path.")
        if member.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target_path.open("wb") as output:
                shutil.copyfileobj(source, output)

    for child in destination.iterdir():
        if child.is_dir() and _is_sqlmap_checkout(child):
            return child
    return None


def _download_archive(destination: Path) -> bool:
    request_headers = {"User-Agent": "Cerberus-SQLMap-Launcher/1.0"}
    for archive_url in ARCHIVE_URLS:
        try:
            request = urllib.request.Request(archive_url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=90) as response:
                with tempfile.NamedTemporaryFile(prefix="cerberus-sqlmap-", suffix=".zip", delete=False) as handle:
                    archive_path = Path(handle.name)
                    shutil.copyfileobj(response, handle)

            try:
                with zipfile.ZipFile(archive_path) as archive:
                    extracted = _safe_extract(archive, destination)
                    if extracted:
                        shutil.move(str(extracted), str(destination / "sqlmap-checkout"))
                        return _is_sqlmap_checkout(destination / "sqlmap-checkout")
            finally:
                archive_path.unlink(missing_ok=True)
        except (OSError, urllib.error.URLError, zipfile.BadZipFile, RuntimeError):
            continue
    return False


def ensure_sqlmap() -> Path:
    """Return the cached official sqlmap checkout, bootstrapping when needed."""
    if _is_sqlmap_checkout(SQLMAP_HOME):
        print(f"[sqlmap] Using the existing project-local checkout: {SQLMAP_HOME}")
        return SQLMAP_HOME

    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    print("[sqlmap] First run: fetching the official sqlmap source into Cerberus...")
    print("[sqlmap] This requires internet access once. No separate manual install is needed.")

    with tempfile.TemporaryDirectory(prefix="sqlmap-bootstrap-", dir=RUNTIME_ROOT) as temporary:
        temporary_root = Path(temporary)
        git_destination = temporary_root / "git-checkout"
        checkout: Path | None = None

        try:
            if _clone_with_git(git_destination):
                checkout = git_destination
        except (OSError, subprocess.SubprocessError):
            checkout = None

        if checkout is None:
            archive_destination = temporary_root / "archive-extract"
            if _download_archive(archive_destination):
                checkout = archive_destination / "sqlmap-checkout"

        if checkout is None or not _is_sqlmap_checkout(checkout):
            raise RuntimeError(
                "Could not download sqlmap from its official GitHub repository. "
                "Check internet access, proxy settings, and GitHub availability, then retry."
            )

        if SQLMAP_HOME.exists():
            # Do not overwrite an unexpected pre-existing directory.
            raise RuntimeError(
                f"A non-sqlmap directory already exists at {SQLMAP_HOME}. "
                "Move it aside manually before retrying; it was not changed."
            )
        shutil.move(str(checkout), str(SQLMAP_HOME))

    print(f"[sqlmap] Official source is ready at: {SQLMAP_HOME}")
    print("[sqlmap] The upstream LICENSE file is retained with the downloaded source.")
    return SQLMAP_HOME
