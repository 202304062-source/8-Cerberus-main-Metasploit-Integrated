"""Interactive, official-source bootstrap for Nmap.

Nmap is not redistributed in the Cerberus repository. If it is missing, this
module offers to install it from the official Nmap website on Windows or from
the host OS package manager on macOS/Linux.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from .runner import find_nmap

OFFICIAL_DOWNLOAD_PAGE = "https://nmap.org/download.html"
USER_AGENT = "Cerberus-Nmap-Integration/1.0"


class NmapInstallError(RuntimeError):
    """Raised when the Nmap bootstrap cannot complete."""


def _download_latest_windows_installer() -> Path:
    request = urllib.request.Request(OFFICIAL_DOWNLOAD_PAGE, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            page = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise NmapInstallError(f"Could not read the official Nmap download page: {exc}") from exc

    matches = re.findall(
        r"(?:https?://nmap\.org)?/dist/(nmap-([0-9]+(?:\.[0-9]+)+)-setup\.exe)",
        page,
        flags=re.IGNORECASE,
    )
    if not matches:
        raise NmapInstallError(
            "Could not identify the current Windows installer on the official Nmap page. "
            f"Open {OFFICIAL_DOWNLOAD_PAGE} and install Nmap manually, then rerun Cerberus."
        )
    filename, version = sorted(matches, key=lambda item: tuple(int(x) for x in item[1].split(".")), reverse=True)[0]
    url = f"https://nmap.org/dist/{filename}"
    destination = Path(tempfile.gettempdir()) / filename
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise NmapInstallError(f"Could not download Nmap {version} from nmap.org: {exc}") from exc
    if destination.stat().st_size < 5_000_000:
        destination.unlink(missing_ok=True)
        raise NmapInstallError("The downloaded installer is unexpectedly small; refusing to run it.")
    return destination


def _windows_install() -> str:
    installer = _download_latest_windows_installer()
    print(f"[CERBERUS][NMAP] Downloaded official installer: {installer}")
    print("[CERBERUS][NMAP] The Nmap setup wizard will open. Allow Npcap installation if prompted;")
    print("[CERBERUS][NMAP] Npcap may request administrator approval for packet-capture features.")
    try:
        completed = subprocess.run([str(installer)], check=False)
    except OSError as exc:
        raise NmapInstallError(f"Could not launch the Nmap installer: {exc}") from exc
    finally:
        # Keep downloaded setup until installer exits; then remove temporary copy.
        installer.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise NmapInstallError(f"Nmap installer returned code {completed.returncode}.")
    path = find_nmap()
    if not path:
        raise NmapInstallError(
            "The installer finished, but nmap.exe was not found. Close and reopen VS Code/Terminal "
            "to refresh PATH, or install from https://nmap.org/download.html."
        )
    return path


def _unix_install() -> str:
    system = platform.system().lower()
    if system == "darwin":
        brew = shutil.which("brew")
        if not brew:
            raise NmapInstallError("Homebrew is required for automatic macOS installation. Install Homebrew or Nmap from nmap.org.")
        command = [brew, "install", "nmap"]
    else:
        if shutil.which("apt-get"):
            command = ["apt-get", "install", "-y", "nmap"]
        elif shutil.which("dnf"):
            command = ["dnf", "install", "-y", "nmap"]
        elif shutil.which("yum"):
            command = ["yum", "install", "-y", "nmap"]
        elif shutil.which("pacman"):
            command = ["pacman", "-S", "--noconfirm", "nmap"]
        else:
            raise NmapInstallError("No supported package manager found. Install Nmap from https://nmap.org/download.html.")
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo:
                raise NmapInstallError(f"Administrator privileges required. Run: sudo {' '.join(command)}")
            command.insert(0, sudo)
    print("[CERBERUS][NMAP] Installing Nmap through the system package manager:")
    print("[CERBERUS][NMAP] " + " ".join(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise NmapInstallError(f"Package manager returned code {completed.returncode}.")
    path = find_nmap()
    if not path:
        raise NmapInstallError("Package installation completed, but Nmap was not found on PATH.")
    return path


def ensure_nmap(*, allow_install: bool = True, input_fn=input) -> str:
    """Return an Nmap executable path, optionally offering an interactive install."""
    found = find_nmap()
    if found:
        return found
    if not allow_install:
        raise NmapInstallError("Nmap is not installed. Rerun without --no-install to use the integrated bootstrap.")
    print("[CERBERUS][NMAP] Nmap was not found on this computer.")
    print("[CERBERUS][NMAP] Cerberus can fetch the official Nmap installer/package automatically.")
    try:
        answer = input_fn("Download/install Nmap now? [Y/N]: ")
    except EOFError:
        answer = "N"
    if answer.strip().lower() not in {"y", "yes"}:
        raise NmapInstallError("Installation cancelled. Install Nmap from https://nmap.org/download.html and retry.")
    if platform.system().lower() == "windows":
        return _windows_install()
    return _unix_install()
