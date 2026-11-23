"""Locate Metasploit or offer an explicit, interactive official Windows setup.

The framework itself is not vendored in Cerberus. On Windows, this helper can
fetch the official Rapid7 MSI into this integration's ignored .runtime folder,
verify its Authenticode publisher, and launch the normal interactive installer.
It never performs a silent installation and never disables security controls.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

WINDOWS_INSTALLER_URL = "https://windows.metasploit.com/metasploitframework-latest.msi"
MAX_INSTALLER_BYTES = 2 * 1024 * 1024 * 1024
USER_AGENT = "Cerberus-Metasploit-Integration/1.0"


class MetasploitBootstrapError(RuntimeError):
    """Raised when Metasploit cannot be located or prepared."""


def find_msfconsole(explicit_path: str | None = None) -> str | None:
    """Find msfconsole from an explicit path, environment, PATH, or common folders."""
    candidates: list[Path] = []
    if explicit_path:
        candidate = Path(explicit_path).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        located = shutil.which(explicit_path)
        if located:
            return located
        if candidate.is_dir():
            candidates.extend(_console_candidates_under(candidate))
        else:
            return None

    env_path = os.environ.get("CERBERUS_MSFCONSOLE")
    if env_path:
        env_candidate = Path(env_path).expanduser()
        if env_candidate.is_file():
            return str(env_candidate.resolve())
        located = shutil.which(env_path)
        if located:
            return located

    for command in ("msfconsole", "msfconsole.bat", "msfconsole.exe"):
        located = shutil.which(command)
        if located:
            return located

    if os.name == "nt":
        roots = []
        for variable in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            root = os.environ.get(variable)
            if root:
                roots.append(Path(root))
        candidates.extend([
            Path(r"C:\Metasploit-framework\bin\msfconsole.bat"),
            Path(r"C:\Metasploit-framework\msfconsole.bat"),
            Path(r"C:\metasploit-framework\bin\msfconsole.bat"),
            Path(r"C:\metasploit-framework\msfconsole.bat"),
        ])
        for root in roots:
            candidates.extend(_console_candidates_under(root / "Metasploit"))
            candidates.extend(_console_candidates_under(root / "Metasploit-framework"))
    else:
        candidates.extend([
            Path("/opt/metasploit-framework/bin/msfconsole"),
            Path("/usr/bin/msfconsole"),
            Path("/usr/local/bin/msfconsole"),
        ])

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _console_candidates_under(directory: Path) -> list[Path]:
    return [
        directory / "bin" / "msfconsole.bat",
        directory / "msfconsole.bat",
        directory / "bin" / "msfconsole",
        directory / "msfconsole",
        directory / "bin" / "msfconsole.exe",
        directory / "msfconsole.exe",
    ]


def _download_official_windows_installer(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        WINDOWS_INSTALLER_URL,
        headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"},
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as handle:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_INSTALLER_BYTES:
                raise MetasploitBootstrapError("The official installer exceeds the configured 2 GB download limit.")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_INSTALLER_BYTES:
                    raise MetasploitBootstrapError("The installer download exceeded the configured 2 GB limit.")
                handle.write(chunk)
        if total < 10 * 1024 * 1024:
            raise MetasploitBootstrapError("The downloaded file is unexpectedly small to be a Metasploit MSI installer.")
        with temporary.open("rb") as handle:
            signature = handle.read(8)
        # MSI is an OLE compound file and starts with the following magic bytes.
        if signature != bytes.fromhex("D0CF11E0A1B11AE1"):
            raise MetasploitBootstrapError("The downloaded file is not recognized as a Windows MSI package.")
        temporary.replace(destination)
        return destination
    except MetasploitBootstrapError:
        temporary.unlink(missing_ok=True)
        raise
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        raise MetasploitBootstrapError(f"Unable to download the official Rapid7 installer: {exc}") from exc


def _verify_rapid7_authenticode(installer: Path) -> None:
    """Require a valid Windows Authenticode signature from a Rapid7 publisher."""
    escaped_path = str(installer.resolve()).replace("'", "''")
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
        "if ($s.Status -ne 'Valid') { exit 31 }; "
        "if ($null -eq $s.SignerCertificate -or $s.SignerCertificate.Subject -notmatch 'Rapid7') { exit 32 }; "
        "Write-Output $s.SignerCertificate.Subject"
    )
    try:
        checked = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MetasploitBootstrapError(f"Could not verify the installer Authenticode signature: {exc}") from exc
    if checked.returncode != 0 or "rapid7" not in (checked.stdout or "").lower():
        raise MetasploitBootstrapError(
            "The downloaded MSI did not pass the Rapid7 Authenticode publisher check. It will not be installed."
        )


def install_official_windows_metasploit(integration_dir: Path | None = None) -> str:
    """Download and launch the standard interactive Rapid7 Windows MSI installer."""
    if os.name != "nt":
        raise MetasploitBootstrapError(
            "Automatic MSI setup is Windows-only. On Linux/macOS, follow Rapid7's official installation guide."
        )
    package_dir = integration_dir or Path(__file__).resolve().parent
    installer_dir = package_dir / ".runtime" / "installers"
    installer_path = installer_dir / "metasploitframework-latest.msi"
    if not installer_path.is_file() or installer_path.stat().st_size < 10 * 1024 * 1024:
        print("[CERBERUS][METASPLOIT] Downloading the official Rapid7 Windows installer into the project...")
        _download_official_windows_installer(installer_path)
    print("[CERBERUS][METASPLOIT] Verifying the Rapid7 Authenticode signature...")
    _verify_rapid7_authenticode(installer_path)
    print("[CERBERUS][METASPLOIT] Launching the normal interactive MSI installer. No silent install is used.")
    print("[CERBERUS][METASPLOIT] Accept the license and complete setup in the installer window.")
    try:
        completed = subprocess.run(["msiexec.exe", "/i", str(installer_path)], check=False)
    except OSError as exc:
        raise MetasploitBootstrapError(f"Could not launch Windows Installer: {exc}") from exc
    if completed.returncode != 0:
        raise MetasploitBootstrapError(
            f"The interactive installer exited with code {completed.returncode}. "
            "No silent retry was attempted."
        )
    located = find_msfconsole()
    if not located:
        raise MetasploitBootstrapError(
            "Installer returned successfully, but msfconsole was not found. "
            "Reopen VS Code and run again, or pass --msfconsole-path with the installed msfconsole.bat path."
        )
    installer_path.unlink(missing_ok=True)
    return located
