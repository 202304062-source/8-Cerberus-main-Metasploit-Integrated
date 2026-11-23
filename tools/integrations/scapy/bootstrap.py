"""Install the Scapy Python dependency into the active Python environment."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


class ScapyBootstrapError(RuntimeError):
    """Raised when the Scapy dependency cannot be made available."""


def ensure_scapy(*, allow_install: bool = True) -> None:
    """Ensure Scapy is importable, installing this integration's requirements if needed.

    The launcher uses ``sys.executable`` so the dependency is installed into the same
    interpreter that is running the Cerberus tool (including an activated venv).
    """
    importlib.invalidate_caches()
    if importlib.util.find_spec("scapy") is not None:
        return
    if not allow_install:
        raise ScapyBootstrapError(
            "Scapy is not installed in the active Python environment. "
            "Run the launcher without --no-install to install it automatically."
        )

    requirements = Path(__file__).resolve().parent / "requirements.txt"
    if not requirements.is_file():
        raise ScapyBootstrapError(f"Scapy requirements file is missing: {requirements}")

    print("[CERBERUS][SCAPY] Scapy is not installed. Installing project dependency...", flush=True)
    command = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
    try:
        completed = subprocess.run(command, check=False)
    except OSError as exc:
        raise ScapyBootstrapError(f"Could not start pip: {exc}") from exc
    if completed.returncode != 0:
        raise ScapyBootstrapError(
            "Automatic Scapy installation failed. Check internet access and pip, then retry "
            f"with: {sys.executable} -m pip install -r {requirements}"
        )

    importlib.invalidate_caches()
    if importlib.util.find_spec("scapy") is None:
        raise ScapyBootstrapError(
            "pip completed, but Scapy is still not importable from the active Python interpreter."
        )
    print("[CERBERUS][SCAPY] Scapy dependency is ready.", flush=True)
