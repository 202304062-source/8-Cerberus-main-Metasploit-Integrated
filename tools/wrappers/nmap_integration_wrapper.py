"""Async Cerberus wrapper for the controlled Nmap integration.

This is intentionally a new file. The pre-existing tools/wrappers/nmap_wrapper.py
is preserved unchanged for backwards compatibility with existing project code.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.nmap.runner import NmapRunner


class NmapIntegrationWrapper:
    """Expose the allow-listed Nmap profiles to Cerberus agents/services."""

    def __init__(self, output_directory: str | Path | None = None, nmap_path: str | None = None):
        self.runner = NmapRunner(output_directory=output_directory, nmap_path=nmap_path)

    async def scan(
        self,
        target: str,
        *,
        authorized: bool,
        profile: str = "standard",
    ) -> dict[str, Any]:
        """Run Nmap off the event loop and return a JSON-serializable result."""
        result = await asyncio.to_thread(
            self.runner.run,
            target,
            authorized=authorized,
            profile=profile,
        )
        return result.to_dict()
