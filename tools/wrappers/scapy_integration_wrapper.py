"""Async Cerberus wrapper for the bounded Scapy integration.

This is a new wrapper. The existing Nmap, SQLMap, and other wrappers remain
untouched. Callers must derive ``authorized=True`` from the active engagement's
approved Scope of Engagement / Rules of Engagement.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.scapy.runner import ScapyRunner


class ScapyIntegrationWrapper:
    """Expose the bounded URL-based Scapy check to Cerberus services and agents."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        *,
        http_timeout: float = 5.0,
        packet_timeout: float = 1.5,
    ) -> None:
        self.runner = ScapyRunner(
            output_directory=output_directory,
            http_timeout=http_timeout,
            packet_timeout=packet_timeout,
        )

    async def scan(
        self,
        target_url: str,
        *,
        authorized: bool,
        ports: tuple[int, ...] | None = None,
    ) -> dict[str, Any]:
        """Run the synchronous network check in a worker thread and return JSON data."""
        result = await asyncio.to_thread(
            self.runner.run,
            target_url,
            authorized=authorized,
            ports=ports,
        )
        return result.to_dict()
