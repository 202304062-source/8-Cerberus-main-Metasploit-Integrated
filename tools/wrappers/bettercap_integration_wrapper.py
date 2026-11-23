"""Async Cerberus wrapper for the bounded Bettercap local-ARP integration."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.bettercap.bootstrap import ensure_bettercap
from tools.integrations.bettercap.runner import BettercapRunner


class BettercapIntegrationWrapper:
    """Expose local ARP-table observation to Cerberus services and agents.

    The caller must enforce the active Scope of Engagement / Rules of Engagement.
    This wrapper deliberately does not expose Bettercap's sniffing, spoofing,
    proxy, deauthentication, credential-harvesting, or active-probing modules.
    """

    def __init__(self, output_directory: str | Path | None = None) -> None:
        self.output_directory = output_directory

    async def inspect_target(
        self,
        target_url: str,
        *,
        authorized: bool,
        wait_seconds: int = 3,
        interface: str | None = None,
    ) -> dict[str, Any]:
        binary = await asyncio.to_thread(ensure_bettercap)
        runner = BettercapRunner(binary, self.output_directory)
        result = await asyncio.to_thread(
            runner.run,
            target_url,
            authorized=authorized,
            wait_seconds=wait_seconds,
            interface=interface,
        )
        return result.to_dict()
