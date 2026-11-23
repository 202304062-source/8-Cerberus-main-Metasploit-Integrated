"""Async Cerberus wrapper for the fixed Metasploit HTTP version check.

This wrapper does not expose arbitrary Metasploit modules or commands. The
calling service/agent must enforce the active Scope of Engagement / ROE before
passing authorized=True; the boolean itself is not proof of permission.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.metasploit.bootstrap import find_msfconsole
from tools.integrations.metasploit.runner import MetasploitExecutionError, MetasploitRunner


class MetasploitIntegrationWrapper:
    """Expose the fixed HTTP version scanner to Cerberus services and agents."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        *,
        msfconsole_path: str | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        self.output_directory = output_directory
        self.msfconsole_path = msfconsole_path
        self.timeout_seconds = timeout_seconds

    async def inspect_http_service(
        self,
        target_url: str,
        *,
        authorized: bool,
    ) -> dict[str, Any]:
        """Run the bounded HTTP version check in a worker thread."""
        console = find_msfconsole(self.msfconsole_path)
        if not console:
            raise MetasploitExecutionError(
                "msfconsole is not installed or was not found. Install Metasploit using the official Rapid7 installer."
            )
        runner = MetasploitRunner(
            console,
            output_directory=self.output_directory,
            timeout_seconds=self.timeout_seconds,
        )
        result = await asyncio.to_thread(runner.run, target_url, authorized=authorized)
        return result.to_dict()
