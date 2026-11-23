"""Cerberus wrapper for OWASP ZAP's passive baseline scan."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.owasp_zap.runner import (
    ZAPBaselineRunner,
    ZAPExecutionError,
)


class OWASPZAPWrapper:
    """Async adapter that exposes the ZAP baseline runner to Cerberus agents."""

    def __init__(
        self,
        output_directory: str | Path | None = None,
        timeout_seconds: int = 20 * 60,
    ) -> None:
        self.runner = ZAPBaselineRunner(
            output_directory=output_directory,
            timeout_seconds=timeout_seconds,
        )

    async def baseline_scan(
        self,
        target: str,
        *,
        authorized: bool = False,
        minutes: int = 1,
    ) -> dict[str, Any]:
        """Run a passive ZAP scan without blocking the async event loop."""
        if authorized is not True:
            return {
                "target": target,
                "status": "rejected",
                "error": "Explicit authorization is required.",
            }

        try:
            result = await asyncio.to_thread(
                self.runner.run,
                target,
                authorized=True,
                minutes=minutes,
            )
            return result.to_dict()
        except (ZAPExecutionError, ValueError) as exc:
            return {
                "target": target,
                "status": "failed",
                "error": str(exc),
            }
