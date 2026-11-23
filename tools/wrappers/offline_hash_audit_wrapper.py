"""Async Cerberus adapter for local John/Hashcat dictionary audits."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.auth_security_audit.hash_audit_runner import OfflineHashAuditRunner


class OfflineHashAuditWrapper:
    def __init__(self, output_directory: str | Path | None = None) -> None:
        self.runner = OfflineHashAuditRunner(output_directory=output_directory)

    async def audit(
        self,
        engine: str,
        hash_file: str | Path,
        wordlist: str | Path,
        *,
        authorized: bool,
        max_runtime: int = 600,
        hash_mode: str | None = None,
        john_format: str | None = None,
    ) -> dict[str, Any]:
        result = await asyncio.to_thread(
            self.runner.run,
            engine,
            hash_file,
            wordlist,
            authorized=authorized,
            max_runtime=max_runtime,
            hash_mode=hash_mode,
            john_format=john_format,
        )
        return result.to_dict()
