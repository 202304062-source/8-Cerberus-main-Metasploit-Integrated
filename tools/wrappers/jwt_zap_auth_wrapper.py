"""Async Cerberus adapter for JWT + target-scoped passive ZAP authentication audit."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.integrations.auth_security_audit.jwt_zap_runner import JWTZAPAuthRunner


class JWTZAPAuthWrapper:
    def __init__(self, output_directory: str | Path | None = None, timeout_seconds: int = 1200) -> None:
        self.runner = JWTZAPAuthRunner(output_directory=output_directory, timeout_seconds=timeout_seconds)

    async def audit(
        self,
        target: str,
        token: str,
        *,
        authorized: bool,
        public_key_path: str | Path | None = None,
        minutes: int = 1,
    ) -> dict[str, Any]:
        result = await asyncio.to_thread(
            self.runner.run,
            target,
            token,
            authorized=authorized,
            public_key_path=public_key_path,
            minutes=minutes,
        )
        return result
