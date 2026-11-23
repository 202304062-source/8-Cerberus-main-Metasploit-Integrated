"""Local-only JWT structure and time-claim inspection (no signature verification)."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any


class JWTFormatError(ValueError):
    """Raised when a value is not a structurally valid compact JWT."""


def _decode_segment(segment: str, label: str) -> dict[str, Any]:
    if not segment or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=" for ch in segment):
        raise JWTFormatError(f"JWT {label} segment is not valid base64url text.")
    padded = segment + ("=" * ((4 - len(segment) % 4) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise JWTFormatError(f"JWT {label} segment is not valid JSON/base64url.") from exc
    if not isinstance(value, dict):
        raise JWTFormatError(f"JWT {label} must decode to a JSON object.")
    return value


def inspect_jwt(token: str, *, now_epoch: int | None = None) -> dict[str, Any]:
    """Inspect JWT metadata without printing or returning claim values or signature.

    This is structural inspection only. It does not validate the signature, issuer,
    audience, revocation state, or server-side session state.
    """
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise JWTFormatError("JWT must be non-empty text no longer than 16 KiB.")
    if any(ch.isspace() or ord(ch) < 32 for ch in token):
        raise JWTFormatError("JWT must not contain whitespace or control characters.")
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTFormatError("Expected a three-part compact JWT (header.payload.signature).")
    header = _decode_segment(parts[0], "header")
    payload = _decode_segment(parts[1], "payload")
    algorithm = header.get("alg")
    now = int(now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp())
    claims = {key: payload.get(key) for key in ("exp", "iat", "nbf") if key in payload}
    warnings: list[str] = []
    if algorithm == "none":
        warnings.append("The token declares alg=none; reject unless an explicitly designed test fixture requires it.")
    if "exp" not in payload:
        warnings.append("No exp claim is present; the token has no self-declared expiry.")
    if "iat" not in payload:
        warnings.append("No iat claim is present.")
    if "iss" not in payload:
        warnings.append("No iss claim is present; verify issuer constraints are enforced by the application.")
    if "aud" not in payload:
        warnings.append("No aud claim is present; verify audience constraints are enforced by the application.")

    def numeric_claim(name: str) -> int | None:
        value = claims.get(name)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            warnings.append(f"The {name} claim is not numeric.")
            return None
        return int(value)

    exp = numeric_claim("exp")
    iat = numeric_claim("iat")
    nbf = numeric_claim("nbf")
    expired = exp is not None and exp <= now
    not_yet_valid = nbf is not None and nbf > now
    if expired:
        warnings.append("The token is expired according to its exp claim.")
    if not_yet_valid:
        warnings.append("The token is not yet valid according to its nbf claim.")
    exp_iso = datetime.fromtimestamp(exp, timezone.utc).isoformat() if exp is not None else None
    return {
        "format": "JWT compact serialization",
        "algorithm": algorithm if isinstance(algorithm, str) else None,
        "type": header.get("typ") if isinstance(header.get("typ"), str) else None,
        "key_id_present": isinstance(header.get("kid"), str) and bool(header.get("kid")),
        "signature_segment_present": bool(parts[2]),
        "claim_names": sorted(payload.keys()),
        "exp_utc": exp_iso,
        "expires_in_seconds": (exp - now) if exp is not None else None,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "signature_verification": "not_performed_by_structural_inspector",
        "warnings": warnings,
    }
