"""Fail-closed secret loading for network-capable THOS services."""
from __future__ import annotations

import os


KNOWN_INSECURE_VALUES = {
    "thos_change_me",
    "thos_change_me_mcp_token",
    "thos_change_me_orchestrator_key",
    "thos_change_me_session_key",
    "thos_change_me_redis",
    "change_me",
}


def required_secret(name: str, *, minimum_length: int = 24) -> str:
    value = os.environ.get(name, "").strip()
    if (
        len(value) < minimum_length
        or value.casefold() in KNOWN_INSECURE_VALUES
        or "change_me" in value.casefold()
    ):
        raise RuntimeError(
            f"{name} must be explicitly configured with a unique secret "
            f"of at least {minimum_length} characters"
        )
    return value
