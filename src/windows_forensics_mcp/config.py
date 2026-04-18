"""Runtime settings for the MCP server."""

from __future__ import annotations

from dataclasses import dataclass
import os


def _get_int_env(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer") from exc

    if value <= 0:
        raise ValueError(f"Environment variable {name} must be greater than zero")

    return value


@dataclass(frozen=True, slots=True)
class Settings:
    server_name: str = "windows-forensics-mcp"
    server_display_name: str = "Windows Forensics MCP"
    max_scan_entries: int = _get_int_env("WFMCP_MAX_SCAN_ENTRIES", 200)
    hash_chunk_size: int = _get_int_env("WFMCP_HASH_CHUNK_SIZE", 1024 * 1024)


settings = Settings()
