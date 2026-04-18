"""FastMCP server entrypoint."""

from __future__ import annotations

from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    FastMCP = None  # type: ignore[assignment]

from windows_forensics_mcp import __version__
from windows_forensics_mcp.config import settings
from windows_forensics_mcp.tools.discovery import register_tools
from windows_forensics_mcp.tools.evtx import register_tools as register_evtx_tools
from windows_forensics_mcp.tools.jumplist import register_tools as register_jumplist_tools
from windows_forensics_mcp.tools.lnk import register_tools as register_lnk_tools
from windows_forensics_mcp.tools.mft import register_tools as register_mft_tools
from windows_forensics_mcp.tools.prefetch import register_tools as register_prefetch_tools
from windows_forensics_mcp.tools.registry import register_tools as register_registry_tools
from windows_forensics_mcp.tools.srum import register_tools as register_srum_tools
from windows_forensics_mcp.tools.usn import register_tools as register_usn_tools


def create_server() -> Any:
    if FastMCP is None:
        raise RuntimeError(
            "The 'mcp' package is not installed. Install project dependencies before starting the server."
        )

    mcp = FastMCP(f"{settings.server_display_name} {__version__}")
    register_tools(mcp)
    register_evtx_tools(mcp)
    register_registry_tools(mcp)
    register_prefetch_tools(mcp)
    register_lnk_tools(mcp)
    register_jumplist_tools(mcp)
    register_srum_tools(mcp)
    register_mft_tools(mcp)
    register_usn_tools(mcp)
    return mcp


mcp = None


def main() -> None:
    """Run the MCP server with the default stdio transport."""

    global mcp
    if mcp is None:
        mcp = create_server()

    mcp.run()
