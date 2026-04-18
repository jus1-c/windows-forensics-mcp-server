"""Discovery tools exposed by the MCP server."""

from pathlib import Path
from typing import TYPE_CHECKING

from windows_forensics_mcp.artifacts import identify_artifact, identify_artifact_path
from windows_forensics_mcp.config import settings
from windows_forensics_mcp.schemas import DirectoryScanResult
from windows_forensics_mcp.utils.paths import ensure_directory, resolve_input_path

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def scan_directory_path(
    raw_path: str,
    *,
    recursive: bool = True,
    max_entries: int | None = None,
    include_hashes: bool = False,
    include_unknown: bool = False,
) -> DirectoryScanResult:
    root = ensure_directory(resolve_input_path(raw_path))
    max_entries = max_entries or settings.max_scan_entries

    warnings: list[str] = []
    findings: list[dict[str, object]] = []
    scanned_entries = 0
    truncated = False

    pending: list[Path] = [root]
    while pending:
        current = pending.pop()
        try:
            directory_entries = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except PermissionError:
            warnings.append(f"Permission denied while scanning: {current}")
            continue

        for entry in directory_entries:
            scanned_entries += 1
            descriptor = identify_artifact(entry, include_hash=include_hashes and entry.is_file())

            if include_unknown or descriptor.artifact_type != "unknown":
                findings.append(descriptor.to_dict())
                if len(findings) >= max_entries:
                    truncated = True
                    break

            if recursive and entry.is_dir():
                pending.append(entry)

        if truncated:
            break

    return DirectoryScanResult(
        root_path=str(root),
        recursive=recursive,
        include_hashes=include_hashes,
        include_unknown=include_unknown,
        scanned_entries=scanned_entries,
        returned_entries=len(findings),
        truncated=truncated,
        entries=findings,
        warnings=warnings,
    )


def register_tools(mcp) -> None:
    @mcp.tool()
    def artifact_identify(path: str, include_hash: bool = True) -> dict[str, object]:
        """Identify a Windows forensic artifact from a local path."""

        return identify_artifact_path(path, include_hash=include_hash).to_dict()

    @mcp.tool()
    def scan_directory(
        path: str,
        recursive: bool = True,
        max_entries: int = settings.max_scan_entries,
        include_hashes: bool = False,
        include_unknown: bool = False,
    ) -> dict[str, object]:
        """Scan a local directory and return recognizable forensic artifacts."""

        return scan_directory_path(
            path,
            recursive=recursive,
            max_entries=max_entries,
            include_hashes=include_hashes,
            include_unknown=include_unknown,
        ).to_dict()
