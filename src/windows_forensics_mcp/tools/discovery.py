"""Discovery tools exposed by the MCP server."""

from pathlib import Path

from windows_forensics_mcp.artifacts import identify_artifact, identify_artifact_path
from windows_forensics_mcp.config import settings
from windows_forensics_mcp.schemas import DirectoryScanResult
from windows_forensics_mcp.utils.paths import ensure_directory, resolve_input_path
from windows_forensics_mcp.utils.validation import validate_limit


def scan_directory_path(
    raw_path: str,
    *,
    recursive: bool = True,
    max_entries: int | None = None,
    include_hashes: bool = False,
    include_unknown: bool = False,
) -> DirectoryScanResult:
    root = ensure_directory(resolve_input_path(raw_path))
    # Use ``is None`` (not falsiness) so an explicit max_entries=0 is rejected
    # by validate_limit instead of silently becoming the default.
    if max_entries is None:
        max_entries = settings.max_scan_entries
    max_entries = validate_limit(max_entries, parameter="max_entries")

    warnings: list[str] = []
    findings: list[dict[str, object]] = []
    scanned_entries = 0
    truncated = False

    # Track resolved directories already queued so symlink loops (a -> ../a)
    # cannot cause unbounded traversal.
    visited: set[str] = set()
    try:
        visited.add(str(root.resolve()))
    except OSError:
        visited.add(str(root))

    pending: list[Path] = [root]
    while pending:
        current = pending.pop()
        try:
            directory_entries = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except OSError as exc:
            warnings.append(f"Could not scan {current}: {type(exc).__name__}: {exc}")
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
                try:
                    resolved = str(entry.resolve())
                except OSError:
                    resolved = str(entry)
                if resolved in visited:
                    warnings.append(f"Skipped already-visited path (symlink loop?): {entry}")
                    continue
                visited.add(resolved)
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
