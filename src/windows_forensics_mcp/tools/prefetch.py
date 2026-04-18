"""Windows Prefetch parsing tools."""

from pathlib import Path
from typing import TYPE_CHECKING

from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_directory, ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import filetime_to_iso

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _open_prefetch_file(path: str):
    pyscca = require_module("pyscca", "libscca-python")
    prefetch_file = pyscca.file()
    prefetch_file.open(path)
    return prefetch_file


def _prefetch_last_run_times(prefetch_file) -> list[str]:
    run_times: list[str] = []
    for index in range(8):
        try:
            timestamp = prefetch_file.get_last_run_time_as_integer(index)
        except OSError:
            break

        iso_timestamp = filetime_to_iso(timestamp)
        if iso_timestamp:
            run_times.append(iso_timestamp)

    return run_times


def _prefetch_volumes(prefetch_file) -> list[dict[str, object]]:
    volumes = []
    for index in range(prefetch_file.number_of_volumes):
        volume = prefetch_file.get_volume_information(index)
        volumes.append(
            {
                "index": index,
                "device_path": volume.device_path,
                "serial_number": volume.serial_number,
                "creation_time": filetime_to_iso(volume.get_creation_time_as_integer()),
            }
        )
    return volumes


def prefetch_parse_path(file_path: str, filename_limit: int = 200) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    prefetch_file = _open_prefetch_file(str(path))

    try:
        filenames = []
        for index in range(min(prefetch_file.number_of_filenames, filename_limit)):
            filenames.append(prefetch_file.get_filename(index))

        file_metrics = []
        for index in range(min(prefetch_file.number_of_file_metrics_entries, 50)):
            metric = prefetch_file.get_file_metrics_entry(index)
            file_metrics.append(
                {
                    "index": index,
                    "filename": metric.filename,
                    "file_reference": metric.file_reference,
                }
            )

        return {
            "source_path": str(path),
            "format_version": prefetch_file.format_version,
            "executable_filename": prefetch_file.executable_filename,
            "prefetch_hash": prefetch_file.prefetch_hash,
            "run_count": prefetch_file.run_count,
            "last_run_times": _prefetch_last_run_times(prefetch_file),
            "volume_information": _prefetch_volumes(prefetch_file),
            "filenames": filenames,
            "file_metrics": file_metrics,
        }
    finally:
        prefetch_file.close()


def prefetch_directory_summary_path(directory_path: str, limit: int = 50) -> dict[str, object]:
    path = ensure_directory(resolve_input_path(directory_path))
    entries = []

    for file_path in sorted(path.glob("*.pf"))[:limit]:
        try:
            parsed = prefetch_parse_path(str(file_path), filename_limit=20)
            entries.append(
                {
                    "source_path": parsed["source_path"],
                    "executable_filename": parsed["executable_filename"],
                    "run_count": parsed["run_count"],
                    "last_run_times": parsed["last_run_times"],
                }
            )
        except OSError as exc:
            entries.append({"source_path": str(file_path), "error": str(exc)})

    return {
        "directory_path": str(path),
        "entry_count": len(entries),
        "entries": entries,
    }


def prefetch_timeline_path(path_or_directory: str, limit: int = 100) -> dict[str, object]:
    path = resolve_input_path(path_or_directory)

    files: list[Path]
    if path.is_dir():
        files = sorted(path.glob("*.pf"))
    else:
        files = [ensure_file(path)]

    timeline = []
    for file_path in files:
        parsed = prefetch_parse_path(str(file_path), filename_limit=10)
        for timestamp in parsed["last_run_times"]:
            timeline.append(
                {
                    "timestamp": timestamp,
                    "artifact_type": "prefetch",
                    "source_path": parsed["source_path"],
                    "executable_filename": parsed["executable_filename"],
                    "run_count": parsed["run_count"],
                }
            )
            if len(timeline) >= limit:
                break
        if len(timeline) >= limit:
            break

    timeline.sort(key=lambda item: item["timestamp"] or "")
    return {
        "source_path": str(path),
        "timeline": timeline,
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def prefetch_parse(file_path: str, filename_limit: int = 200) -> dict[str, object]:
        """Parse a Windows Prefetch file."""

        return prefetch_parse_path(file_path, filename_limit=filename_limit)

    @mcp.tool()
    def prefetch_directory_summary(directory_path: str, limit: int = 50) -> dict[str, object]:
        """Summarize Prefetch files within a directory."""

        return prefetch_directory_summary_path(directory_path, limit=limit)

    @mcp.tool()
    def prefetch_timeline(path_or_directory: str, limit: int = 100) -> dict[str, object]:
        """Build a timeline from one or more Prefetch files."""

        return prefetch_timeline_path(path_or_directory, limit=limit)
