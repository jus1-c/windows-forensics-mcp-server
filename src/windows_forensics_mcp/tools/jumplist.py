"""Jump List parsing tools."""

from pathlib import Path
from typing import TYPE_CHECKING

from windows_forensics_mcp.tools.lnk import parse_lnk_bytes
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_directory, ensure_file, resolve_input_path

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


CUSTOM_DEST_SIG = b"\x4c\x00\x00\x00\x01\x14\x02\x00"


def _parse_automatic_destinations(path: Path) -> dict[str, object]:
    pyolecf = require_module("pyolecf", "libolecf-python")
    ole_file = pyolecf.file()
    ole_file.open(str(path))

    try:
        root = ole_file.get_root_item()
        entries = []
        for index in range(root.get_number_of_sub_items()):
            item = root.get_sub_item(index)
            if not item.name.isdigit():
                continue

            data = item.read_buffer(item.size)
            parsed = parse_lnk_bytes(data, f"{path}:{item.name}")
            parsed["stream_name"] = item.name
            entries.append(parsed)

        return {
            "source_path": str(path),
            "jumplist_type": "automatic",
            "entry_count": len(entries),
            "entries": entries,
            "streams": [root.get_sub_item(i).name for i in range(root.get_number_of_sub_items())],
        }
    finally:
        ole_file.close()


def _parse_custom_destinations(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    offsets = []
    current_offset = data.find(CUSTOM_DEST_SIG)
    while current_offset != -1:
        offsets.append(current_offset)
        current_offset = data.find(CUSTOM_DEST_SIG, current_offset + 1)

    entries = []
    for index, start_offset in enumerate(offsets):
        end_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        parsed = parse_lnk_bytes(data[start_offset:end_offset], f"{path}@{start_offset}")
        parsed["offset"] = start_offset
        entries.append(parsed)

    return {
        "source_path": str(path),
        "jumplist_type": "custom",
        "entry_count": len(entries),
        "entries": entries,
        "offsets": offsets,
    }


def jumplist_parse_path(file_path: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    lowered_name = path.name.lower()
    if lowered_name.endswith(".automaticdestinations-ms"):
        return _parse_automatic_destinations(path)
    if lowered_name.endswith(".customdestinations-ms"):
        return _parse_custom_destinations(path)
    raise ValueError(f"Unsupported Jump List file: {path}")


def jumplist_directory_summary_path(directory_path: str, limit: int = 50) -> dict[str, object]:
    path = ensure_directory(resolve_input_path(directory_path))
    entries = []
    candidates = sorted(path.glob("*.automaticDestinations-ms")) + sorted(path.glob("*.customDestinations-ms"))

    for file_path in candidates[:limit]:
        parsed = jumplist_parse_path(str(file_path))
        entries.append(
            {
                "source_path": parsed["source_path"],
                "jumplist_type": parsed["jumplist_type"],
                "entry_count": parsed["entry_count"],
            }
        )

    return {
        "directory_path": str(path),
        "entry_count": len(entries),
        "entries": entries,
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def jumplist_parse(file_path: str) -> dict[str, object]:
        """Parse an automatic or custom Jump List file."""

        return jumplist_parse_path(file_path)

    @mcp.tool()
    def jumplist_directory_summary(directory_path: str, limit: int = 50) -> dict[str, object]:
        """Summarize Jump List files in a directory."""

        return jumplist_directory_summary_path(directory_path, limit=limit)
