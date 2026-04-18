"""LNK and shell item parsing tools."""

import io
from pathlib import Path
from typing import TYPE_CHECKING

from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_directory, ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import filetime_to_iso

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _open_lnk_file(path: str):
    pylnk = require_module("pylnk", "liblnk-python")
    lnk_file = pylnk.file()
    lnk_file.open(path)
    return lnk_file


def _parse_shell_item_bytes(data: bytes) -> list[dict[str, object]]:
    if not data:
        return []

    pyfwsi = require_module("pyfwsi", "libfwsi-python")
    item_list = pyfwsi.item_list()
    item_list.copy_from_byte_stream(data)

    items = []
    for index in range(item_list.get_number_of_items()):
        item = item_list.get_item(index)
        parsed = {
            "index": index,
            "class": type(item).__name__,
            "class_type": getattr(item, "class_type", None),
            "data_size": getattr(item, "data_size", None),
        }

        for attribute_name in (
            "name",
            "identifier",
            "shell_folder_identifier",
            "file_size",
            "file_attribute_flags",
            "delegate_folder_identifier",
        ):
            if hasattr(item, attribute_name):
                parsed[attribute_name] = getattr(item, attribute_name)

        if hasattr(item, "get_modification_time_as_integer"):
            parsed["modification_time"] = filetime_to_iso(item.get_modification_time_as_integer())

        items.append(parsed)

    return items


def parse_lnk_bytes(data: bytes, source_path: str) -> dict[str, object]:
    pylnk = require_module("pylnk", "liblnk-python")
    lnk_file = pylnk.file()
    lnk_file.open_file_object(io.BytesIO(data))

    try:
        raw_shell_items = lnk_file.get_link_target_identifier_data()
        return {
            "source_path": source_path,
            "local_path": lnk_file.local_path,
            "network_path": lnk_file.network_path,
            "relative_path": lnk_file.relative_path,
            "working_directory": lnk_file.working_directory,
            "command_line_arguments": lnk_file.command_line_arguments,
            "description": lnk_file.description,
            "icon_location": lnk_file.icon_location,
            "volume_label": lnk_file.volume_label,
            "machine_identifier": lnk_file.machine_identifier,
            "drive_type": lnk_file.drive_type,
            "drive_serial_number": lnk_file.drive_serial_number,
            "file_size": lnk_file.file_size,
            "file_creation_time": filetime_to_iso(lnk_file.get_file_creation_time_as_integer()),
            "file_modification_time": filetime_to_iso(lnk_file.get_file_modification_time_as_integer()),
            "file_access_time": filetime_to_iso(lnk_file.get_file_access_time_as_integer()),
            "shell_items": _parse_shell_item_bytes(raw_shell_items),
        }
    finally:
        lnk_file.close()


def lnk_parse_path(file_path: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    return parse_lnk_bytes(path.read_bytes(), str(path))


def shellitems_parse_path(file_path: str) -> dict[str, object]:
    parsed = lnk_parse_path(file_path)
    return {
        "source_path": parsed["source_path"],
        "shell_item_count": len(parsed["shell_items"]),
        "shell_items": parsed["shell_items"],
    }


def lnk_directory_summary_path(directory_path: str, limit: int = 50) -> dict[str, object]:
    path = ensure_directory(resolve_input_path(directory_path))
    entries = []

    for file_path in sorted(path.glob("*.lnk"))[:limit]:
        try:
            parsed = lnk_parse_path(str(file_path))
            entries.append(
                {
                    "source_path": parsed["source_path"],
                    "local_path": parsed["local_path"],
                    "network_path": parsed["network_path"],
                    "command_line_arguments": parsed["command_line_arguments"],
                }
            )
        except OSError as exc:
            entries.append({"source_path": str(file_path), "error": str(exc)})

    return {
        "directory_path": str(path),
        "entry_count": len(entries),
        "entries": entries,
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def lnk_parse(file_path: str) -> dict[str, object]:
        """Parse a Windows shortcut (.lnk) file."""

        return lnk_parse_path(file_path)

    @mcp.tool()
    def shellitems_parse(file_path: str) -> dict[str, object]:
        """Parse shell items embedded in a Windows shortcut."""

        return shellitems_parse_path(file_path)

    @mcp.tool()
    def lnk_directory_summary(directory_path: str, limit: int = 50) -> dict[str, object]:
        """Summarize LNK files in a directory."""

        return lnk_directory_summary_path(directory_path, limit=limit)
