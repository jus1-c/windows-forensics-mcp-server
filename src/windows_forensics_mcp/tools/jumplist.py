"""Jump List parsing tools."""

import struct
from pathlib import Path

from windows_forensics_mcp.errors import UnsupportedArtifactError
from windows_forensics_mcp.tools.lnk import parse_lnk_bytes
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_directory, ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import filetime_to_iso
from windows_forensics_mcp.utils.validation import validate_limit

CUSTOM_DEST_SIG = b"\x4c\x00\x00\x00\x01\x14\x02\x00"

# DestList entry field offsets, verified against real Windows 10 (v4) Jump
# Lists. The fixed-size prefix differs between layout versions: in v1/v3 the
# UTF-16 path-size WORD lives at +0x70, while v4 inserts an extra 16-byte
# block pushing it to +0x80. Common fields (hostname, entry number, MRU
# access time) share the same offsets across v3/v4.
_DESTLIST_HOSTNAME_OFFSET = 0x48
_DESTLIST_ENTRY_NUMBER_OFFSET = 0x58
_DESTLIST_ACCESS_TIME_OFFSET = 0x64
_DESTLIST_PATH_SIZE_OFFSET = {1: 0x70, 3: 0x70, 4: 0x80}
_DESTLIST_TRAILER_SIZE = 4  # v3/v4 append a 4-byte trailer after the path


def _parse_destlist_stream(data: bytes) -> dict[str, object]:
    """Parse the DestList stream of an automatic Jump List.

    DestList carries the MRU ordering, per-entry access timestamps, the
    originating hostname, and the stream-number mapping that ties each entry
    back to its embedded LNK stream. Returns header metadata plus a list of
    decoded entries (best-effort; malformed tails are reported in warnings).
    """
    result: dict[str, object] = {
        "version": None,
        "total_entries": None,
        "pinned_entries": None,
        "entries": [],
        "warnings": [],
    }
    if len(data) < 32:
        if data:
            result["warnings"].append("DestList stream too small to contain a header")
        return result

    version, total_entries, pinned_entries = struct.unpack("<III", data[:12])
    result["version"] = version
    result["total_entries"] = total_entries
    result["pinned_entries"] = pinned_entries

    path_size_offset = _DESTLIST_PATH_SIZE_OFFSET.get(version)
    if path_size_offset is None:
        result["warnings"].append(f"Unsupported DestList version {version}; entries not decoded")
        return result

    entries: list[dict[str, object]] = []
    warnings: list[str] = result["warnings"]
    offset = 32
    index = 0
    while index < total_entries:
        base = offset
        if base + path_size_offset + 2 > len(data):
            warnings.append("DestList truncated before all entries were read")
            break

        hostname = (
            data[base + _DESTLIST_HOSTNAME_OFFSET : base + _DESTLIST_HOSTNAME_OFFSET + 16]
            .split(b"\x00")[0]
            .decode("latin1", errors="replace")
        )
        entry_number = struct.unpack(
            "<I", data[base + _DESTLIST_ENTRY_NUMBER_OFFSET : base + _DESTLIST_ENTRY_NUMBER_OFFSET + 4]
        )[0]
        access_filetime = struct.unpack(
            "<Q", data[base + _DESTLIST_ACCESS_TIME_OFFSET : base + _DESTLIST_ACCESS_TIME_OFFSET + 8]
        )[0]
        path_size = struct.unpack(
            "<H", data[base + path_size_offset : base + path_size_offset + 2]
        )[0]

        path_start = base + path_size_offset + 2
        path_end = path_start + path_size * 2
        if path_end > len(data):
            warnings.append(f"DestList entry {index} path extends past stream end")
            break

        path = data[path_start:path_end].decode("utf-16-le", errors="replace")
        entries.append(
            {
                "mru_position": index,
                "entry_number": entry_number,
                "stream_name": str(entry_number),
                "hostname": hostname,
                "last_access_time": filetime_to_iso(access_filetime),
                "is_pinned": index < pinned_entries,
                "path": path,
            }
        )

        offset = path_end + _DESTLIST_TRAILER_SIZE
        index += 1

    result["entries"] = entries
    return result


def _parse_automatic_destinations(path: Path) -> dict[str, object]:
    pyolecf = require_module("pyolecf", "libolecf-python")
    ole_file = pyolecf.file()
    ole_file.open(str(path))

    try:
        root = ole_file.get_root_item()
        stream_names: list[str] = []
        entries = []
        warnings: list[str] = []
        destlist: dict[str, object] | None = None
        for index in range(root.get_number_of_sub_items()):
            item = root.get_sub_item(index)
            stream_names.append(item.name)

            if item.name == "DestList":
                try:
                    destlist = _parse_destlist_stream(item.read_buffer(item.size))
                    warnings.extend(destlist.pop("warnings", []))
                except Exception as exc:  # noqa: BLE001 - DestList is best-effort metadata
                    warnings.append(f"Failed to parse DestList: {type(exc).__name__}: {exc}")
                continue

            if not item.name.isdigit():
                continue

            try:
                data = item.read_buffer(item.size)
                parsed = parse_lnk_bytes(data, f"{path}:{item.name}")
                parsed["stream_name"] = item.name
                entries.append(parsed)
            except Exception as exc:  # noqa: BLE001 - skip malformed embedded LNK streams
                warnings.append(f"Skipped stream {item.name}: {type(exc).__name__}: {exc}")

        # Attach DestList MRU metadata (access time, pin status, order) to each
        # parsed LNK entry by matching on stream name.
        if destlist is not None:
            by_stream = {meta["stream_name"]: meta for meta in destlist.get("entries", [])}
            for entry in entries:
                meta = by_stream.get(entry.get("stream_name"))
                if meta is not None:
                    entry["destlist"] = meta

        return {
            "source_path": str(path),
            "jumplist_type": "automatic",
            "entry_count": len(entries),
            "entries": entries,
            "streams": stream_names,
            "destlist": destlist,
            "warnings": warnings,
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
    warnings: list[str] = []
    for index, start_offset in enumerate(offsets):
        end_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        try:
            parsed = parse_lnk_bytes(data[start_offset:end_offset], f"{path}@{start_offset}")
            parsed["offset"] = start_offset
            entries.append(parsed)
        except Exception as exc:  # noqa: BLE001 - skip malformed embedded LNK segments
            warnings.append(f"Skipped segment at offset {start_offset}: {type(exc).__name__}: {exc}")

    return {
        "source_path": str(path),
        "jumplist_type": "custom",
        "entry_count": len(entries),
        "entries": entries,
        "offsets": offsets,
        "warnings": warnings,
    }


def jumplist_parse_path(file_path: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    lowered_name = path.name.lower()
    if lowered_name.endswith(".automaticdestinations-ms"):
        return _parse_automatic_destinations(path)
    if lowered_name.endswith(".customdestinations-ms"):
        return _parse_custom_destinations(path)
    raise UnsupportedArtifactError(f"Unsupported Jump List file: {path}")


def _iter_jumplist_files(path: Path):
    # Match case-insensitively so directories on case-sensitive filesystems
    # (Linux/WSL) are handled the same way jumplist_parse handles them.
    for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
        if not child.is_file():
            continue
        lowered = child.name.lower()
        if lowered.endswith(".automaticdestinations-ms") or lowered.endswith(".customdestinations-ms"):
            yield child


def jumplist_directory_summary_path(directory_path: str, limit: int = 50) -> dict[str, object]:
    limit = validate_limit(limit)
    path = ensure_directory(resolve_input_path(directory_path))
    entries = []
    warnings: list[str] = []

    candidates = list(_iter_jumplist_files(path))
    for file_path in candidates[:limit]:
        try:
            parsed = jumplist_parse_path(str(file_path))
            entries.append(
                {
                    "source_path": parsed["source_path"],
                    "jumplist_type": parsed["jumplist_type"],
                    "entry_count": parsed["entry_count"],
                }
            )
        except Exception as exc:  # noqa: BLE001 - degrade gracefully per file
            warnings.append(f"Could not parse {file_path}: {type(exc).__name__}: {exc}")

    return {
        "directory_path": str(path),
        "entry_count": len(entries),
        "entries": entries,
        "warnings": warnings,
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
