"""MFT parsing tools."""

from itertools import islice
from typing import TYPE_CHECKING

from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import isoformat_datetime

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _open_mft(path: str):
    ntfs_module = require_module("dissect.ntfs.mft", "dissect.ntfs")
    file_handle = open(path, "rb")
    return ntfs_module.Mft(file_handle), ntfs_module.ATTRIBUTE_TYPE_CODE, file_handle


def _mft_record_to_dict(record, attribute_type_code) -> dict[str, object]:
    timestamps = {
        "creation_time": None,
        "modification_time": None,
        "access_time": None,
        "entry_change_time": None,
    }

    standard_information = record.attributes[attribute_type_code.STANDARD_INFORMATION]
    if standard_information:
        attribute = standard_information[0]
        timestamps = {
            "creation_time": isoformat_datetime(attribute.creation_time),
            "modification_time": isoformat_datetime(attribute.last_modification_time),
            "access_time": isoformat_datetime(attribute.last_access_time),
            "entry_change_time": isoformat_datetime(attribute.last_change_time),
        }

    size = None
    try:
        size = record.size()
    except Exception:
        size = None

    return {
        "segment": record.segment,
        "filename": record.filename,
        "filenames": record.filenames(),
        "is_directory": record.is_dir(),
        "is_file": record.is_file(),
        "size": size,
        **timestamps,
    }


def mft_parse_path(file_path: str, limit: int = 100, offset: int = 0) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    mft, attribute_type_code, file_handle = _open_mft(str(path))

    try:
        records = [_mft_record_to_dict(record, attribute_type_code) for record in islice(mft.segments(), offset, offset + limit)]
        return {
            "source_path": str(path),
            "offset": offset,
            "limit": limit,
            "records": records,
        }
    finally:
        file_handle.close()


def mft_search_records_path(file_path: str, name_contains: str, limit: int = 50) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    mft, attribute_type_code, file_handle = _open_mft(str(path))
    lowered_pattern = name_contains.lower()
    matches = []

    try:
        for record in mft.segments():
            filename = record.filename or ""
            if lowered_pattern not in filename.lower():
                continue
            matches.append(_mft_record_to_dict(record, attribute_type_code))
            if len(matches) >= limit:
                break

        return {
            "source_path": str(path),
            "pattern": name_contains,
            "match_count": len(matches),
            "matches": matches,
        }
    finally:
        file_handle.close()


def mft_timeline_path(file_path: str, limit: int = 100) -> dict[str, object]:
    parsed = mft_parse_path(file_path, limit=limit, offset=0)
    timeline = []
    for record in parsed["records"]:
        for timestamp_key in ("creation_time", "modification_time", "entry_change_time", "access_time"):
            timestamp = record.get(timestamp_key)
            if not timestamp:
                continue
            timeline.append(
                {
                    "timestamp": timestamp,
                    "artifact_type": "mft",
                    "segment": record["segment"],
                    "filename": record["filename"],
                    "event_type": timestamp_key,
                }
            )

    timeline.sort(key=lambda item: item["timestamp"])
    return {
        "source_path": parsed["source_path"],
        "timeline": timeline,
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def mft_parse(file_path: str, limit: int = 100, offset: int = 0) -> dict[str, object]:
        """Parse an exported $MFT file."""

        return mft_parse_path(file_path, limit=limit, offset=offset)

    @mcp.tool()
    def mft_search_records(file_path: str, name_contains: str, limit: int = 50) -> dict[str, object]:
        """Search records in an exported $MFT file."""

        return mft_search_records_path(file_path, name_contains=name_contains, limit=limit)

    @mcp.tool()
    def mft_timeline(file_path: str, limit: int = 100) -> dict[str, object]:
        """Build a timeline from an exported $MFT file."""

        return mft_timeline_path(file_path, limit=limit)
