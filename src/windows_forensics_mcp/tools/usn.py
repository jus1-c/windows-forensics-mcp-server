"""USN journal parsing tools."""

from itertools import islice
from typing import TYPE_CHECKING

from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import isoformat_datetime

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _open_usn(path: str):
    usn_module = require_module("dissect.ntfs.usnjrnl", "dissect.ntfs")
    return usn_module.UsnJrnl(open(path, "rb"))


def _usn_record_to_dict(record) -> dict[str, object]:
    return {
        "usn": int(record.Usn),
        "major_version": int(record.header.MajorVersion),
        "minor_version": int(record.header.MinorVersion),
        "file_reference_number": int(record.FileReferenceNumber),
        "parent_file_reference_number": int(record.ParentFileReferenceNumber),
        "reason": int(record.Reason),
        "source_info": int(record.SourceInfo),
        "security_id": int(record.SecurityId),
        "file_attributes": int(record.FileAttributes),
        "filename": record.filename,
        "timestamp": isoformat_datetime(record.timestamp),
        "full_path": record.full_path,
    }


def usn_parse_path(file_path: str, limit: int = 100) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    if path.stat().st_size == 0:
        return {
            "source_path": str(path),
            "record_count": 0,
            "records": [],
            "warnings": ["USN journal file is empty"],
        }

    usn = _open_usn(str(path))
    records = [_usn_record_to_dict(record) for record in islice(usn.records(), limit)]
    return {
        "source_path": str(path),
        "record_count": len(records),
        "records": records,
        "warnings": [],
    }


def usn_timeline_path(file_path: str, limit: int = 100) -> dict[str, object]:
    parsed = usn_parse_path(file_path, limit=limit)
    timeline = [
        {
            "timestamp": record["timestamp"],
            "artifact_type": "usn_journal",
            "usn": record["usn"],
            "filename": record["filename"],
            "reason": record["reason"],
            "full_path": record["full_path"],
        }
        for record in parsed["records"]
    ]
    timeline.sort(key=lambda item: item["timestamp"] or "")
    return {
        "source_path": parsed["source_path"],
        "timeline": timeline,
        "warnings": parsed["warnings"],
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def usn_parse(file_path: str, limit: int = 100) -> dict[str, object]:
        """Parse an exported USN journal stream file."""

        return usn_parse_path(file_path, limit=limit)

    @mcp.tool()
    def usn_timeline(file_path: str, limit: int = 100) -> dict[str, object]:
        """Build a timeline from an exported USN journal stream."""

        return usn_timeline_path(file_path, limit=limit)
