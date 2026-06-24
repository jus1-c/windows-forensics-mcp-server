"""USN journal parsing tools."""

from itertools import islice

from windows_forensics_mcp.errors import UnsupportedArtifactError
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import isoformat_datetime
from windows_forensics_mcp.utils.validation import validate_limit


def _open_usn(path: str):
    usn_module = require_module("dissect.ntfs.usnjrnl", "dissect.ntfs")
    file_handle = open(path, "rb")
    try:
        return usn_module.UsnJrnl(file_handle), file_handle
    except Exception as exc:
        file_handle.close()
        raise UnsupportedArtifactError(f"Failed to open USN journal: {exc}") from exc


def _coerce_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _usn_record_to_dict(record) -> dict[str, object]:
    header = getattr(record, "header", None)
    return {
        "usn": _coerce_int(record.Usn),
        "major_version": _coerce_int(getattr(header, "MajorVersion", None)),
        "minor_version": _coerce_int(getattr(header, "MinorVersion", None)),
        "file_reference_number": _coerce_int(record.FileReferenceNumber),
        "parent_file_reference_number": _coerce_int(record.ParentFileReferenceNumber),
        "reason": _coerce_int(record.Reason),
        "source_info": _coerce_int(record.SourceInfo),
        "security_id": _coerce_int(record.SecurityId),
        "file_attributes": _coerce_int(record.FileAttributes),
        "filename": record.filename,
        "timestamp": isoformat_datetime(record.timestamp),
        "full_path": record.full_path,
    }


def usn_parse_path(file_path: str, limit: int = 100) -> dict[str, object]:
    limit = validate_limit(limit)
    path = ensure_file(resolve_input_path(file_path))
    if path.stat().st_size == 0:
        return {
            "source_path": str(path),
            "record_count": 0,
            "records": [],
            "warnings": ["USN journal file is empty"],
        }

    usn, file_handle = _open_usn(str(path))
    records: list[dict[str, object]] = []
    warnings: list[str] = []
    skipped = 0
    try:
        for record in islice(usn.records(), limit):
            try:
                records.append(_usn_record_to_dict(record))
            except Exception as exc:  # noqa: BLE001 - degrade gracefully on damaged records
                skipped += 1
                if len(warnings) < 5:
                    warnings.append(f"Skipped malformed USN record: {type(exc).__name__}: {exc}")
    finally:
        file_handle.close()

    if skipped:
        warnings.append(f"Skipped {skipped} malformed USN record(s)")

    return {
        "source_path": str(path),
        "record_count": len(records),
        "records": records,
        "warnings": warnings,
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
