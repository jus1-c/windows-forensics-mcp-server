"""MFT parsing tools."""

from itertools import islice

from windows_forensics_mcp.errors import UnsupportedArtifactError
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import isoformat_datetime
from windows_forensics_mcp.utils.validation import validate_limit, validate_offset

# Default ceiling on how many segments mft_search_records will scan before
# stopping, so a non-matching pattern on a multi-million-record $MFT cannot
# run unbounded. dissect.ntfs iterates segments at roughly 1ms each, so this
# bound trades completeness for a predictable worst-case runtime.
DEFAULT_SEARCH_SCAN_LIMIT = 50_000


def _open_mft(path: str):
    ntfs_module = require_module("dissect.ntfs.mft", "dissect.ntfs")
    file_handle = open(path, "rb")
    try:
        return ntfs_module.Mft(file_handle), ntfs_module.ATTRIBUTE_TYPE_CODE, file_handle
    except Exception as exc:
        file_handle.close()
        raise UnsupportedArtifactError(f"Failed to open $MFT: {exc}") from exc


def _mft_record_to_dict(record, attribute_type_code) -> dict[str, object]:
    timestamps: dict[str, object] = {
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
    except Exception:  # noqa: BLE001 - size is best-effort; missing $DATA is common
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
    limit = validate_limit(limit)
    offset = validate_offset(offset)
    path = ensure_file(resolve_input_path(file_path))
    mft, attribute_type_code, file_handle = _open_mft(str(path))

    records: list[dict[str, object]] = []
    warnings: list[str] = []
    skipped = 0
    try:
        for record in islice(mft.segments(), offset, offset + limit):
            try:
                records.append(_mft_record_to_dict(record, attribute_type_code))
            except Exception as exc:  # noqa: BLE001 - degrade gracefully on damaged records
                skipped += 1
                if len(warnings) < 5:
                    warnings.append(f"Skipped malformed MFT record: {type(exc).__name__}: {exc}")
    finally:
        file_handle.close()

    if skipped:
        warnings.append(f"Skipped {skipped} malformed MFT record(s)")

    return {
        "source_path": str(path),
        "offset": offset,
        "limit": limit,
        "records": records,
        "warnings": warnings,
    }


def mft_search_records_path(
    file_path: str,
    name_contains: str,
    limit: int = 50,
    scan_limit: int = DEFAULT_SEARCH_SCAN_LIMIT,
) -> dict[str, object]:
    limit = validate_limit(limit)
    scan_limit = validate_limit(scan_limit, parameter="scan_limit")
    path = ensure_file(resolve_input_path(file_path))
    mft, attribute_type_code, file_handle = _open_mft(str(path))
    lowered_pattern = name_contains.lower()
    matches: list[dict[str, object]] = []
    warnings: list[str] = []
    skipped = 0
    scanned = 0
    scan_truncated = False

    try:
        for record in mft.segments():
            scanned += 1
            if scanned > scan_limit:
                scan_truncated = True
                break
            try:
                filename = record.filename or ""
                if lowered_pattern not in filename.lower():
                    continue
                matches.append(_mft_record_to_dict(record, attribute_type_code))
            except Exception as exc:  # noqa: BLE001 - degrade gracefully on damaged records
                skipped += 1
                if len(warnings) < 5:
                    warnings.append(f"Skipped malformed MFT record: {type(exc).__name__}: {exc}")
                continue
            if len(matches) >= limit:
                break

        if scan_truncated:
            warnings.append(
                f"Scan stopped after {scan_limit} records; results may be incomplete"
            )
        if skipped:
            warnings.append(f"Skipped {skipped} malformed MFT record(s)")

        return {
            "source_path": str(path),
            "pattern": name_contains,
            "scanned": scanned,
            "match_count": len(matches),
            "matches": matches,
            "warnings": warnings,
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
        "warnings": parsed.get("warnings", []),
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def mft_parse(file_path: str, limit: int = 100, offset: int = 0) -> dict[str, object]:
        """Parse an exported $MFT file."""

        return mft_parse_path(file_path, limit=limit, offset=offset)

    @mcp.tool()
    def mft_search_records(
        file_path: str,
        name_contains: str,
        limit: int = 50,
        scan_limit: int = DEFAULT_SEARCH_SCAN_LIMIT,
    ) -> dict[str, object]:
        """Search records in an exported $MFT file.

        scan_limit bounds how many MFT records are examined before stopping so
        a rare/absent pattern cannot trigger an unbounded full-table scan.
        """

        return mft_search_records_path(
            file_path, name_contains=name_contains, limit=limit, scan_limit=scan_limit
        )

    @mcp.tool()
    def mft_timeline(file_path: str, limit: int = 100) -> dict[str, object]:
        """Build a timeline from an exported $MFT file."""

        return mft_timeline_path(file_path, limit=limit)
