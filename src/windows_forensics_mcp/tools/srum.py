"""SRUM parsing tools."""

from windows_forensics_mcp.errors import UnsupportedArtifactError
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import ole_automation_bits_to_iso
from windows_forensics_mcp.utils.validation import validate_count, validate_limit

SRUM_APP_USAGE_TABLE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_NETWORK_USAGE_TABLE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
SRUM_ID_MAP_TABLE = "SruDbIdMapTable"


def _open_srum_database(path: str):
    esedb_module = require_module("dissect.esedb.esedb", "dissect.esedb")
    file_handle = open(path, "rb")
    try:
        ese_db = esedb_module.EseDB(file_handle)
    except Exception:
        file_handle.close()
        raise
    return ese_db, file_handle


def _decode_sid(blob: bytes) -> str | None:
    # A valid binary SID has revision 1, at most 15 sub-authorities, and a
    # total length of exactly 8 + 4 * sub_authority_count. Requiring an exact
    # match (and revision == 1) prevents UTF-16 string blobs such as
    # "C:\\Program Files\\..." from being misread as bogus SIDs like "S-67-...".
    if len(blob) < 8:
        return None

    revision = blob[0]
    sub_authority_count = blob[1]
    if revision != 1 or sub_authority_count > 15:
        return None
    if len(blob) != 8 + sub_authority_count * 4:
        return None

    authority = int.from_bytes(blob[2:8], "big")
    sub_authorities = [
        str(int.from_bytes(blob[8 + index * 4 : 12 + index * 4], "little"))
        for index in range(sub_authority_count)
    ]
    return f"S-{revision}-{authority}" + ("-" + "-".join(sub_authorities) if sub_authorities else "")


def _decode_srum_blob(blob: bytes | None) -> str | None:
    if not blob:
        return None

    decoded_sid = _decode_sid(blob)
    if decoded_sid:
        return decoded_sid

    try:
        decoded = blob.decode("utf-16-le", errors="ignore").rstrip("\x00")
        if decoded:
            return decoded
    except UnicodeDecodeError:
        pass

    return blob.hex()


def _decode_srum_blob(blob: bytes | None) -> str | None:
    if not blob:
        return None

    decoded_sid = _decode_sid(blob)
    if decoded_sid:
        return decoded_sid

    try:
        decoded = blob.decode("utf-16-le", errors="ignore").rstrip("\x00")
        if decoded:
            return decoded
    except UnicodeDecodeError:
        pass

    return blob.hex()


def _decode_id_blob(blob: bytes | None, id_type: object) -> str | None:
    """Decode a SruDbIdMapTable IdBlob.

    SRUM stores the blob as a binary SID when IdType == 3 and as a UTF-16
    string otherwise. When IdType is present we honor it; otherwise we fall
    back to the conservative auto-detection in _decode_srum_blob.
    """
    if not blob:
        return None

    if id_type == 3:
        return _decode_sid(blob) or blob.hex()
    if id_type is not None:
        decoded = blob.decode("utf-16-le", errors="ignore").rstrip("\x00")
        return decoded or blob.hex()

    return _decode_srum_blob(blob)


def _coerce_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _build_srum_id_map(ese_db) -> dict[int, str | None]:
    table = ese_db.table(SRUM_ID_MAP_TABLE)
    mapping: dict[int, str | None] = {}
    for record in table.records():
        row = record.as_dict()
        id_index = row.get("IdIndex")
        if id_index is None:
            continue
        mapping[id_index] = _decode_id_blob(row.get("IdBlob"), row.get("IdType"))
    return mapping


def _convert_srum_record(row: dict[str, object], id_map: dict[int, str | None]) -> dict[str, object]:
    converted = dict(row)
    if "TimeStamp" in converted:
        converted["timestamp"] = ole_automation_bits_to_iso(_coerce_int(converted["TimeStamp"]))

    if "AppId" in converted:
        app_id = _coerce_int(converted["AppId"])
        converted["app_name"] = id_map.get(app_id) if app_id is not None else None

    if "UserId" in converted:
        user_id = _coerce_int(converted["UserId"])
        converted["user_name"] = id_map.get(user_id) if user_id is not None else None

    for key, value in list(converted.items()):
        if isinstance(value, bytes):
            converted[key] = _decode_srum_blob(value)

    return converted


def srum_parse_path(file_path: str, sample_per_table: int = 3) -> dict[str, object]:
    sample_per_table = validate_count(sample_per_table, parameter="sample_per_table")
    path = ensure_file(resolve_input_path(file_path))
    ese_db, file_handle = _open_srum_database(str(path))

    try:
        tables = []
        for table in ese_db.tables():
            sample_rows = []
            for index, record in enumerate(table.records()):
                sample_rows.append(record.as_dict())
                if index + 1 >= sample_per_table:
                    break

            tables.append(
                {
                    "name": table.name,
                    "columns": list(table.column_names),
                    "sample_rows": sample_rows,
                }
            )

        return {
            "source_path": str(path),
            "version": ese_db.version,
            "format_major": ese_db.format_major,
            "format_minor": ese_db.format_minor,
            "page_size": ese_db.page_size,
            "table_count": len(tables),
            "tables": tables,
        }
    finally:
        file_handle.close()


def _extract_srum_rows(file_path: str, table_name: str, limit: int) -> dict[str, object]:
    limit = validate_limit(limit)
    path = ensure_file(resolve_input_path(file_path))
    ese_db, file_handle = _open_srum_database(str(path))

    try:
        id_map = _build_srum_id_map(ese_db)

        try:
            table = ese_db.table(table_name)
        except (KeyError, ValueError) as exc:
            raise UnsupportedArtifactError(
                f"SRUM table {table_name} was not found in this database: {exc}"
            ) from exc
        rows = []
        for record in table.records():
            rows.append(_convert_srum_record(record.as_dict(), id_map))
            if len(rows) >= limit:
                break

        return {
            "source_path": str(path),
            "table_name": table_name,
            "row_count": len(rows),
            "rows": rows,
        }
    finally:
        file_handle.close()


def srum_extract_app_usage_path(file_path: str, limit: int = 50) -> dict[str, object]:
    return _extract_srum_rows(file_path, SRUM_APP_USAGE_TABLE, limit)


def srum_extract_network_usage_path(file_path: str, limit: int = 50) -> dict[str, object]:
    return _extract_srum_rows(file_path, SRUM_NETWORK_USAGE_TABLE, limit)


def register_tools(mcp) -> None:
    @mcp.tool()
    def srum_parse(file_path: str, sample_per_table: int = 3) -> dict[str, object]:
        """Summarize a SRUM ESE database."""

        return srum_parse_path(file_path, sample_per_table=sample_per_table)

    @mcp.tool()
    def srum_extract_app_usage(file_path: str, limit: int = 50) -> dict[str, object]:
        """Extract application usage rows from SRUM."""

        return srum_extract_app_usage_path(file_path, limit=limit)

    @mcp.tool()
    def srum_extract_network_usage(file_path: str, limit: int = 50) -> dict[str, object]:
        """Extract network usage rows from SRUM."""

        return srum_extract_network_usage_path(file_path, limit=limit)
