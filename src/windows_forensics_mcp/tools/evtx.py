"""EVTX parsing tools."""

from typing import TYPE_CHECKING, Iterable, Iterator
from xml.etree import ElementTree as ET

from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import isoformat_datetime

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _open_evtx_file(path: str):
    pyevtx = require_module("pyevtx", "libevtx-python")
    evtx_file = pyevtx.file()
    evtx_file.open(path)
    return evtx_file


def _iter_evtx_records(evtx_file) -> tuple[str, int, Iterator]:
    record_count = evtx_file.get_number_of_records()
    if record_count > 0:
        return "records", record_count, _yield_evtx_records(evtx_file, recovered=False)
    recovered_count = evtx_file.get_number_of_recovered_records()
    return "recovered_records", recovered_count, _yield_evtx_records(evtx_file, recovered=True)


def _yield_evtx_records(evtx_file, *, recovered: bool) -> Iterator:
    total = evtx_file.get_number_of_recovered_records() if recovered else evtx_file.get_number_of_records()
    getter = evtx_file.get_recovered_record if recovered else evtx_file.get_record

    for index in range(total):
        try:
            yield getter(index)
        except OSError:
            continue


def _safe_xml_text(xml_root: ET.Element, xpath: str) -> str | None:
    element = xml_root.find(xpath, EVENT_NS)
    if element is None:
        return None
    return element.text


def _record_to_dict(record) -> dict[str, object]:
    xml_string = record.xml_string
    parsed_xml: ET.Element | None = None
    provider_name = record.source_name
    channel_name = record.channel_name
    event_identifier = record.event_identifier
    event_record_identifier = record.identifier
    computer_name = record.computer_name
    user_sid = record.user_security_identifier
    correlation_id = None
    event_data: list[dict[str, str | None]] = []

    try:
        parsed_xml = ET.fromstring(xml_string)
    except ET.ParseError:
        parsed_xml = None

    if parsed_xml is not None:
        provider = parsed_xml.find("e:System/e:Provider", EVENT_NS)
        if provider is not None:
            provider_name = provider.get("Name") or provider_name

        channel_name = _safe_xml_text(parsed_xml, "e:System/e:Channel") or channel_name
        event_identifier = int(_safe_xml_text(parsed_xml, "e:System/e:EventID") or event_identifier)
        event_record_identifier = int(
            _safe_xml_text(parsed_xml, "e:System/e:EventRecordID") or event_record_identifier
        )
        computer_name = _safe_xml_text(parsed_xml, "e:System/e:Computer") or computer_name
        security_element = parsed_xml.find("e:System/e:Security", EVENT_NS)
        if security_element is not None:
            user_sid = security_element.get("UserID") or user_sid
        correlation_element = parsed_xml.find("e:System/e:Correlation", EVENT_NS)
        if correlation_element is not None:
            correlation_id = correlation_element.get("ActivityID")

        event_data_root = parsed_xml.find("e:EventData", EVENT_NS)
        if event_data_root is not None:
            for data_item in event_data_root.findall("e:Data", EVENT_NS):
                event_data.append({"name": data_item.get("Name"), "value": data_item.text})

    return {
        "identifier": record.identifier,
        "event_record_id": event_record_identifier,
        "event_id": event_identifier,
        "event_level": record.event_level,
        "event_version": record.event_version,
        "provider": provider_name,
        "provider_identifier": str(record.provider_identifier) if record.provider_identifier else None,
        "source_name": record.source_name,
        "channel": channel_name,
        "computer": computer_name,
        "user_sid": user_sid,
        "creation_time": isoformat_datetime(record.creation_time),
        "written_time": isoformat_datetime(record.written_time),
        "correlation_activity_id": correlation_id,
        "data": event_data,
        "xml": xml_string,
    }


def evtx_info_path(file_path: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    evtx_file = _open_evtx_file(str(path))

    try:
        record_source, _, records = _iter_evtx_records(evtx_file)
        sample_records = []
        for record in records:
            sample_records.append(_record_to_dict(record))
            if len(sample_records) >= 3:
                break
        return {
            "source_path": str(path),
            "format_version": evtx_file.format_version,
            "is_corrupted": bool(evtx_file.is_corrupted()),
            "record_count": evtx_file.get_number_of_records(),
            "recovered_record_count": evtx_file.get_number_of_recovered_records(),
            "record_source": record_source,
            "sample_records": sample_records,
        }
    finally:
        evtx_file.close()


def evtx_list_records_path(file_path: str, limit: int = 50, offset: int = 0) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    evtx_file = _open_evtx_file(str(path))

    try:
        record_source, _, records = _iter_evtx_records(evtx_file)
        selected_records = []
        matched_index = 0
        for record in records:
            if matched_index < offset:
                matched_index += 1
                continue

            selected_records.append(record)
            matched_index += 1
            if len(selected_records) >= limit:
                break
        return {
            "source_path": str(path),
            "record_source": record_source,
            "offset": offset,
            "limit": limit,
            "records": [_record_to_dict(record) for record in selected_records],
        }
    finally:
        evtx_file.close()


def evtx_search_path(
    file_path: str,
    *,
    event_id: int | None = None,
    provider_contains: str | None = None,
    text_contains: str | None = None,
    limit: int = 50,
) -> dict[str, object]:
    path = ensure_file(resolve_input_path(file_path))
    evtx_file = _open_evtx_file(str(path))

    provider_contains = provider_contains.lower() if provider_contains else None
    text_contains = text_contains.lower() if text_contains else None

    try:
        record_source, _, records = _iter_evtx_records(evtx_file)
        matches: list[dict[str, object]] = []
        scanned = 0

        for record in records:
            scanned += 1
            item = _record_to_dict(record)

            if event_id is not None and item["event_id"] != event_id:
                continue

            provider_value = str(item.get("provider") or "").lower()
            if provider_contains and provider_contains not in provider_value:
                continue

            xml_value = str(item.get("xml") or "").lower()
            if text_contains and text_contains not in xml_value:
                continue

            matches.append(item)
            if len(matches) >= limit:
                break

        return {
            "source_path": str(path),
            "record_source": record_source,
            "scanned": scanned,
            "match_count": len(matches),
            "matches": matches,
        }
    finally:
        evtx_file.close()


def evtx_timeline_path(file_path: str, limit: int = 100) -> dict[str, object]:
    listing = evtx_list_records_path(file_path, limit=limit, offset=0)
    timeline = []

    for record in listing["records"]:
        timeline.append(
            {
                "timestamp": record.get("written_time") or record.get("creation_time"),
                "artifact_type": "evtx",
                "event_id": record.get("event_id"),
                "provider": record.get("provider"),
                "channel": record.get("channel"),
                "event_record_id": record.get("event_record_id"),
                "summary": f"{record.get('provider')} event {record.get('event_id')}",
            }
        )

    return {
        "source_path": listing["source_path"],
        "record_source": listing["record_source"],
        "timeline": timeline,
    }


def evtx_detect_security_events_path(file_path: str, profile: str = "powershell", limit: int = 50) -> dict[str, object]:
    profile_key = profile.lower()
    profiles = {
        "powershell": {"provider": "powershell", "event_ids": {4103, 4104, 40961, 40962}},
        "logon": {"provider": None, "event_ids": {4624, 4625}},
        "process_creation": {"provider": None, "event_ids": {4688}},
        "service_install": {"provider": None, "event_ids": {7045}},
    }
    selected = profiles.get(profile_key, profiles["powershell"])

    search_result = evtx_search_path(
        file_path,
        provider_contains=selected["provider"],
        limit=limit * 5,
    )

    matches = [
        item for item in search_result["matches"] if int(item.get("event_id") or -1) in selected["event_ids"]
    ][:limit]

    return {
        "source_path": search_result["source_path"],
        "profile": profile_key,
        "match_count": len(matches),
        "matches": matches,
    }


def register_tools(mcp) -> None:
    @mcp.tool()
    def evtx_info(file_path: str) -> dict[str, object]:
        """Summarize an EVTX file."""

        return evtx_info_path(file_path)

    @mcp.tool()
    def evtx_list_records(file_path: str, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """List EVTX records from a file."""

        return evtx_list_records_path(file_path, limit=limit, offset=offset)

    @mcp.tool()
    def evtx_search(
        file_path: str,
        event_id: int | None = None,
        provider_contains: str | None = None,
        text_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        """Search an EVTX file by event id, provider, or text."""

        return evtx_search_path(
            file_path,
            event_id=event_id,
            provider_contains=provider_contains,
            text_contains=text_contains,
            limit=limit,
        )

    @mcp.tool()
    def evtx_timeline(file_path: str, limit: int = 100) -> dict[str, object]:
        """Build a timeline view from an EVTX file."""

        return evtx_timeline_path(file_path, limit=limit)

    @mcp.tool()
    def evtx_detect_security_events(file_path: str, profile: str = "powershell", limit: int = 50) -> dict[str, object]:
        """Detect common security-relevant EVTX events."""

        return evtx_detect_security_events_path(file_path, profile=profile, limit=limit)
