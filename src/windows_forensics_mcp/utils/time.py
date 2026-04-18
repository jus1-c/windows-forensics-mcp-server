"""Time conversion helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import struct


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
OLE_AUTOMATION_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def isoformat_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.isoformat().replace("+00:00", "Z")


def filetime_to_datetime(value: int | None) -> datetime | None:
    if value in (None, 0):
        return None

    return FILETIME_EPOCH + timedelta(microseconds=value / 10)


def filetime_to_iso(value: int | None) -> str | None:
    return isoformat_datetime(filetime_to_datetime(value))


def ole_automation_bits_to_datetime(raw_value: int | None) -> datetime | None:
    if raw_value in (None, 0):
        return None

    encoded = struct.pack("<Q", int(raw_value))
    days = struct.unpack("<d", encoded)[0]
    return OLE_AUTOMATION_EPOCH + timedelta(days=days)


def ole_automation_bits_to_iso(raw_value: int | None) -> str | None:
    return isoformat_datetime(ole_automation_bits_to_datetime(raw_value))
