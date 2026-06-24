"""Registry hive parsing tools."""

import codecs

from windows_forensics_mcp.errors import UnsupportedArtifactError
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_file, resolve_input_path
from windows_forensics_mcp.utils.time import filetime_to_iso, isoformat_datetime
from windows_forensics_mcp.utils.validation import validate_depth, validate_limit


def _open_registry_hive(path: str):
    pyregf = require_module("pyregf", "libregf-python")
    registry_file = pyregf.file()
    registry_file.open(path)
    return registry_file


def _normalize_registry_path(key_path: str | None) -> str | None:
    if not key_path:
        return None
    normalized = key_path.strip("\\/").replace("/", "\\")
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return normalized or None


def _get_registry_key(registry_file, key_path: str | None):
    normalized = _normalize_registry_path(key_path)
    if not normalized:
        return registry_file.get_root_key()
    return registry_file.get_key_by_path(normalized)


def _decode_registry_value(value) -> dict[str, object]:
    decoded: object
    data_type = value.type
    data_size = value.data_size
    raw_data = value.data or b""

    decoded = None
    for accessor_name in ("get_data_as_multi_string", "get_data_as_string", "get_data_as_integer"):
        accessor = getattr(value, accessor_name)
        try:
            decoded = accessor()
            break
        except (OSError, ValueError, TypeError):
            continue

    if decoded is None:
        decoded = raw_data.hex()

    return {
        "name": value.name,
        "type": data_type,
        "size": data_size,
        "data": decoded,
        "raw_hex": raw_data.hex() if raw_data else None,
        "offset": value.offset,
    }


def _key_to_dict(key, key_path: str | None = None) -> dict[str, object]:
    path_suffix = key_path or key.name
    return {
        "name": key.name,
        "path": path_suffix,
        "class_name": key.class_name,
        "last_written_time": isoformat_datetime(key.last_written_time),
        "sub_key_count": key.number_of_sub_keys,
        "value_count": key.number_of_values,
        "offset": key.offset,
    }


def registry_hive_info_path(hive_path: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(hive_path))
    registry_file = _open_registry_hive(str(path))

    try:
        root_key = registry_file.get_root_key()
        logical_name = None
        lowered_name = path.name.lower()
        if lowered_name == "ntuser.dat":
            logical_name = "HKEY_CURRENT_USER"
        elif lowered_name == "usrclass.dat":
            logical_name = "HKEY_CURRENT_USER\\Software\\Classes"
        elif lowered_name in {"software", "system", "sam", "security", "default"}:
            logical_name = f"HKEY_LOCAL_MACHINE\\{path.name.upper()}"
        return {
            "source_path": str(path),
            "format_version": registry_file.format_version,
            "type": registry_file.type,
            "is_corrupted": bool(registry_file.is_corrupted()),
            "root_key": _key_to_dict(root_key, key_path=root_key.name),
            "logical_hive_name": logical_name,
        }
    finally:
        registry_file.close()


def registry_list_keys_path(
    hive_path: str, key_path: str | None = None, depth: int = 1, max_keys: int = 5000
) -> dict[str, object]:
    depth = validate_depth(depth)
    max_keys = validate_limit(max_keys, parameter="max_keys")
    path = ensure_file(resolve_input_path(hive_path))
    registry_file = _open_registry_hive(str(path))

    try:
        root_key = _get_registry_key(registry_file, key_path)
        if root_key is None:
            raise UnsupportedArtifactError(f"Registry key not found: {key_path}")

        results = []
        truncated = False
        stack = [(root_key, _normalize_registry_path(key_path) or root_key.name, 0)]
        while stack:
            current_key, current_path, current_depth = stack.pop()
            results.append(_key_to_dict(current_key, current_path))
            if len(results) >= max_keys:
                truncated = True
                break
            if current_depth >= depth:
                continue

            for index in range(current_key.number_of_sub_keys - 1, -1, -1):
                sub_key = current_key.get_sub_key(index)
                stack.append((sub_key, f"{current_path}\\{sub_key.name}", current_depth + 1))

        return {
            "source_path": str(path),
            "requested_key": _normalize_registry_path(key_path) or root_key.name,
            "depth": depth,
            "key_count": len(results),
            "truncated": truncated,
            "keys": results,
        }
    finally:
        registry_file.close()


def registry_get_values_path(hive_path: str, key_path: str | None = None) -> dict[str, object]:
    path = ensure_file(resolve_input_path(hive_path))
    registry_file = _open_registry_hive(str(path))

    try:
        key = _get_registry_key(registry_file, key_path)
        if key is None:
            raise UnsupportedArtifactError(f"Registry key not found: {key_path}")

        values = [_decode_registry_value(key.get_value(index)) for index in range(key.number_of_values)]
        return {
            "source_path": str(path),
            "key": _key_to_dict(key, _normalize_registry_path(key_path) or key.name),
            "values": values,
        }
    finally:
        registry_file.close()


def registry_search_path(
    hive_path: str,
    pattern: str,
    scope: str = "all",
    max_results: int = 50,
    max_depth: int = 32,
) -> dict[str, object]:
    max_results = validate_limit(max_results, parameter="max_results")
    max_depth = validate_depth(max_depth, parameter="max_depth")
    path = ensure_file(resolve_input_path(hive_path))
    registry_file = _open_registry_hive(str(path))
    lowered_pattern = pattern.lower()
    scope_key = scope.lower()

    try:
        root_key = registry_file.get_root_key()
        stack = [(root_key, root_key.name, 0)]
        matches: list[dict[str, object]] = []

        while stack and len(matches) < max_results:
            current_key, current_path, current_depth = stack.pop()

            key_name_match = lowered_pattern in current_key.name.lower()
            if key_name_match and scope_key in {"all", "keys"}:
                matches.append(
                    {
                        "match_type": "key",
                        "path": current_path,
                        "metadata": _key_to_dict(current_key, current_path),
                    }
                )
                if len(matches) >= max_results:
                    break

            if scope_key in {"all", "values"}:
                for index in range(current_key.number_of_values):
                    value = current_key.get_value(index)
                    parsed_value = _decode_registry_value(value)
                    value_name = str(parsed_value["name"] or "")
                    value_data = str(parsed_value["data"] or "")
                    if lowered_pattern in value_name.lower() or lowered_pattern in value_data.lower():
                        matches.append(
                            {
                                "match_type": "value",
                                "path": current_path,
                                "value": parsed_value,
                            }
                        )
                        if len(matches) >= max_results:
                            break

            if current_depth < max_depth and len(matches) < max_results:
                for index in range(current_key.number_of_sub_keys - 1, -1, -1):
                    sub_key = current_key.get_sub_key(index)
                    stack.append((sub_key, f"{current_path}\\{sub_key.name}", current_depth + 1))

        return {
            "source_path": str(path),
            "pattern": pattern,
            "scope": scope_key,
            "match_count": len(matches),
            "matches": matches,
        }
    finally:
        registry_file.close()


def _collect_key_values(registry_file, key_path: str) -> list[dict[str, object]]:
    key = _get_registry_key(registry_file, key_path)
    if key is None:
        return []
    return [_decode_registry_value(key.get_value(index)) for index in range(key.number_of_values)]


def _extract_run_entries(registry_file) -> list[dict[str, object]]:
    candidate_paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    entries = []
    for candidate in candidate_paths:
        values = _collect_key_values(registry_file, candidate)
        if not values:
            continue
        entries.append({"key_path": candidate, "values": values})
    return entries


def _extract_userassist_entries(registry_file) -> list[dict[str, object]]:
    root_key = _get_registry_key(registry_file, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    if root_key is None:
        return []

    entries = []
    for index in range(root_key.number_of_sub_keys):
        guid_key = root_key.get_sub_key(index)
        count_key = guid_key.get_sub_key_by_name("Count")
        if count_key is None:
            continue

        for value_index in range(count_key.number_of_values):
            value = count_key.get_value(value_index)
            raw_data = value.data or b""
            run_count = int.from_bytes(raw_data[4:8], "little") if len(raw_data) >= 8 else None
            last_execution_time = None
            if len(raw_data) >= 68:
                last_execution_time = filetime_to_iso(int.from_bytes(raw_data[60:68], "little"))

            value_name = value.name
            decoded_name = codecs.decode(value_name, "rot_13") if value_name else None

            entries.append(
                {
                    "guid": guid_key.name,
                    "name_rot13": value_name,
                    "decoded_name": decoded_name,
                    "run_count": run_count,
                    "last_execution_time": last_execution_time,
                    "raw_hex": raw_data.hex(),
                }
            )

    return entries


def _extract_recentdocs_entries(registry_file) -> list[dict[str, object]]:
    root_key = _get_registry_key(registry_file, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
    if root_key is None:
        return []

    entries = []
    candidate_keys = [(root_key, root_key.name)]
    for index in range(root_key.number_of_sub_keys):
        sub_key = root_key.get_sub_key(index)
        candidate_keys.append((sub_key, f"{root_key.name}\\{sub_key.name}"))

    for key, key_path in candidate_keys:
        values = []
        for value_index in range(key.number_of_values):
            value = _decode_registry_value(key.get_value(value_index))
            if value["name"] == "MRUListEx":
                continue
            values.append(value)
        if values:
            entries.append({"key_path": key_path, "values": values})

    return entries


def _extract_runmru_entries(registry_file) -> list[dict[str, object]]:
    values = _collect_key_values(registry_file, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
    return [value for value in values if value["name"] != "MRUList"]


def _control_set_paths(registry_file, suffix: str) -> list[str]:
    """Build candidate control-set-relative paths.

    Offline SYSTEM hives expose ControlSetNNN keys rather than the live
    CurrentControlSet symlink, so we try the Select\\Current set first, then
    fall back to common control sets and the live name.
    """
    candidates: list[str] = []
    select_key = _get_registry_key(registry_file, "Select")
    if select_key is not None:
        current = select_key.get_value_by_name("Current")
        if current is not None:
            try:
                candidates.append(f"ControlSet{current.get_data_as_integer():03d}\\{suffix}")
            except (OSError, ValueError, TypeError):
                pass
    candidates.extend(
        [
            f"ControlSet001\\{suffix}",
            f"ControlSet002\\{suffix}",
            f"CurrentControlSet\\{suffix}",
        ]
    )
    # Preserve order while removing duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _decode_shimcache_win10(data: bytes) -> list[dict[str, object]]:
    """Decode a Windows 8.1/10 AppCompatCache (ShimCache) blob.

    Each entry is framed by a '10ts' signature followed by a cache-entry size,
    a UTF-16 path, and an 8-byte FILETIME last-modified timestamp. The header
    length is stored in the first DWORD (0x34 on Windows 10).
    """
    entries: list[dict[str, object]] = []
    if len(data) < 4:
        return entries

    header_size = int.from_bytes(data[:4], "little")
    offset = header_size
    while offset + 12 <= len(data):
        if data[offset : offset + 4] != b"10ts":
            break
        cache_entry_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        pointer = offset + 12
        if pointer + 2 > len(data):
            break
        path_length = int.from_bytes(data[pointer : pointer + 2], "little")
        pointer += 2
        path = data[pointer : pointer + path_length].decode("utf-16-le", errors="replace")
        pointer += path_length
        last_modified = None
        if pointer + 8 <= len(data):
            last_modified = filetime_to_iso(int.from_bytes(data[pointer : pointer + 8], "little"))
        entries.append(
            {
                "position": len(entries),
                "path": path,
                "last_modified_time": last_modified,
            }
        )
        if cache_entry_size <= 0:
            break
        offset += 12 + cache_entry_size
    return entries


def _extract_shimcache_entries(registry_file) -> list[dict[str, object]]:
    suffix = r"Control\Session Manager\AppCompatCache"
    for candidate in _control_set_paths(registry_file, suffix):
        key = _get_registry_key(registry_file, candidate)
        if key is None:
            continue
        value = key.get_value_by_name("AppCompatCache")
        if value is None:
            continue
        data = value.data or b""
        decoded = _decode_shimcache_win10(data)
        return [{"key_path": candidate, "signature": data[:4].hex(), "entries": decoded}]
    return []


def _extract_usbstor_entries(registry_file) -> list[dict[str, object]]:
    string_fields = (
        "FriendlyName",
        "DeviceDesc",
        "Mfg",
        "Service",
        "ContainerID",
        "HardwareID",
    )
    for candidate in _control_set_paths(registry_file, r"Enum\USBSTOR"):
        usbstor_key = _get_registry_key(registry_file, candidate)
        if usbstor_key is None:
            continue

        devices: list[dict[str, object]] = []
        for class_index in range(usbstor_key.number_of_sub_keys):
            device_class = usbstor_key.get_sub_key(class_index)
            for instance_index in range(device_class.number_of_sub_keys):
                instance = device_class.get_sub_key(instance_index)
                properties: dict[str, object] = {}
                for field in string_fields:
                    value = instance.get_value_by_name(field)
                    if value is None:
                        continue
                    try:
                        properties[field] = value.get_data_as_string()
                    except (OSError, ValueError, TypeError):
                        properties[field] = (value.data or b"").hex()
                devices.append(
                    {
                        "device_class": device_class.name,
                        "serial_number": instance.name,
                        "last_written_time": isoformat_datetime(instance.last_written_time),
                        "properties": properties,
                    }
                )
        return [{"key_path": candidate, "device_count": len(devices), "devices": devices}]
    return []


def _amcache_entry_values(entry_key) -> dict[str, object]:
    values: dict[str, object] = {}
    for value_index in range(entry_key.number_of_values):
        value = entry_key.get_value(value_index)
        decoded: object = None
        for accessor in ("get_data_as_string", "get_data_as_integer"):
            try:
                decoded = getattr(value, accessor)()
                break
            except (OSError, ValueError, TypeError):
                continue
        if decoded is None:
            decoded = (value.data or b"").hex() or None
        values[value.name or ""] = decoded
    return values


def _extract_amcache_entries(registry_file, limit: int = 1000) -> list[dict[str, object]]:
    # Modern (Win10/11) Amcache stores program executables under
    # Root\InventoryApplicationFile; older builds use Root\File\<volume>\<id>.
    inventory = _get_registry_key(registry_file, r"Root\InventoryApplicationFile")
    if inventory is not None:
        entries: list[dict[str, object]] = []
        for index in range(inventory.number_of_sub_keys):
            if len(entries) >= limit:
                break
            entry_key = inventory.get_sub_key(index)
            entries.append(
                {
                    "key_name": entry_key.name,
                    "last_written_time": isoformat_datetime(entry_key.last_written_time),
                    "values": _amcache_entry_values(entry_key),
                }
            )
        return entries

    file_root = _get_registry_key(registry_file, r"Root\File")
    if file_root is None:
        return []
    entries = []
    for volume_index in range(file_root.number_of_sub_keys):
        volume_key = file_root.get_sub_key(volume_index)
        for entry_index in range(volume_key.number_of_sub_keys):
            if len(entries) >= limit:
                return entries
            entry_key = volume_key.get_sub_key(entry_index)
            entries.append(
                {
                    "key_name": f"{volume_key.name}\\{entry_key.name}",
                    "last_written_time": isoformat_datetime(entry_key.last_written_time),
                    "values": _amcache_entry_values(entry_key),
                }
            )
    return entries


def registry_extract_artifact_path(hive_path: str, artifact_type: str) -> dict[str, object]:
    path = ensure_file(resolve_input_path(hive_path))
    registry_file = _open_registry_hive(str(path))
    artifact_key = artifact_type.lower()

    try:
        if artifact_key in {"run", "runonce", "autoruns"}:
            entries = _extract_run_entries(registry_file)
        elif artifact_key == "userassist":
            entries = _extract_userassist_entries(registry_file)
        elif artifact_key == "recentdocs":
            entries = _extract_recentdocs_entries(registry_file)
        elif artifact_key == "runmru":
            entries = _extract_runmru_entries(registry_file)
        elif artifact_key == "shimcache":
            entries = _extract_shimcache_entries(registry_file)
        elif artifact_key == "usbstor":
            entries = _extract_usbstor_entries(registry_file)
        elif artifact_key == "amcache":
            entries = _extract_amcache_entries(registry_file)
        else:
            raise UnsupportedArtifactError(f"Unsupported registry artifact extractor: {artifact_type}")

        return {
            "source_path": str(path),
            "artifact_type": artifact_key,
            "entry_count": len(entries),
            "entries": entries,
        }
    finally:
        registry_file.close()


def register_tools(mcp) -> None:
    @mcp.tool()
    def registry_hive_info(hive_path: str) -> dict[str, object]:
        """Summarize an offline Windows registry hive."""

        return registry_hive_info_path(hive_path)

    @mcp.tool()
    def registry_list_keys(
        hive_path: str, key_path: str | None = None, depth: int = 1, max_keys: int = 5000
    ) -> dict[str, object]:
        """List registry keys from an offline hive."""

        return registry_list_keys_path(hive_path, key_path=key_path, depth=depth, max_keys=max_keys)

    @mcp.tool()
    def registry_get_values(hive_path: str, key_path: str | None = None) -> dict[str, object]:
        """Get registry values from an offline hive key."""

        return registry_get_values_path(hive_path, key_path=key_path)

    @mcp.tool()
    def registry_search(
        hive_path: str,
        pattern: str,
        scope: str = "all",
        max_results: int = 50,
        max_depth: int = 32,
    ) -> dict[str, object]:
        """Search an offline registry hive."""

        return registry_search_path(
            hive_path,
            pattern,
            scope=scope,
            max_results=max_results,
            max_depth=max_depth,
        )

    @mcp.tool()
    def registry_extract_artifact(hive_path: str, artifact_type: str) -> dict[str, object]:
        """Extract common forensic artifacts from a registry hive."""

        return registry_extract_artifact_path(hive_path, artifact_type)
