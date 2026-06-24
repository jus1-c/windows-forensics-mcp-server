"""Windows DPAPI recovery and artifact decryption tools."""

import base64
import binascii
import json
import uuid
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

from windows_forensics_mcp.errors import DecryptionError, ToolInputError, UnsupportedArtifactError
from windows_forensics_mcp.utils.deps import require_module
from windows_forensics_mcp.utils.paths import ensure_directory, ensure_file, resolve_input_path


def _require_dpapick3() -> tuple[Any, Any, Any]:
    blob_module = require_module("dpapick3.blob", "dpapick3")
    masterkey_module = require_module("dpapick3.masterkey", "dpapick3")
    registry_module = require_module("dpapick3.registry", "dpapick3")
    return blob_module.DPAPIBlob, masterkey_module.MasterKeyPool, registry_module.Regedit


def _require_pypykatz_dpapi() -> Any:
    dpapi_module = require_module("pypykatz.dpapi.dpapi", "pypykatz")
    return dpapi_module.DPAPI


def _jsonify(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, bytes):
        utf8 = None
        try:
            utf8 = value.decode("utf-8")
        except UnicodeDecodeError:
            pass
        return {
            "hex": value.hex(),
            "base64": base64.b64encode(value).decode("ascii"),
            "utf8": utf8,
            "size": len(value),
        }
    if isinstance(value, Path):
        return str(value)
    if depth >= 4:
        return repr(value)
    if isinstance(value, dict):
        return {str(key): _jsonify(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(item, depth + 1) for item in value]
    if hasattr(value, "__dict__"):
        items = {
            key: _jsonify(item, depth + 1)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
        items["__class__"] = value.__class__.__name__
        return items
    return repr(value)


def _decode_hex(value: str | None, *, parameter: str) -> bytes | None:
    if value is None:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ToolInputError(f"Invalid hex value for {parameter}: {exc}") from exc


def _normalize_guid(guid: Any) -> str:
    if isinstance(guid, bytes):
        return guid.decode("utf-8").lower()
    return str(guid).lower()


def _validate_masterkeys(masterkeys_by_guid: dict[str, str] | None) -> dict[str, bytes]:
    if not masterkeys_by_guid:
        raise ToolInputError("masterkeys_by_guid is required for this operation")
    validated: dict[str, bytes] = {}
    for guid, key_hex in masterkeys_by_guid.items():
        try:
            normalized_guid = str(uuid.UUID(guid)).lower()
        except ValueError as exc:
            raise ToolInputError(f"Invalid masterkey GUID: {guid}") from exc
        validated[normalized_guid] = _decode_hex(key_hex, parameter=f"masterkeys_by_guid[{guid}]")
    return validated


def _preferred_masterkey_guid(protect_dir: Path) -> str | None:
    preferred_path = protect_dir / "Preferred"
    if not preferred_path.exists():
        return None
    raw = preferred_path.read_bytes()
    if len(raw) < 16:
        return None
    try:
        return str(uuid.UUID(bytes_le=raw[:16])).lower()
    except ValueError:
        return None


def _masterkey_file_decrypted(masterkey_file: Any) -> bool:
    masterkey = getattr(masterkey_file, "masterkey", None)
    backupkey = getattr(masterkey_file, "backupkey", None)
    return bool(
        (masterkey is not None and getattr(masterkey, "decrypted", False))
        or (backupkey is not None and getattr(backupkey, "decrypted", False))
    )


def _serialize_masterkeys(pool: Any) -> dict[str, str]:
    masterkeys_by_guid: dict[str, str] = {}
    for guid, entries in getattr(pool, "keys", {}).items():
        normalized_guid = _normalize_guid(guid)
        for entry in entries:
            if not _masterkey_file_decrypted(entry):
                continue
            key_bytes = entry.get_key()
            if key_bytes is None:
                continue
            masterkeys_by_guid[normalized_guid] = key_bytes.hex()
            break
    return masterkeys_by_guid


def _load_system_credential_blob(system_hive_path: Path, security_hive_path: Path) -> bytes:
    _, _, Regedit = _require_dpapick3()
    regedit = Regedit()
    lsa_secrets = regedit.get_lsa_secrets(str(security_hive_path), str(system_hive_path))
    dpapi_system = (lsa_secrets.get("DPAPI_SYSTEM") or {}).get("CurrVal")
    if not dpapi_system:
        raise DecryptionError("DPAPI_SYSTEM secret not found in SECURITY hive")
    return dpapi_system


def _recover_masterkeys_internal(
    *,
    protect_dir: Path,
    sid: str,
    password: str | None,
    nt_hash_hex: str | None,
    system_hive_path: Path | None,
    security_hive_path: Path | None,
    credhist_path: Path | None,
) -> dict[str, object]:
    if password is None and nt_hash_hex is None and system_hive_path is None and security_hive_path is None:
        raise ToolInputError(
            "Provide at least one recovery input: password, nt_hash, or both system_hive_path and security_hive_path"
        )
    if (system_hive_path is None) != (security_hive_path is None):
        raise ToolInputError("system_hive_path and security_hive_path must be provided together")

    _, MasterKeyPool, _ = _require_dpapick3()
    pool = MasterKeyPool()
    pool.loadDirectory(str(protect_dir))

    system_credential_loaded = False
    credhist_loaded = False
    strategy_attempts: list[dict[str, object]] = []
    warnings: list[str] = []

    if credhist_path is not None:
        pool.addCredhistFile(sid, str(credhist_path))
        credhist_loaded = True

    if system_hive_path is not None and security_hive_path is not None:
        try:
            pool.addSystemCredential(_load_system_credential_blob(system_hive_path, security_hive_path))
            system_credential_loaded = True
        except Exception as exc:
            warnings.append(f"Failed to load DPAPI_SYSTEM secret: {exc}")

    if password is not None:
        decrypted_count = pool.try_credential(sid, password)
        strategy_attempts.append(
            {"method": "password", "input_provided": True, "decrypted_count": decrypted_count}
        )

    if nt_hash_hex is not None:
        decrypted_count = pool.try_credential_hash(sid, _decode_hex(nt_hash_hex, parameter="nt_hash"))
        strategy_attempts.append(
            {"method": "nt_hash", "input_provided": True, "decrypted_count": decrypted_count}
        )

    if system_credential_loaded:
        decrypted_count = pool.try_credential_hash(sid, None)
        strategy_attempts.append(
            {"method": "dpapi_system", "input_provided": True, "decrypted_count": decrypted_count}
        )

    masterkeys_by_guid = _serialize_masterkeys(pool)
    if not masterkeys_by_guid:
        warnings.append("No DPAPI masterkeys were recovered with the supplied inputs")

    return {
        "sid": sid,
        "protect_dir": str(protect_dir),
        "preferred_guid": _preferred_masterkey_guid(protect_dir),
        "recovered_masterkey_count": len(masterkeys_by_guid),
        "masterkeys_by_guid": masterkeys_by_guid,
        "strategy_attempts": strategy_attempts,
        "system_credential_loaded": system_credential_loaded,
        "credhist_loaded": credhist_loaded,
        "warnings": warnings,
    }


def windows_dpapi_recover_masterkeys_path(
    protect_dir: str,
    sid: str,
    *,
    password: str | None = None,
    nt_hash: str | None = None,
    system_hive_path: str | None = None,
    security_hive_path: str | None = None,
    credhist_path: str | None = None,
) -> dict[str, object]:
    protect_path = ensure_directory(resolve_input_path(protect_dir))
    system_path = ensure_file(resolve_input_path(system_hive_path)) if system_hive_path else None
    security_path = ensure_file(resolve_input_path(security_hive_path)) if security_hive_path else None
    credhist = ensure_file(resolve_input_path(credhist_path)) if credhist_path else None
    return _recover_masterkeys_internal(
        protect_dir=protect_path,
        sid=sid,
        password=password,
        nt_hash_hex=nt_hash,
        system_hive_path=system_path,
        security_hive_path=security_path,
        credhist_path=credhist,
    )


def _resolve_blob_bytes(blob_hex: str | None, blob_path: str | None) -> bytes:
    if blob_hex is None and blob_path is None:
        raise ToolInputError("Provide either blob_hex or blob_path")
    if blob_hex is not None and blob_path is not None:
        raise ToolInputError("Provide only one of blob_hex or blob_path")
    if blob_hex is not None:
        return _decode_hex(blob_hex, parameter="blob_hex")
    return ensure_file(resolve_input_path(blob_path)).read_bytes()


def windows_dpapi_decrypt_blob_path(
    *,
    masterkeys_by_guid: dict[str, str],
    blob_hex: str | None = None,
    blob_path: str | None = None,
    entropy_hex: str | None = None,
) -> dict[str, object]:
    DPAPIBlob, _, _ = _require_dpapick3()
    blob_bytes = _resolve_blob_bytes(blob_hex, blob_path)
    entropy = _decode_hex(entropy_hex, parameter="entropy_hex")
    validated_masterkeys = _validate_masterkeys(masterkeys_by_guid)

    blob = DPAPIBlob(blob_bytes)
    masterkey_guid = _normalize_guid(blob.mkguid)
    key = validated_masterkeys.get(masterkey_guid)
    if key is None:
        raise DecryptionError(f"No matching masterkey was found for blob GUID {masterkey_guid}")
    if not blob.decrypt(key, entropy=entropy):
        raise DecryptionError(f"Failed to decrypt DPAPI blob with masterkey {masterkey_guid}")

    cleartext = blob.cleartext or b""
    utf8 = None
    try:
        utf8 = cleartext.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return {
        "masterkey_guid": masterkey_guid,
        "cleartext_hex": cleartext.hex(),
        "cleartext_b64": base64.b64encode(cleartext).decode("ascii"),
        "cleartext_utf8": utf8,
        "cleartext_size": len(cleartext),
    }


def _resolve_or_recover_masterkeys(
    *,
    masterkeys_by_guid: dict[str, str] | None,
    protect_dir: str | None,
    sid: str | None,
    password: str | None,
    nt_hash: str | None,
    system_hive_path: str | None,
    security_hive_path: str | None,
    credhist_path: str | None,
) -> tuple[dict[str, str], dict[str, object] | None]:
    if masterkeys_by_guid is not None:
        validated = _validate_masterkeys(masterkeys_by_guid)
        # Return the validated, GUID-normalized mapping (as hex) so downstream
        # consumers share one canonical form instead of re-normalizing the raw
        # caller-supplied keys.
        normalized = {guid: key_bytes.hex() for guid, key_bytes in validated.items()}
        return normalized, None
    if protect_dir is None or sid is None:
        raise ToolInputError("Provide either masterkeys_by_guid or both protect_dir and sid")
    recovery = windows_dpapi_recover_masterkeys_path(
        protect_dir,
        sid,
        password=password,
        nt_hash=nt_hash,
        system_hive_path=system_hive_path,
        security_hive_path=security_hive_path,
        credhist_path=credhist_path,
    )
    return recovery["masterkeys_by_guid"], recovery


def _parse_local_state(local_state_path: Path) -> dict[str, object]:
    try:
        return json.loads(local_state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UnsupportedArtifactError(f"Failed to parse Local State JSON: {exc}") from exc


def windows_dpapi_recover_chromium_master_key_path(
    local_state_path: str,
    *,
    masterkeys_by_guid: dict[str, str] | None = None,
    protect_dir: str | None = None,
    sid: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    system_hive_path: str | None = None,
    security_hive_path: str | None = None,
    credhist_path: str | None = None,
) -> dict[str, object]:
    local_state_file = ensure_file(resolve_input_path(local_state_path))
    local_state = _parse_local_state(local_state_file)
    os_crypt = local_state.get("os_crypt") or {}
    encrypted_key_b64 = os_crypt.get("encrypted_key")
    app_bound_encrypted_key_b64 = os_crypt.get("app_bound_encrypted_key")
    if not encrypted_key_b64 and not app_bound_encrypted_key_b64:
        raise UnsupportedArtifactError(
            "Neither os_crypt.encrypted_key nor os_crypt.app_bound_encrypted_key was found"
        )

    resolved_masterkeys, recovery = _resolve_or_recover_masterkeys(
        masterkeys_by_guid=masterkeys_by_guid,
        protect_dir=protect_dir,
        sid=sid,
        password=password,
        nt_hash=nt_hash,
        system_hive_path=system_hive_path,
        security_hive_path=security_hive_path,
        credhist_path=credhist_path,
    )

    result: dict[str, object] = {
        "local_state_path": str(local_state_file),
        "encrypted_key_present": bool(encrypted_key_b64),
        "app_bound_encrypted_key_present": bool(app_bound_encrypted_key_b64),
        "legacy_supported": bool(encrypted_key_b64),
        "v20_detected": bool(app_bound_encrypted_key_b64),
        "master_key_b64": None,
        "encrypted_key_blob_guid": None,
        "recovered_masterkey_count": len(resolved_masterkeys),
        "warnings": [],
    }
    if recovery is not None:
        result["recovery"] = recovery

    if app_bound_encrypted_key_b64:
        result["warnings"].append(
            "App-bound Chromium encryption was detected. v20 decryption is not supported."
        )
    if not encrypted_key_b64:
        return result

    try:
        encrypted_key_blob = base64.b64decode(encrypted_key_b64)
    except (ValueError, binascii.Error) as exc:
        raise UnsupportedArtifactError(
            f"Failed to base64-decode os_crypt.encrypted_key: {exc}"
        ) from exc
    if encrypted_key_blob.startswith(b"DPAPI"):
        encrypted_key_blob = encrypted_key_blob[5:]
    blob_result = windows_dpapi_decrypt_blob_path(
        masterkeys_by_guid=resolved_masterkeys,
        blob_hex=encrypted_key_blob.hex(),
    )
    result["master_key_b64"] = blob_result["cleartext_b64"]
    result["encrypted_key_blob_guid"] = blob_result["masterkey_guid"]
    return result


def _create_pypykatz_dpapi(masterkeys_by_guid: dict[str, str]) -> Any:
    DPAPI = _require_pypykatz_dpapi()
    dpapi = DPAPI()
    for guid, key_hex in masterkeys_by_guid.items():
        dpapi.masterkeys[_normalize_guid(guid)] = _decode_hex(key_hex, parameter=f"masterkeys_by_guid[{guid}]")
    return dpapi


def _parse_credential_file_with_dpapi(
    credential_path: Path,
    *,
    dpapi: Any,
    masterkey_count: int,
) -> dict[str, object]:
    credential = dpapi.decrypt_credential_file(str(credential_path))
    return {
        "source_path": str(credential_path),
        "masterkey_count": masterkey_count,
        "credential": _jsonify(credential),
    }


def windows_dpapi_parse_credential_file_path(
    file_path: str,
    *,
    masterkeys_by_guid: dict[str, str] | None = None,
    protect_dir: str | None = None,
    sid: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    system_hive_path: str | None = None,
    security_hive_path: str | None = None,
    credhist_path: str | None = None,
) -> dict[str, object]:
    credential_path = ensure_file(resolve_input_path(file_path))
    resolved_masterkeys, recovery = _resolve_or_recover_masterkeys(
        masterkeys_by_guid=masterkeys_by_guid,
        protect_dir=protect_dir,
        sid=sid,
        password=password,
        nt_hash=nt_hash,
        system_hive_path=system_hive_path,
        security_hive_path=security_hive_path,
        credhist_path=credhist_path,
    )
    dpapi = _create_pypykatz_dpapi(resolved_masterkeys)
    result = _parse_credential_file_with_dpapi(
        credential_path,
        dpapi=dpapi,
        masterkey_count=len(resolved_masterkeys),
    )
    if recovery is not None:
        result["recovery"] = recovery
    return result


def windows_dpapi_parse_credentials_directory_path(
    directory_path: str,
    *,
    masterkeys_by_guid: dict[str, str] | None = None,
    protect_dir: str | None = None,
    sid: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    system_hive_path: str | None = None,
    security_hive_path: str | None = None,
    credhist_path: str | None = None,
) -> dict[str, object]:
    credentials_dir = ensure_directory(resolve_input_path(directory_path))
    credential_files = sorted([path for path in credentials_dir.iterdir() if path.is_file()])
    if not credential_files:
        raise UnsupportedArtifactError(
            f"No credential files were found in directory: {credentials_dir}"
        )

    resolved_masterkeys, recovery = _resolve_or_recover_masterkeys(
        masterkeys_by_guid=masterkeys_by_guid,
        protect_dir=protect_dir,
        sid=sid,
        password=password,
        nt_hash=nt_hash,
        system_hive_path=system_hive_path,
        security_hive_path=security_hive_path,
        credhist_path=credhist_path,
    )
    dpapi = _create_pypykatz_dpapi(resolved_masterkeys)

    records: list[dict[str, object]] = []
    warnings: list[str] = []
    for credential_path in credential_files:
        try:
            records.append(
                _parse_credential_file_with_dpapi(
                    credential_path,
                    dpapi=dpapi,
                    masterkey_count=len(resolved_masterkeys),
                )
            )
        except Exception as exc:
            warnings.append(f"Failed to decrypt {credential_path.name}: {exc}")

    result = {
        "directory_path": str(credentials_dir),
        "file_count": len(credential_files),
        "parsed_count": len(records),
        "failed_count": len(credential_files) - len(records),
        "records": records,
        "warnings": warnings,
    }
    if recovery is not None:
        result["recovery"] = recovery
    return result


def windows_dpapi_parse_vault_directory_path(
    directory_path: str,
    *,
    masterkeys_by_guid: dict[str, str] | None = None,
    protect_dir: str | None = None,
    sid: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    system_hive_path: str | None = None,
    security_hive_path: str | None = None,
    credhist_path: str | None = None,
) -> dict[str, object]:
    vault_dir = ensure_directory(resolve_input_path(directory_path))
    vpol_files = sorted(vault_dir.glob("*.vpol"))
    vcrd_files = sorted(vault_dir.glob("*.vcrd"))
    if not vpol_files:
        raise UnsupportedArtifactError(f"No .vpol files found in vault directory: {vault_dir}")
    if not vcrd_files:
        raise UnsupportedArtifactError(f"No .vcrd files found in vault directory: {vault_dir}")

    resolved_masterkeys, recovery = _resolve_or_recover_masterkeys(
        masterkeys_by_guid=masterkeys_by_guid,
        protect_dir=protect_dir,
        sid=sid,
        password=password,
        nt_hash=nt_hash,
        system_hive_path=system_hive_path,
        security_hive_path=security_hive_path,
        credhist_path=credhist_path,
    )
    dpapi = _create_pypykatz_dpapi(resolved_masterkeys)

    vpol_path = vpol_files[0]
    vpol_keys = dpapi.decrypt_vpol_file(str(vpol_path))
    warnings: list[str] = []
    records: list[dict[str, object]] = []
    for vcrd_path in vcrd_files:
        try:
            decrypted = dpapi.decrypt_vcrd_file(str(vcrd_path))
        except Exception as exc:
            warnings.append(f"Failed to decrypt {vcrd_path.name}: {exc}")
            continue
        attributes = []
        for attribute, candidates in decrypted.items():
            attributes.append(
                {
                    "attribute": _jsonify(attribute),
                    "cleartext_candidates": [_jsonify(candidate) for candidate in candidates],
                }
            )
        records.append(
            {
                "file_path": str(vcrd_path),
                "attribute_count": len(attributes),
                "attributes": attributes,
            }
        )

    result = {
        "directory_path": str(vault_dir),
        "vpol_path": str(vpol_path),
        "vpol_keys_hex": [key.hex() for key in vpol_keys],
        "record_count": len(records),
        "records": records,
        "warnings": warnings,
    }
    if recovery is not None:
        result["recovery"] = recovery
    return result


def register_tools(mcp) -> None:
    @mcp.tool()
    def windows_dpapi_recover_masterkeys(
        protect_dir: str,
        sid: str,
        password: str | None = None,
        nt_hash: str | None = None,
        system_hive_path: str | None = None,
        security_hive_path: str | None = None,
        credhist_path: str | None = None,
    ) -> dict[str, object]:
        """Recover offline Windows DPAPI masterkeys from a Protect directory."""

        return windows_dpapi_recover_masterkeys_path(
            protect_dir,
            sid,
            password=password,
            nt_hash=nt_hash,
            system_hive_path=system_hive_path,
            security_hive_path=security_hive_path,
            credhist_path=credhist_path,
        )

    @mcp.tool()
    def windows_dpapi_decrypt_blob(
        masterkeys_by_guid: dict[str, str],
        blob_hex: str | None = None,
        blob_path: str | None = None,
        entropy_hex: str | None = None,
    ) -> dict[str, object]:
        """Decrypt a generic DPAPI blob using recovered masterkeys."""

        return windows_dpapi_decrypt_blob_path(
            masterkeys_by_guid=masterkeys_by_guid,
            blob_hex=blob_hex,
            blob_path=blob_path,
            entropy_hex=entropy_hex,
        )

    @mcp.tool()
    def windows_dpapi_recover_chromium_master_key(
        local_state_path: str,
        masterkeys_by_guid: dict[str, str] | None = None,
        protect_dir: str | None = None,
        sid: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        system_hive_path: str | None = None,
        security_hive_path: str | None = None,
        credhist_path: str | None = None,
    ) -> dict[str, object]:
        """Recover Chromium's legacy AES master key from Local State using offline DPAPI artifacts."""

        return windows_dpapi_recover_chromium_master_key_path(
            local_state_path,
            masterkeys_by_guid=masterkeys_by_guid,
            protect_dir=protect_dir,
            sid=sid,
            password=password,
            nt_hash=nt_hash,
            system_hive_path=system_hive_path,
            security_hive_path=security_hive_path,
            credhist_path=credhist_path,
        )

    @mcp.tool()
    def windows_dpapi_parse_credential_file(
        file_path: str,
        masterkeys_by_guid: dict[str, str] | None = None,
        protect_dir: str | None = None,
        sid: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        system_hive_path: str | None = None,
        security_hive_path: str | None = None,
        credhist_path: str | None = None,
    ) -> dict[str, object]:
        """Decrypt a Windows Credential Manager credential file using offline DPAPI masterkeys."""

        return windows_dpapi_parse_credential_file_path(
            file_path,
            masterkeys_by_guid=masterkeys_by_guid,
            protect_dir=protect_dir,
            sid=sid,
            password=password,
            nt_hash=nt_hash,
            system_hive_path=system_hive_path,
            security_hive_path=security_hive_path,
            credhist_path=credhist_path,
        )

    @mcp.tool()
    def windows_dpapi_parse_credentials_directory(
        directory_path: str,
        masterkeys_by_guid: dict[str, str] | None = None,
        protect_dir: str | None = None,
        sid: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        system_hive_path: str | None = None,
        security_hive_path: str | None = None,
        credhist_path: str | None = None,
    ) -> dict[str, object]:
        """Decrypt all Windows Credential Manager credential files in a directory using offline DPAPI masterkeys."""

        return windows_dpapi_parse_credentials_directory_path(
            directory_path,
            masterkeys_by_guid=masterkeys_by_guid,
            protect_dir=protect_dir,
            sid=sid,
            password=password,
            nt_hash=nt_hash,
            system_hive_path=system_hive_path,
            security_hive_path=security_hive_path,
            credhist_path=credhist_path,
        )

    @mcp.tool()
    def windows_dpapi_parse_vault_directory(
        directory_path: str,
        masterkeys_by_guid: dict[str, str] | None = None,
        protect_dir: str | None = None,
        sid: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        system_hive_path: str | None = None,
        security_hive_path: str | None = None,
        credhist_path: str | None = None,
    ) -> dict[str, object]:
        """Decrypt a Windows Vault directory using offline DPAPI masterkeys."""

        return windows_dpapi_parse_vault_directory_path(
            directory_path,
            masterkeys_by_guid=masterkeys_by_guid,
            protect_dir=protect_dir,
            sid=sid,
            password=password,
            nt_hash=nt_hash,
            system_hive_path=system_hive_path,
            security_hive_path=security_hive_path,
            credhist_path=credhist_path,
        )
