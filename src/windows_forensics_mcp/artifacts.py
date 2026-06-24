"""Artifact detection helpers for Windows forensic files."""

from __future__ import annotations

from pathlib import Path

from windows_forensics_mcp.config import settings
from windows_forensics_mcp.schemas import ArtifactDescriptor
from windows_forensics_mcp.utils.hashing import sha256_file
from windows_forensics_mcp.utils.paths import resolve_input_path

_REGISTRY_HIVE_NAMES: dict[str, tuple[str, str, str, str, list[str]]] = {
    "software": (
        "registry_hive_software",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
            "registry_extract_artifact",
        ],
    ),
    "system": (
        "registry_hive_system",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
            "registry_extract_artifact",
        ],
    ),
    "sam": (
        "registry_hive_sam",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
        ],
    ),
    "security": (
        "registry_hive_security",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
        ],
    ),
    "default": (
        "registry_hive_default",
        "registry",
        "registry name",
        "registry",
        ["registry_hive_info", "registry_list_keys", "registry_get_values"],
    ),
    "ntuser.dat": (
        "registry_hive_ntuser",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
            "registry_extract_artifact",
        ],
    ),
    "usrclass.dat": (
        "registry_hive_usrclass",
        "registry",
        "registry name",
        "registry",
        [
            "registry_hive_info",
            "registry_list_keys",
            "registry_get_values",
            "registry_search",
            "registry_extract_artifact",
        ],
    ),
}

_REGISTRY_LOG_SUFFIXES = {
    ".log1": "registry_transaction_log",
    ".log2": "registry_transaction_log",
    ".regtrans-ms": "registry_transaction_log",
    ".tm.blf": "registry_transaction_log",
}

_SUFFIX_RULES: dict[str, tuple[str, str, str | None, list[str]]] = {
    ".ad1": ("logical_image_ad1", "logical_image", None, ["artifact_identify", "scan_directory"]),
    ".automaticdestinations-ms": (
        "jump_list_automatic",
        "jump_list",
        "jump_list",
        ["jumplist_parse", "jumplist_directory_summary"],
    ),
    ".customdestinations-ms": (
        "jump_list_custom",
        "jump_list",
        "jump_list",
        ["jumplist_parse", "jumplist_directory_summary"],
    ),
    ".evtx": (
        "evtx",
        "evtx",
        "evtx",
        ["evtx_info", "evtx_list_records", "evtx_search", "evtx_timeline"],
    ),
    ".lnk": (
        "lnk",
        "lnk",
        "lnk",
        ["lnk_parse", "lnk_directory_summary", "shellitems_parse"],
    ),
    ".pf": (
        "prefetch",
        "prefetch",
        "prefetch",
        ["prefetch_parse", "prefetch_directory_summary", "prefetch_timeline"],
    ),
}


def _directory_descriptor(path: Path) -> ArtifactDescriptor:
    lowered_name = path.name.lower()
    artifact_type = "directory"
    artifact_family = "directory"
    detected_from = "directory"
    parser_hint = None
    supported_tools: list[str] = ["scan_directory"]
    confidence = 0.6

    if lowered_name == "$extend":
        artifact_type = "ntfs_extend_directory"
        artifact_family = "ntfs_metadata"
        detected_from = "directory name"
        parser_hint = "usn"
        supported_tools = ["usn_parse", "usn_timeline"]
        confidence = 0.95
    elif lowered_name == "prefetch":
        artifact_type = "prefetch_directory"
        artifact_family = "prefetch"
        detected_from = "directory name"
        parser_hint = "prefetch"
        supported_tools = ["prefetch_directory_summary", "prefetch_timeline"]
        confidence = 0.95
    elif lowered_name == "logs" and any(part.lower() == "winevt" for part in path.parts):
        artifact_type = "evtx_directory"
        artifact_family = "evtx"
        detected_from = "directory context"
        parser_hint = "evtx"
        supported_tools = ["scan_directory"]
        confidence = 0.8
    elif lowered_name == "config" and any(part.lower() == "system32" for part in path.parts):
        artifact_type = "registry_hive_directory"
        artifact_family = "registry"
        detected_from = "directory context"
        parser_hint = "registry"
        supported_tools = ["scan_directory"]
        confidence = 0.8

    return ArtifactDescriptor(
        artifact_type=artifact_type,
        artifact_family=artifact_family,
        confidence=confidence,
        detected_from=detected_from,
        parser_hint=parser_hint,
        supported_tools=supported_tools,
        source_path=str(path),
        name=path.name,
        exists=True,
        is_directory=True,
        size=None,
    )


def identify_artifact(path: Path, include_hash: bool = True) -> ArtifactDescriptor:
    if path.is_dir():
        return _directory_descriptor(path)

    lowered_name = path.name.lower()
    suffix = path.suffix.lower()

    if lowered_name == "$mft":
        descriptor = ArtifactDescriptor(
            artifact_type="mft",
            artifact_family="ntfs_metadata",
            confidence=1.0,
            detected_from="filename",
            parser_hint="mft",
            supported_tools=["mft_parse", "mft_search_records", "mft_timeline"],
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    elif lowered_name in {"$usnjrnl", "$j"}:
        descriptor = ArtifactDescriptor(
            artifact_type="usn_journal",
            artifact_family="ntfs_metadata",
            confidence=1.0,
            detected_from="filename",
            parser_hint="usn",
            supported_tools=["usn_parse", "usn_timeline"],
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    elif lowered_name == "srudb.dat":
        descriptor = ArtifactDescriptor(
            artifact_type="srum_database",
            artifact_family="srum",
            confidence=1.0,
            detected_from="filename",
            parser_hint="srum",
            supported_tools=["srum_parse", "srum_extract_app_usage", "srum_extract_network_usage"],
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    elif lowered_name in _REGISTRY_HIVE_NAMES:
        artifact_type, artifact_family, detected_from, parser_hint, supported_tools = _REGISTRY_HIVE_NAMES[lowered_name]
        descriptor = ArtifactDescriptor(
            artifact_type=artifact_type,
            artifact_family=artifact_family,
            confidence=1.0,
            detected_from=detected_from,
            parser_hint=parser_hint,
            supported_tools=supported_tools,
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    elif suffix in _REGISTRY_LOG_SUFFIXES:
        descriptor = ArtifactDescriptor(
            artifact_type=_REGISTRY_LOG_SUFFIXES[suffix],
            artifact_family="registry",
            confidence=0.95,
            detected_from="suffix",
            parser_hint="registry",
            supported_tools=["registry_hive_info"],
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    elif suffix in _SUFFIX_RULES:
        artifact_type, artifact_family, parser_hint, supported_tools = _SUFFIX_RULES[suffix]
        descriptor = ArtifactDescriptor(
            artifact_type=artifact_type,
            artifact_family=artifact_family,
            confidence=0.95,
            detected_from="suffix",
            parser_hint=parser_hint,
            supported_tools=supported_tools,
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )
    else:
        descriptor = ArtifactDescriptor(
            artifact_type="unknown",
            artifact_family="unknown",
            confidence=0.0,
            detected_from="none",
            parser_hint=None,
            supported_tools=[],
            source_path=str(path),
            name=path.name,
            exists=True,
            is_directory=False,
            size=path.stat().st_size,
        )

    if include_hash and not descriptor.is_directory:
        descriptor.sha256 = sha256_file(path, chunk_size=settings.hash_chunk_size)

    if descriptor.artifact_type == "usn_journal" and descriptor.size == 0:
        descriptor.warnings.append(
            "USN journal sample is empty; positive parsing tests will need a non-empty $J export"
        )

    return descriptor


def identify_artifact_path(raw_path: str, include_hash: bool = True) -> ArtifactDescriptor:
    return identify_artifact(resolve_input_path(raw_path), include_hash=include_hash)
