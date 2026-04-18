"""JSON-friendly dataclasses returned by tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ArtifactDescriptor:
    artifact_type: str
    artifact_family: str
    confidence: float
    detected_from: str
    parser_hint: str | None
    supported_tools: list[str]
    source_path: str
    name: str
    exists: bool
    is_directory: bool
    size: int | None
    sha256: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DirectoryScanResult:
    root_path: str
    recursive: bool
    include_hashes: bool
    include_unknown: bool
    scanned_entries: int
    returned_entries: int
    truncated: bool
    entries: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
