"""Path normalization and validation helpers."""

from __future__ import annotations

import os
from pathlib import Path

from windows_forensics_mcp.errors import ArtifactPathError


def resolve_input_path(raw_path: str) -> Path:
    if not raw_path or not raw_path.strip():
        raise ArtifactPathError("Path must be a non-empty string")

    expanded = Path(os.path.expandvars(raw_path)).expanduser()
    if not expanded.exists():
        raise ArtifactPathError(f"Path does not exist: {raw_path}")

    return expanded.resolve()


def ensure_file(path: Path) -> Path:
    if not path.is_file():
        raise ArtifactPathError(f"Expected a file path, received: {path}")
    return path


def ensure_directory(path: Path) -> Path:
    if not path.is_dir():
        raise ArtifactPathError(f"Expected a directory path, received: {path}")
    return path
