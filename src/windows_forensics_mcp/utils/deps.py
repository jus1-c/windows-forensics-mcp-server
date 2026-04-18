"""Optional dependency loading helpers."""

from __future__ import annotations

import importlib
from types import ModuleType

from windows_forensics_mcp.errors import OptionalDependencyError


def require_module(module_name: str, package_name: str | None = None) -> ModuleType:
    """Import a module and raise a user-facing dependency error on failure."""

    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        package_hint = package_name or module_name
        raise OptionalDependencyError(
            f"Missing optional dependency '{package_hint}'. Install the project dependencies in the active environment."
        ) from exc
