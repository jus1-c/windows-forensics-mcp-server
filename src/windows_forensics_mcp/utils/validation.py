"""Validation helpers for tool input bounds (limit/offset/depth/etc.)."""

from windows_forensics_mcp.errors import ToolInputError

# Upper bounds to keep result sizes and traversal cost bounded. These are
# generous defaults that still protect against pathological inputs (e.g. a
# negative or multi-million ``limit`` that would otherwise crash islice or
# exhaust memory).
MAX_LIMIT = 100_000
MAX_OFFSET = 100_000_000
MAX_DEPTH = 64


def validate_limit(limit: int, *, parameter: str = "limit", maximum: int = MAX_LIMIT) -> int:
    """Validate a positive result-count limit.

    Raises ToolInputError for non-integer, zero, or negative values, and clamps
    to ``maximum`` to keep result sizes bounded.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ToolInputError(f"{parameter} must be an integer")
    if limit <= 0:
        raise ToolInputError(f"{parameter} must be greater than zero")
    return min(limit, maximum)


def validate_offset(offset: int, *, parameter: str = "offset", maximum: int = MAX_OFFSET) -> int:
    """Validate a non-negative offset.

    Raises ToolInputError for non-integer or negative values, and clamps to
    ``maximum``.
    """
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ToolInputError(f"{parameter} must be an integer")
    if offset < 0:
        raise ToolInputError(f"{parameter} must be zero or greater")
    return min(offset, maximum)


def validate_depth(depth: int, *, parameter: str = "depth", maximum: int = MAX_DEPTH) -> int:
    """Validate a non-negative traversal depth, clamped to ``maximum``."""
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise ToolInputError(f"{parameter} must be an integer")
    if depth < 0:
        raise ToolInputError(f"{parameter} must be zero or greater")
    return min(depth, maximum)


def validate_count(value: int, *, parameter: str, maximum: int = MAX_LIMIT) -> int:
    """Validate a positive count parameter (e.g. sample sizes), clamped to ``maximum``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolInputError(f"{parameter} must be an integer")
    if value <= 0:
        raise ToolInputError(f"{parameter} must be greater than zero")
    return min(value, maximum)
