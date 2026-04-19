"""Custom error types used by the server."""

from __future__ import annotations


class WindowsForensicsError(Exception):
    """Base exception for server-specific failures."""

    code = "windows_forensics_error"

    def to_payload(self) -> dict[str, str]:
        return {
            "error": self.code,
            "message": str(self),
        }


class ArtifactPathError(WindowsForensicsError):
    code = "artifact_path_error"


class OptionalDependencyError(WindowsForensicsError):
    code = "optional_dependency_error"


class UnsupportedArtifactError(WindowsForensicsError):
    code = "unsupported_artifact_error"


class ToolInputError(WindowsForensicsError):
    code = "tool_input_error"


class DecryptionError(WindowsForensicsError):
    code = "decryption_error"
