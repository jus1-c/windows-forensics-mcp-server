"""Abstract backend contracts for forensic artifact parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class BackendSpec:
    artifact_family: str
    parser_name: str
    dependency_name: str


class ParserBackend(ABC):
    spec: BackendSpec

    @abstractmethod
    def get_info(self, path: Path) -> dict[str, Any]:
        """Return artifact metadata or summary information."""


class EvtxBackend(ParserBackend, ABC):
    spec = BackendSpec("evtx", "libevtx", "libevtx-python")


class RegistryBackend(ParserBackend, ABC):
    spec = BackendSpec("registry", "libregf", "libregf-python")


class PrefetchBackend(ParserBackend, ABC):
    spec = BackendSpec("prefetch", "libscca", "libscca-python")


class LnkBackend(ParserBackend, ABC):
    spec = BackendSpec("lnk", "liblnk", "liblnk-python")


class JumpListBackend(ParserBackend, ABC):
    spec = BackendSpec("jump_list", "libolecf/liblnk", "libolecf-python")


class ShellItemBackend(ParserBackend, ABC):
    spec = BackendSpec("shell_items", "libfwsi", "libfwsi-python")


class SrumBackend(ParserBackend, ABC):
    spec = BackendSpec("srum", "libesedb", "libesedb-python")


class MftBackend(ParserBackend, ABC):
    spec = BackendSpec("mft", "libfsntfs", "libfsntfs-python")


class UsnBackend(ParserBackend, ABC):
    spec = BackendSpec("usn", "libfsntfs", "libfsntfs-python")
