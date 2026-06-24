from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.artifacts import identify_artifact_path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_EVIDENCE_ROOT = (REPO_ROOT / "$MFT").exists() and (REPO_ROOT / "extracted.ad1").exists()


@unittest.skipUnless(LOCAL_EVIDENCE_ROOT, "local evidence samples not available")
class ArtifactIdentificationTests(unittest.TestCase):
    def test_identifies_exported_mft_sample(self) -> None:
        descriptor = identify_artifact_path(str(REPO_ROOT / "$MFT"), include_hash=False)

        self.assertEqual(descriptor.artifact_type, "mft")
        self.assertEqual(descriptor.artifact_family, "ntfs_metadata")
        self.assertEqual(descriptor.parser_hint, "mft")

    def test_identifies_ad1_sample(self) -> None:
        descriptor = identify_artifact_path(str(REPO_ROOT / "extracted.ad1"), include_hash=False)

        self.assertEqual(descriptor.artifact_type, "logical_image_ad1")
        self.assertEqual(descriptor.artifact_family, "logical_image")

    def test_identifies_exported_empty_usn_sample(self) -> None:
        descriptor = identify_artifact_path(str(REPO_ROOT / "$Extend" / "$UsnJrnl"), include_hash=False)

        self.assertEqual(descriptor.artifact_type, "usn_journal")
        self.assertTrue(descriptor.warnings)

    def test_identifies_registry_hive_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            hive_path = Path(temp_dir) / "SOFTWARE"
            hive_path.write_bytes(b"test")

            descriptor = identify_artifact_path(str(hive_path), include_hash=False)

        self.assertEqual(descriptor.artifact_type, "registry_hive_software")
        self.assertEqual(descriptor.artifact_family, "registry")

    def test_unknown_file_stays_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            other_path = Path(temp_dir) / "notes.txt"
            other_path.write_text("hello", encoding="utf-8")

            descriptor = identify_artifact_path(str(other_path), include_hash=False)

        self.assertEqual(descriptor.artifact_type, "unknown")
        self.assertEqual(descriptor.supported_tools, [])
