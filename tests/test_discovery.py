from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.discovery import scan_directory_path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_EVIDENCE_ROOT = (REPO_ROOT / "$MFT").exists() and (REPO_ROOT / "extracted.ad1").exists()


@unittest.skipUnless(LOCAL_EVIDENCE_ROOT, "local evidence samples not available")
class DirectoryScanTests(unittest.TestCase):
    def test_scan_directory_finds_workspace_samples(self) -> None:
        result = scan_directory_path(str(REPO_ROOT), recursive=False, include_hashes=False)

        artifact_types = {entry["artifact_type"] for entry in result.entries}

        self.assertIn("mft", artifact_types)
        self.assertIn("logical_image_ad1", artifact_types)
        self.assertIn("ntfs_extend_directory", artifact_types)
        self.assertFalse(result.truncated)

    def test_scan_directory_filters_unknown_entries_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "notes.txt").write_text("hello", encoding="utf-8")

            result = scan_directory_path(str(temp_path), recursive=False)

        self.assertEqual(result.entries, [])

    def test_scan_directory_can_include_unknown_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "notes.txt").write_text("hello", encoding="utf-8")

            result = scan_directory_path(str(temp_path), recursive=False, include_unknown=True)

        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0]["artifact_type"], "unknown")
