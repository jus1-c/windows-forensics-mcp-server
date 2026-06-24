from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.mft import mft_parse_path, mft_search_records_path, mft_timeline_path
from windows_forensics_mcp.tools.srum import srum_extract_app_usage_path, srum_parse_path
from windows_forensics_mcp.tools.usn import usn_parse_path, usn_timeline_path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRUM_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "srum" / "SRUDB.dat"
MFT_SAMPLE = REPO_ROOT / "$MFT"
USN_SAMPLE = REPO_ROOT / "$Extend" / "$UsnJrnl"


@unittest.skipUnless(
    SRUM_SAMPLE.exists() and MFT_SAMPLE.exists() and USN_SAMPLE.exists(),
    "SRUM, MFT, or USN fixtures not available",
)
class SrumMftUsnToolTests(unittest.TestCase):
    def test_srum_parse_reads_tables(self) -> None:
        parsed = srum_parse_path(str(SRUM_SAMPLE), sample_per_table=1)

        self.assertGreater(parsed["table_count"], 0)

    def test_srum_extract_app_usage_returns_rows(self) -> None:
        parsed = srum_extract_app_usage_path(str(SRUM_SAMPLE), limit=5)

        self.assertGreater(parsed["row_count"], 0)

    def test_mft_parse_reads_segments(self) -> None:
        parsed = mft_parse_path(str(MFT_SAMPLE), limit=5)

        self.assertEqual(len(parsed["records"]), 5)
        self.assertEqual(parsed["records"][0]["segment"], 0)

    def test_mft_search_finds_mft_record(self) -> None:
        parsed = mft_search_records_path(str(MFT_SAMPLE), name_contains="$MFT", limit=5, scan_limit=2000)

        self.assertGreater(parsed["match_count"], 0)

    def test_mft_timeline_contains_events(self) -> None:
        parsed = mft_timeline_path(str(MFT_SAMPLE), limit=5)

        self.assertTrue(parsed["timeline"])

    def test_usn_parse_handles_empty_journal(self) -> None:
        parsed = usn_parse_path(str(USN_SAMPLE), limit=5)

        self.assertEqual(parsed["record_count"], 0)
        self.assertTrue(parsed["warnings"])

    def test_usn_timeline_handles_empty_journal(self) -> None:
        parsed = usn_timeline_path(str(USN_SAMPLE), limit=5)

        self.assertEqual(parsed["timeline"], [])
