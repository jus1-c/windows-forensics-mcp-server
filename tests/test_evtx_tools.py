from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.evtx import (
    evtx_detect_security_events_path,
    evtx_info_path,
    evtx_list_records_path,
    evtx_search_path,
    evtx_timeline_path,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EVTX_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "evtx" / "powershell_operational.evtx"


@unittest.skipUnless(EVTX_SAMPLE.exists(), "EVTX fixture not available")
class EvtxToolTests(unittest.TestCase):
    def test_evtx_info_reads_sample(self) -> None:
        info = evtx_info_path(str(EVTX_SAMPLE))

        self.assertEqual(info["record_source"], "recovered_records")
        self.assertGreater(info["recovered_record_count"], 0)
        self.assertTrue(info["sample_records"])

    def test_evtx_list_records_returns_entries(self) -> None:
        result = evtx_list_records_path(str(EVTX_SAMPLE), limit=5)

        self.assertEqual(len(result["records"]), 5)
        self.assertEqual(result["records"][0]["provider"], "Microsoft-Windows-PowerShell")

    def test_evtx_search_matches_provider(self) -> None:
        result = evtx_search_path(str(EVTX_SAMPLE), provider_contains="powershell", limit=3)

        self.assertGreater(result["match_count"], 0)

    def test_evtx_timeline_contains_events(self) -> None:
        result = evtx_timeline_path(str(EVTX_SAMPLE), limit=5)

        self.assertEqual(len(result["timeline"]), 5)

    def test_evtx_detect_security_events_returns_matches(self) -> None:
        result = evtx_detect_security_events_path(str(EVTX_SAMPLE), profile="powershell", limit=5)

        self.assertGreater(result["match_count"], 0)
