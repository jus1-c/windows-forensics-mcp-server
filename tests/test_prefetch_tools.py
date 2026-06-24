from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.prefetch import prefetch_parse_path, prefetch_timeline_path

REPO_ROOT = Path(__file__).resolve().parents[1]
PREFETCH_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "prefetch" / "POWERSHELL.EXE-022A1004.pf"


@unittest.skipUnless(PREFETCH_SAMPLE.exists(), "prefetch fixture not available")
class PrefetchToolTests(unittest.TestCase):
    def test_prefetch_parse_reads_sample(self) -> None:
        parsed = prefetch_parse_path(str(PREFETCH_SAMPLE), filename_limit=20)

        self.assertEqual(parsed["executable_filename"], "POWERSHELL.EXE")
        self.assertGreater(parsed["run_count"], 0)
        self.assertTrue(parsed["last_run_times"])

    def test_prefetch_timeline_contains_events(self) -> None:
        timeline = prefetch_timeline_path(str(PREFETCH_SAMPLE), limit=10)

        self.assertTrue(timeline["timeline"])
