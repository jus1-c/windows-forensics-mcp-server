from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.jumplist import jumplist_parse_path
from windows_forensics_mcp.tools.lnk import lnk_parse_path, shellitems_parse_path

REPO_ROOT = Path(__file__).resolve().parents[1]
LNK_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "lnk" / "microsoft_edge_taskbar.lnk"
AUTO_JUMPLIST_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "jumplist" / "f01b4d95cf55d32a.automaticDestinations-ms"
CUSTOM_JUMPLIST_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "jumplist" / "590aee7bdd69b59b.customDestinations-ms"


@unittest.skipUnless(
    LNK_SAMPLE.exists() and AUTO_JUMPLIST_SAMPLE.exists() and CUSTOM_JUMPLIST_SAMPLE.exists(),
    "LNK or Jump List fixtures not available",
)
class LnkAndJumpListToolTests(unittest.TestCase):
    def test_lnk_parse_reads_sample(self) -> None:
        parsed = lnk_parse_path(str(LNK_SAMPLE))

        self.assertIn("msedge.exe", parsed["local_path"].lower())
        self.assertGreater(len(parsed["shell_items"]), 0)

    def test_shellitems_parse_reads_embedded_items(self) -> None:
        parsed = shellitems_parse_path(str(LNK_SAMPLE))

        self.assertGreater(parsed["shell_item_count"], 0)

    def test_automatic_jumplist_parse_reads_entries(self) -> None:
        parsed = jumplist_parse_path(str(AUTO_JUMPLIST_SAMPLE))

        self.assertEqual(parsed["jumplist_type"], "automatic")
        self.assertGreater(parsed["entry_count"], 0)

    def test_automatic_jumplist_parses_destlist(self) -> None:
        parsed = jumplist_parse_path(str(AUTO_JUMPLIST_SAMPLE))

        destlist = parsed["destlist"]
        self.assertIsNotNone(destlist)
        self.assertIsNotNone(destlist["version"])
        self.assertGreater(len(destlist["entries"]), 0)
        first = destlist["entries"][0]
        self.assertIn("mru_position", first)
        self.assertIn("last_access_time", first)
        self.assertIn("is_pinned", first)
        self.assertIn("path", first)

    def test_custom_jumplist_parse_reads_entries(self) -> None:
        parsed = jumplist_parse_path(str(CUSTOM_JUMPLIST_SAMPLE))

        self.assertEqual(parsed["jumplist_type"], "custom")
        self.assertGreater(parsed["entry_count"], 0)
