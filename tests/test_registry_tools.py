from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.registry import (
    registry_extract_artifact_path,
    registry_get_values_path,
    registry_hive_info_path,
    registry_list_keys_path,
    registry_search_path,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
NTUSER_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "registry" / "NTUSER.DAT"
SYSTEM_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "registry" / "SYSTEM"
AMCACHE_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "registry" / "Amcache.hve"


@unittest.skipUnless(NTUSER_SAMPLE.exists(), "registry fixture not available")
class RegistryToolTests(unittest.TestCase):
    def test_registry_hive_info_reads_sample(self) -> None:
        info = registry_hive_info_path(str(NTUSER_SAMPLE))

        self.assertEqual(info["root_key"]["name"], "ROOT")
        self.assertEqual(info["logical_hive_name"], "HKEY_CURRENT_USER")

    def test_registry_list_keys_returns_explorer_subkeys(self) -> None:
        result = registry_list_keys_path(
            str(NTUSER_SAMPLE),
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer",
            depth=1,
        )

        self.assertGreater(len(result["keys"]), 1)

    def test_registry_list_keys_rejects_negative_depth(self) -> None:
        from windows_forensics_mcp.errors import ToolInputError

        with self.assertRaises(ToolInputError):
            registry_list_keys_path(str(NTUSER_SAMPLE), depth=-1)

    def test_registry_get_values_reads_userassist_count(self) -> None:
        result = registry_get_values_path(
            str(NTUSER_SAMPLE),
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}",
        )

        self.assertGreater(len(result["values"]), 0)

    def test_registry_search_finds_userassist(self) -> None:
        result = registry_search_path(str(NTUSER_SAMPLE), pattern="UserAssist", scope="keys", max_results=5)

        self.assertGreater(result["match_count"], 0)

    def test_registry_extract_userassist_returns_entries(self) -> None:
        result = registry_extract_artifact_path(str(NTUSER_SAMPLE), "userassist")

        self.assertGreater(result["entry_count"], 0)

    def test_registry_extract_unsupported_raises(self) -> None:
        from windows_forensics_mcp.errors import UnsupportedArtifactError

        with self.assertRaises(UnsupportedArtifactError):
            registry_extract_artifact_path(str(NTUSER_SAMPLE), "definitely_not_supported")


@unittest.skipUnless(SYSTEM_SAMPLE.exists(), "SYSTEM hive fixture not available")
class RegistrySystemExtractorTests(unittest.TestCase):
    def test_shimcache_decodes_entries(self) -> None:
        result = registry_extract_artifact_path(str(SYSTEM_SAMPLE), "shimcache")

        self.assertEqual(result["entry_count"], 1)
        cache = result["entries"][0]
        self.assertIn("AppCompatCache", cache["key_path"])
        self.assertGreater(len(cache["entries"]), 0)
        first = cache["entries"][0]
        self.assertIn("path", first)
        self.assertIn("last_modified_time", first)

    def test_usbstor_returns_structure(self) -> None:
        # The fixture VM has no USB devices; the extractor must still return a
        # well-formed (possibly empty) result rather than raising.
        result = registry_extract_artifact_path(str(SYSTEM_SAMPLE), "usbstor")

        self.assertEqual(result["artifact_type"], "usbstor")
        self.assertIsInstance(result["entries"], list)


@unittest.skipUnless(AMCACHE_SAMPLE.exists(), "Amcache hive fixture not available")
class RegistryAmcacheExtractorTests(unittest.TestCase):
    def test_amcache_returns_program_entries(self) -> None:
        result = registry_extract_artifact_path(str(AMCACHE_SAMPLE), "amcache")

        self.assertGreater(result["entry_count"], 0)
        first = result["entries"][0]
        self.assertIn("key_name", first)
        self.assertIn("values", first)
