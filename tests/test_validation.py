from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.errors import ToolInputError
from windows_forensics_mcp.utils.validation import (
    MAX_DEPTH,
    MAX_LIMIT,
    validate_count,
    validate_depth,
    validate_limit,
    validate_offset,
)


class ValidationHelperTests(unittest.TestCase):
    def test_validate_limit_accepts_positive(self) -> None:
        self.assertEqual(validate_limit(10), 10)

    def test_validate_limit_clamps_to_maximum(self) -> None:
        self.assertEqual(validate_limit(MAX_LIMIT + 1000), MAX_LIMIT)

    def test_validate_limit_rejects_zero(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_limit(0)

    def test_validate_limit_rejects_negative(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_limit(-5)

    def test_validate_limit_rejects_bool(self) -> None:
        # bool is an int subclass; it must be rejected explicitly.
        with self.assertRaises(ToolInputError):
            validate_limit(True)

    def test_validate_offset_accepts_zero(self) -> None:
        self.assertEqual(validate_offset(0), 0)

    def test_validate_offset_rejects_negative(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_offset(-1)

    def test_validate_depth_clamps(self) -> None:
        self.assertEqual(validate_depth(MAX_DEPTH + 50), MAX_DEPTH)

    def test_validate_depth_accepts_zero(self) -> None:
        self.assertEqual(validate_depth(0), 0)

    def test_validate_count_rejects_zero(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_count(0, parameter="sample_per_table")

    def test_validate_count_accepts_positive(self) -> None:
        self.assertEqual(validate_count(3, parameter="sample_per_table"), 3)


if __name__ == "__main__":
    unittest.main()
