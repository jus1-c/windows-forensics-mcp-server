from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.jumplist import _parse_destlist_stream
from windows_forensics_mcp.tools.srum import _decode_sid, _decode_srum_blob


class SrumSidDecodeTests(unittest.TestCase):
    def test_well_known_sid_decodes(self) -> None:
        # S-1-5-18 (Local System): revision 1, 1 sub-authority.
        blob = bytes([1, 1]) + (5).to_bytes(6, "big") + (18).to_bytes(4, "little")
        self.assertEqual(_decode_sid(blob), "S-1-5-18")

    def test_utf16_path_is_not_misread_as_sid(self) -> None:
        # A UTF-16 path blob must decode as text, not a bogus SID.
        text = "C:\\Program Files\\app.exe"
        blob = text.encode("utf-16-le")
        self.assertIsNone(_decode_sid(blob))
        self.assertEqual(_decode_srum_blob(blob), text)

    def test_decode_sid_rejects_wrong_revision(self) -> None:
        blob = bytes([2, 1]) + (5).to_bytes(6, "big") + (18).to_bytes(4, "little")
        self.assertIsNone(_decode_sid(blob))

    def test_decode_sid_rejects_length_mismatch(self) -> None:
        # Claims 2 sub-authorities but only provides one.
        blob = bytes([1, 2]) + (5).to_bytes(6, "big") + (18).to_bytes(4, "little")
        self.assertIsNone(_decode_sid(blob))


def _build_destlist_v4(entries: list[tuple[int, str]], pinned: int) -> bytes:
    header = struct.pack("<III", 4, len(entries), pinned) + b"\x00" * 20
    body = b""
    for entry_number, path in entries:
        encoded = path.encode("utf-16-le")
        prefix = bytearray(0x80)
        prefix[0x48:0x48 + 9] = b"testhost\x00"
        struct.pack_into("<I", prefix, 0x58, entry_number)
        # Leave the FILETIME at 0x64 as zero -> decodes to None.
        body += bytes(prefix)
        body += struct.pack("<H", len(path))
        body += encoded
        body += b"\x00\x00\x00\x00"  # 4-byte trailer
    return header + body


class DestListParserTests(unittest.TestCase):
    def test_parses_synthetic_v4_stream(self) -> None:
        data = _build_destlist_v4([(1, "C:\\a.txt"), (2, "C:\\b.txt")], pinned=1)
        result = _parse_destlist_stream(data)

        self.assertEqual(result["version"], 4)
        self.assertEqual(result["total_entries"], 2)
        self.assertEqual(result["pinned_entries"], 1)
        self.assertEqual(len(result["entries"]), 2)

        first = result["entries"][0]
        self.assertEqual(first["entry_number"], 1)
        self.assertEqual(first["stream_name"], "1")
        self.assertEqual(first["path"], "C:\\a.txt")
        self.assertEqual(first["hostname"], "testhost")
        self.assertTrue(first["is_pinned"])
        self.assertFalse(result["entries"][1]["is_pinned"])

    def test_empty_stream_returns_no_entries(self) -> None:
        result = _parse_destlist_stream(b"")
        self.assertEqual(result["entries"], [])
        self.assertIsNone(result["version"])

    def test_unsupported_version_warns(self) -> None:
        data = struct.pack("<III", 99, 1, 0) + b"\x00" * 20
        result = _parse_destlist_stream(data)
        self.assertEqual(result["version"], 99)
        self.assertEqual(result["entries"], [])
        self.assertTrue(result["warnings"])


if __name__ == "__main__":
    unittest.main()
