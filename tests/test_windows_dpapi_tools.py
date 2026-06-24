from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from windows_forensics_mcp.tools.windows_dpapi import (  # noqa: E402
    windows_dpapi_decrypt_blob_path,
    windows_dpapi_parse_credential_file_path,
    windows_dpapi_parse_credentials_directory_path,
    windows_dpapi_parse_vault_directory_path,
    windows_dpapi_recover_chromium_master_key_path,
    windows_dpapi_recover_masterkeys_path,
)

FAKE_GUID = "11111111-1111-1111-1111-111111111111"
FAKE_MASTERKEY = b"\xaa" * 32


def write_preferred_file(protect_dir: Path, guid: str) -> None:
    preferred_path = protect_dir / "Preferred"
    preferred_path.write_bytes(uuid.UUID(guid).bytes_le + b"\x00" * 8)


class FakeMasterKeyFile:
    def __init__(self, guid: str, key: bytes):
        self.guid = guid.encode("utf-8")
        self._key = key
        self.masterkey = type("Master", (), {"decrypted": False})()
        self.backupkey = type("Backup", (), {"decrypted": False})()

    def get_key(self) -> bytes:
        return self._key


class FakeMasterKeyPool:
    def __init__(self):
        self.keys: dict[str, list[FakeMasterKeyFile]] = {}
        self.system_blob = None
        self.credhist = None

    def loadDirectory(self, directory: str) -> None:
        del directory
        self.keys = {FAKE_GUID: [FakeMasterKeyFile(FAKE_GUID, FAKE_MASTERKEY)]}

    def addCredhistFile(self, sid: str, credfile: str) -> None:
        self.credhist = (sid, credfile)

    def addSystemCredential(self, blob: bytes) -> None:
        self.system_blob = blob

    def try_credential(self, sid: str, password: str | None) -> int:
        del sid
        if password == "":
            self.keys[FAKE_GUID][0].masterkey.decrypted = True
            return 1
        return 0

    def try_credential_hash(self, sid: str, pwdhash: bytes | None) -> int:
        del sid
        if pwdhash == bytes.fromhex("11" * 16) or (pwdhash is None and self.system_blob):
            self.keys[FAKE_GUID][0].masterkey.decrypted = True
            return 1
        return 0


class FakeRegedit:
    def get_lsa_secrets(self, security: str, system: str):
        del security, system
        return {"DPAPI_SYSTEM": {"CurrVal": b"\x01" + b"\x02" * 40}}


class FakeDPAPIBlob:
    cleartexts = {
        b"blob-data": b"secret-text",
        b"chromium-key-blob": b"\x10" * 32,
    }

    def __init__(self, raw: bytes):
        self.raw = raw
        self.mkguid = FAKE_GUID
        self.cleartext = None

    def decrypt(self, masterkey: bytes, entropy: bytes | None = None):
        if masterkey != FAKE_MASTERKEY:
            return False
        if entropy is not None and entropy != b"\x01\x02":
            return False
        self.cleartext = self.cleartexts.get(self.raw)
        return self.cleartext is not None


class FakePypykatzDPAPI:
    def __init__(self):
        self.masterkeys: dict[str, bytes] = {}
        self.vault_keys: list[bytes] = []

    def decrypt_credential_file(self, file_path: str):
        return {
            "file_path": file_path,
            "user": "analyst",
            "secret": b"credential-secret",
        }

    def decrypt_vpol_file(self, file_path: str):
        del file_path
        self.vault_keys = [b"\x01" * 16, b"\x02" * 16]
        return tuple(self.vault_keys)

    def decrypt_vcrd_file(self, file_path: str):
        return {
            type("Attr", (), {"id": 1, "name": Path(file_path).name})(): [b"vault-secret"]
        }


class FakePypykatzDPAPIDirectory(FakePypykatzDPAPI):
    def decrypt_credential_file(self, file_path: str):
        if Path(file_path).name == "broken.cred":
            raise ValueError("broken credential")
        return super().decrypt_credential_file(file_path)


class WindowsDpapiToolTests(unittest.TestCase):
    @patch("windows_forensics_mcp.tools.windows_dpapi._require_dpapick3")
    def test_recover_masterkeys_returns_keys_and_metadata(self, require_dpapick3) -> None:
        require_dpapick3.return_value = (FakeDPAPIBlob, FakeMasterKeyPool, FakeRegedit)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            protect_dir = root / "Protect"
            protect_dir.mkdir()
            (protect_dir / FAKE_GUID).write_bytes(b"masterkey")
            write_preferred_file(protect_dir, FAKE_GUID)
            system_hive = root / "SYSTEM"
            security_hive = root / "SECURITY"
            credhist = root / "CREDHIST"
            system_hive.write_bytes(b"system")
            security_hive.write_bytes(b"security")
            credhist.write_bytes(b"credhist")

            result = windows_dpapi_recover_masterkeys_path(
                str(protect_dir),
                "S-1-5-21-test-500",
                password="",
                system_hive_path=str(system_hive),
                security_hive_path=str(security_hive),
                credhist_path=str(credhist),
            )

        self.assertEqual(result["preferred_guid"], FAKE_GUID)
        self.assertEqual(result["recovered_masterkey_count"], 1)
        self.assertEqual(result["masterkeys_by_guid"][FAKE_GUID], FAKE_MASTERKEY.hex())
        self.assertTrue(result["system_credential_loaded"])
        self.assertTrue(result["credhist_loaded"])

    @patch("windows_forensics_mcp.tools.windows_dpapi._require_dpapick3")
    def test_decrypt_blob_uses_matching_guid(self, require_dpapick3) -> None:
        require_dpapick3.return_value = (FakeDPAPIBlob, FakeMasterKeyPool, FakeRegedit)

        result = windows_dpapi_decrypt_blob_path(
            masterkeys_by_guid={FAKE_GUID: FAKE_MASTERKEY.hex()},
            blob_hex=b"blob-data".hex(),
            entropy_hex="0102",
        )

        self.assertEqual(result["masterkey_guid"], FAKE_GUID)
        self.assertEqual(result["cleartext_utf8"], "secret-text")

    @patch("windows_forensics_mcp.tools.windows_dpapi._require_dpapick3")
    def test_recover_chromium_master_key_detects_app_bound(self, require_dpapick3) -> None:
        require_dpapick3.return_value = (FakeDPAPIBlob, FakeMasterKeyPool, FakeRegedit)

        with tempfile.TemporaryDirectory() as temp_dir:
            local_state_path = Path(temp_dir) / "Local State"
            local_state_path.write_text(
                json.dumps(
                    {
                        "os_crypt": {
                            "encrypted_key": base64.b64encode(b"DPAPI" + b"chromium-key-blob").decode(
                                "ascii"
                            ),
                            "app_bound_encrypted_key": base64.b64encode(b"APPBv20").decode(
                                "ascii"
                            ),
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = windows_dpapi_recover_chromium_master_key_path(
                str(local_state_path),
                masterkeys_by_guid={FAKE_GUID: FAKE_MASTERKEY.hex()},
            )

        self.assertTrue(result["encrypted_key_present"])
        self.assertTrue(result["app_bound_encrypted_key_present"])
        self.assertTrue(result["v20_detected"])
        self.assertEqual(result["master_key_b64"], base64.b64encode(b"\x10" * 32).decode("ascii"))

    @patch("windows_forensics_mcp.tools.windows_dpapi._require_pypykatz_dpapi")
    def test_parse_credential_file_uses_masterkeys(self, require_pypykatz_dpapi) -> None:
        require_pypykatz_dpapi.return_value = FakePypykatzDPAPI

        with tempfile.TemporaryDirectory() as temp_dir:
            credential_path = Path(temp_dir) / "credential.bin"
            credential_path.write_bytes(b"credential")

            result = windows_dpapi_parse_credential_file_path(
                str(credential_path),
                masterkeys_by_guid={FAKE_GUID: FAKE_MASTERKEY.hex()},
            )

        self.assertEqual(result["masterkey_count"], 1)
        self.assertEqual(result["credential"]["user"], "analyst")
        self.assertEqual(result["credential"]["secret"]["utf8"], "credential-secret")

    @patch("windows_forensics_mcp.tools.windows_dpapi._require_pypykatz_dpapi")
    def test_parse_credentials_directory_returns_records_and_warnings(self, require_pypykatz_dpapi) -> None:
        require_pypykatz_dpapi.return_value = FakePypykatzDPAPIDirectory

        with tempfile.TemporaryDirectory() as temp_dir:
            credentials_dir = Path(temp_dir) / "Credentials"
            credentials_dir.mkdir()
            (credentials_dir / "good1.cred").write_bytes(b"one")
            (credentials_dir / "good2.cred").write_bytes(b"two")
            (credentials_dir / "broken.cred").write_bytes(b"broken")

            result = windows_dpapi_parse_credentials_directory_path(
                str(credentials_dir),
                masterkeys_by_guid={FAKE_GUID: FAKE_MASTERKEY.hex()},
            )

        self.assertEqual(result["file_count"], 3)
        self.assertEqual(result["parsed_count"], 2)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("broken.cred", result["warnings"][0])

    @patch("windows_forensics_mcp.tools.windows_dpapi._require_pypykatz_dpapi")
    def test_parse_vault_directory_returns_records(self, require_pypykatz_dpapi) -> None:
        require_pypykatz_dpapi.return_value = FakePypykatzDPAPI

        with tempfile.TemporaryDirectory() as temp_dir:
            vault_dir = Path(temp_dir) / "Vault"
            vault_dir.mkdir()
            (vault_dir / "Policy.vpol").write_bytes(b"vpol")
            (vault_dir / "1234.vcrd").write_bytes(b"vcrd")

            result = windows_dpapi_parse_vault_directory_path(
                str(vault_dir),
                masterkeys_by_guid={FAKE_GUID: FAKE_MASTERKEY.hex()},
            )

        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["vpol_keys_hex"], ["01" * 16, "02" * 16])
        self.assertEqual(result["records"][0]["attributes"][0]["cleartext_candidates"][0]["utf8"], "vault-secret")


if __name__ == "__main__":
    unittest.main()
