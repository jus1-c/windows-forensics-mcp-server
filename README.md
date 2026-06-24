# Windows Forensics MCP

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A local-first MCP server for Windows forensics that lets AI agents analyze Windows forensic artifacts directly from the filesystem through the Model Context Protocol. The server is built for `stdio` by default and focuses on offline artifact analysis rather than hosted upload workflows.

## Features

- **Local-first MCP**: built for `stdio` so Claude Desktop, VS Code, Cline, and OpenCode can call it directly on local files
- **Windows Artifact Coverage**: EVTX, Registry hives, Prefetch, LNK, Jump Lists, Shell Items, SRUM, `$MFT`, and USN Journal
- **Windows DPAPI Coverage**: offline DPAPI masterkey recovery, generic blob decryption, Chromium legacy key recovery, Credential Manager credential parsing, and Vault parsing
- **Native-first Parsing**: uses `libyal` bindings where practical, with `dissect.*` fallbacks where they work better on exported samples
- **Offline Analysis**: works against exported hives, EVTX files, prefetch files, SRUM databases, and NTFS metadata exports
- **Structured JSON Output**: every tool returns machine-friendly results for downstream agent workflows
- **Fixture-backed Tests**: parser behavior is validated against real Windows artifacts when local fixtures are present

## Current Artifact Support

- EVTX event logs
- Offline registry hives: `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`, and related hive patterns
- Registry artifact extractors: Run/RunOnce, UserAssist, RecentDocs, RunMRU, Amcache, ShimCache (AppCompatCache), and USBSTOR
- Windows Prefetch `.pf`
- Windows shortcuts `.lnk`
- Jump Lists: `automaticDestinations-ms` and `customDestinations-ms`
- Embedded Shell Items from LNK / Jump List entries
- SRUM `SRUDB.dat`
- Exported `$MFT`
- Exported `$UsnJrnl` stream files
- AD1 artifact discovery support
- Windows DPAPI: `Protect/<SID>`, `CREDHIST`, offline `SYSTEM` / `SECURITY`, Chromium `Local State`, Credential Manager credential files, and Vault directories

## Requirements

- Python `3.10+`
- A virtual environment is recommended
- An MCP-compatible client such as Claude Desktop, VS Code, Cline, or OpenCode
- Local forensic artifacts to analyze

## Installation

### 1. Clone Repository

```bash
git clone <your-repo-url>
cd windows-forensics-mcp-server
```

### 2. Create Virtual Environment

**Linux / WSL / macOS:**
```bash
python3.10 -m venv .venv
. .venv/bin/activate
```

**Windows PowerShell:**
```powershell
py -3.10 -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Package

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

For development (linting and tests):

```bash
python -m pip install -e ".[dev]"
ruff check src tests
pytest -q
```

## Run

```bash
. .venv/bin/activate
windows-forensics-mcp
```

Or:

```bash
. .venv/bin/activate
python -m windows_forensics_mcp
```

## Configuration

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "windows-forensics": {
      "command": "/absolute/path/to/windows-forensics-mcp-server/.venv/bin/windows-forensics-mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### VS Code / Cline

```json
{
  "mcpServers": {
    "windows-forensics": {
      "command": "/absolute/path/to/windows-forensics-mcp-server/.venv/bin/windows-forensics-mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### OpenCode

Add to `~/.opencode/opencode.json`:

```json
{
  "mcp": {
    "windows-forensics": {
      "type": "local",
      "command": ["/absolute/path/to/windows-forensics-mcp-server/.venv/bin/windows-forensics-mcp"],
      "enabled": true,
      "timeout": 180000
    }
  }
}
```

## Available Tools

### Discovery

- `artifact_identify(path, include_hash=True)`
- `scan_directory(path, recursive=True, max_entries=200, include_hashes=False, include_unknown=False)`

### EVTX

- `evtx_info(file_path)`
- `evtx_list_records(file_path, limit=50, offset=0)`
- `evtx_search(file_path, event_id=None, provider_contains=None, text_contains=None, limit=50)`
- `evtx_timeline(file_path, limit=100)`
- `evtx_detect_security_events(file_path, profile="powershell", limit=50)`

### Registry

- `registry_hive_info(hive_path)`
- `registry_list_keys(hive_path, key_path=None, depth=1, max_keys=5000)`
- `registry_get_values(hive_path, key_path=None)`
- `registry_search(hive_path, pattern, scope="all", max_results=50, max_depth=32)`
- `registry_extract_artifact(hive_path, artifact_type)`
  - Supported `artifact_type` values: `run` / `runonce` / `autoruns`, `userassist`, `recentdocs`, `runmru`, `amcache`, `shimcache`, `usbstor`

### Windows DPAPI

- `windows_dpapi_recover_masterkeys(protect_dir, sid, password=None, nt_hash=None, system_hive_path=None, security_hive_path=None, credhist_path=None)`
- `windows_dpapi_decrypt_blob(masterkeys_by_guid, blob_hex=None, blob_path=None, entropy_hex=None)`
- `windows_dpapi_recover_chromium_master_key(local_state_path, masterkeys_by_guid=None, protect_dir=None, sid=None, password=None, nt_hash=None, system_hive_path=None, security_hive_path=None, credhist_path=None)`
- `windows_dpapi_parse_credential_file(file_path, masterkeys_by_guid=None, protect_dir=None, sid=None, password=None, nt_hash=None, system_hive_path=None, security_hive_path=None, credhist_path=None)`
- `windows_dpapi_parse_credentials_directory(directory_path, masterkeys_by_guid=None, protect_dir=None, sid=None, password=None, nt_hash=None, system_hive_path=None, security_hive_path=None, credhist_path=None)`
- `windows_dpapi_parse_vault_directory(directory_path, masterkeys_by_guid=None, protect_dir=None, sid=None, password=None, nt_hash=None, system_hive_path=None, security_hive_path=None, credhist_path=None)`

### Prefetch

- `prefetch_parse(file_path)`
- `prefetch_directory_summary(directory_path, limit=50)`
- `prefetch_timeline(path_or_directory, limit=100)`

### LNK / Jump Lists / Shell Items

- `lnk_parse(file_path)`
- `lnk_directory_summary(directory_path, limit=50)`
- `shellitems_parse(file_path)`
- `jumplist_parse(file_path)` — parses embedded LNK streams plus the `DestList` stream (MRU order, per-entry last-access time, pin status, originating hostname)
- `jumplist_directory_summary(directory_path, limit=50)`

### SRUM

- `srum_parse(file_path, sample_per_table=3)`
- `srum_extract_app_usage(file_path, limit=50)`
- `srum_extract_network_usage(file_path, limit=50)`

### NTFS Metadata

- `mft_parse(file_path, limit=100, offset=0)`
- `mft_search_records(file_path, name_contains, limit=50, scan_limit=50000)`
- `mft_timeline(file_path, limit=100)`
- `usn_parse(file_path, limit=100)`
- `usn_timeline(file_path, limit=100)`

## Usage Examples

### Identify an artifact

```
Identify this file and tell me which forensic tool I should call next:
/cases/host1/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx
```

### Investigate PowerShell activity

```
Search this PowerShell event log for interesting events and build a timeline:
/cases/host1/powershell_operational.evtx
```

### Inspect persistence from a user hive

```
Extract UserAssist and RunMRU from this NTUSER.DAT:
/cases/host1/NTUSER.DAT
```

### Recover DPAPI masterkeys offline

```
Recover DPAPI masterkeys from this user's Protect directory using a blank password and exported SYSTEM/SECURITY hives:
Protect dir: /cases/host1/Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-...
SYSTEM: /cases/host1/SYSTEM
SECURITY: /cases/host1/SECURITY
```

### Recover Chromium legacy master key offline

```
Recover the Chromium legacy AES key from this Local State file using recovered DPAPI masterkeys:
/cases/host1/Users/Alice/AppData/Local/Google/Chrome/User Data/Local State
```

### Parse a Credential Manager file

```
Decrypt this Credential Manager credential file using offline DPAPI masterkeys:
/cases/host1/Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCDEF1234567890...
```

### Parse an entire Credentials directory

```
Decrypt every Credential Manager file in this directory using offline DPAPI masterkeys:
/cases/host1/Users/Alice/AppData/Roaming/Microsoft/Credentials
```

### Parse a Vault directory

```
Decrypt this Windows Vault directory using offline DPAPI masterkeys:
/cases/host1/Users/Alice/AppData/Local/Microsoft/Vault/{GUID}
```

### Analyze execution evidence

```
Parse this prefetch file and show run count, last execution times, and referenced files:
/cases/host1/POWERSHELL.EXE-022A1004.pf
```

### Review jump list activity

```
Parse this Jump List and summarize the linked targets:
/cases/host1/f01b4d95cf55d32a.automaticDestinations-ms
```

### Inspect NTFS metadata

```
Search this exported $MFT for records containing "powershell":
/cases/host1/$MFT
```

## Architecture

```text
┌─────────────────┐     ┌──────────────────────┐     ┌────────────────────┐
│   MCP Client    │────▶│  FastMCP Server      │────▶│ Artifact Parsers   │
│ Claude/Cline/etc│     │  stdio transport     │     │ libyal + dissect   │
└─────────────────┘     └──────────────────────┘     └────────────────────┘
                               │                               │
                               ▼                               ▼
                        ┌─────────────────┐             ┌─────────────────┐
                        │ Tool Layer      │             │ Local Artifacts │
                        │ JSON responses  │             │ evtx/hive/pf/...│
                        └─────────────────┘             └─────────────────┘
```

## Project Structure

```text
windows-forensics-mcp-server/
├── src/
│   └── windows_forensics_mcp/
│       ├── backends/
│       ├── tools/
│       ├── utils/
│       ├── artifacts.py
│       ├── config.py
│       ├── errors.py
│       ├── schemas.py
│       └── server.py
├── pyproject.toml
└── README.md
```

## Development Notes

- Default transport is `stdio`
- The server is intentionally local-first
- Exported evidence files such as `extracted.ad1`, `$MFT`, and `$Extend` are treated as local analysis inputs, not core source code
- On the current sample set, `dissect.esedb` and `dissect.ntfs` are used as practical fallbacks for `SRUM`, exported `$MFT`, and exported `USN` handling
- Local validation files and fixture-backed tests are intentionally left out of the initial repository commit

## Limitations

- The current `USN` sample in this workspace is empty, so positive end-to-end parsing for real USN records still requires a non-empty exported `$J` stream
- Chromium `app_bound_encrypted_key` (v20) decryption is not supported; only the legacy `encrypted_key` path is recovered
- Cross-artifact correlation and detector packs are still future work

## License

MIT License - see [`LICENSE`](LICENSE).
