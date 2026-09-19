# Cisco mcp-scanner static integration

**Status:** Phase 9B IMPLEMENTED + LOCALLY VALIDATED.  
**Pin:** `cisco-ai-mcp-scanner==4.8.4` (`tools/cisco-mcp-scanner/pin.json`).  
**Does not authorize.** Does not ingest Splunk. Schema remains **1.5.0**.

Parents: `docs/PHASE9A_SCANNER_RESEARCH.md`, `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`.

---

## Locked boundary

```text
SCANNER FINDING != AUTHORIZATION DECISION
```

Scanner PASS ≠ trusted. Scanner FAIL ≠ DENY. Scanner silence ≠ safe.  
CTRL-MCP-001 and CTRL-MCP-METADATA-001 are unchanged. The scanner process cannot modify `coded_policy()`.

---

## Upstream re-verification (2026-09-16)

| Item | Recorded |
|------|----------|
| Repository | https://github.com/cisco-ai-defense/mcp-scanner |
| GitHub `main` HEAD | `be87b90d88bca2527a6e2075769a7608decd8f27` (CodeQL workflow only; **not** claimed as the wheel contents) |
| License | Apache-2.0 |
| PyPI package | `cisco-ai-mcp-scanner==4.8.4` |
| Wheel SHA-256 | `cd25f68d4f22c6e40b74578a8c28e2dfc350f69ebf4122801d9d05f804e769cd` |
| CLI | `mcp-scanner` |
| Static syntax | `mcp-scanner --analyzers yara --format raw static --tools <file>` |
| Expected JSON | `{ "tools": [ { "name", "description", "inputSchema" } ] }` — **matches** AgentSec `build_catalog_snapshot` |
| YARA without LLM/API | **VERIFIED** in README and by live execution (no keys in child env) |
| Static executes target? | **No** in canonical argv. Subcommands `stdio` / `remote` exist and are **forbidden** in the wrapper |
| Network | Isolation **not guaranteed** on this host. Canonical argv does not pass `--server-url`. Live JSON still contains a default `server_url` field (see limitations) |

Phase 9A assumptions for static `--tools` + YARA held. Implementation was **not** stopped.

---

## Install (isolated venv, not AgentSec runtime)

```text
uv venv tools/cisco-mcp-scanner/.venv
uv pip install --python tools/cisco-mcp-scanner/.venv -r tools/cisco-mcp-scanner/requirements.txt
```

Do not add this package to AgentSec’s main dependencies (it pulls FastAPI, LiteLLM, MCP SDK, etc.).

Canonical run:

```text
.venv/bin/python scripts/run_lab_mcp_catalog_cisco_scanner.py
```

---

## Catalog export

`src/agentsec/scanners/catalog_export.py` serializes `build_catalog_snapshot()` to UTF-8 JSON (`indent=2` + trailing newline). Same ToolSpec machinery as LAB-MCP-CATALOG. No grant fields.

Two hashes are recorded:

| Hash | Bytes |
|------|--------|
| `artifact.sha256` | Entire exported `tools.json` |
| `description_sha256` | UTF-8 `lookup_policy` description only (same as 8D `agentsec.content.hash`) |

They are **not** equal and must not be compared as if they were.

---

## Wrapper

`src/agentsec/scanners/cisco_mcp_scanner.py`

- `subprocess.run(..., shell=False)`
- argv allow-list: YARA + `static --tools` only
- timeout 60s
- stdout/stderr capped at 2 MiB
- secrets stripped from child environment
- no HTTP/user passthrough of extra CLI flags

---

## Evidence packs

`artifacts/scanners/<scan-id>/` (local) and copies under `docs/phase9b-evidence/` (committed proof).

`scan_id` is a UUID. `agentsec.run.id` is **null**. Correlation with runtime is via `description_sha256` / artifact identity, not a fake run id.
