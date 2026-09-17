# Scanner evidence model

**Status:** Phase 9A DESIGN. Phase **9B** uses `OBSERVED_SCANNER` as a **pack field**, not a `security_event` schema enum. No schema bump.  
**Parents:** `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`, `docs/SCHEMA_1_5_0.md`, `docs/SCANNER_EVIDENCE_RUNTIME_CONTRACT.md`, `.cursor/rules/50-research-integrity.mdc`.

---

## Honesty rule

Never represent imported scanner output as:

- a newly measured live AgentSec runtime experiment
- an authorization decision
- proof a handler ran or did not run
- AgentSec severity (unless a later documented mapping is explicit and reversible)

Research-integrity classes already in AgentSec: OBSERVED, MEASURED, DOCUMENTED, INFERRED, SIMULATED, REPLAYED.

Scanner integration needs **finer producer classes** so a SOC learner can see *who produced the bytes*.

---

## Proposed evidence classes (design names only)

Do **not** implement these as schema enums in Phase 9A.

| Class | Producer | Meaning | Must not be used as |
|-------|----------|---------|---------------------|
| **OBSERVED_RUNTIME** | AgentSec runtime exporters | Control/MCP/LLM events from a real lab invoke | Scanner proof |
| **OBSERVED_SCANNER** | External scanner via adapter | Finding from a recorded scan of an artifact | DENY / ALLOW |
| **OBSERVED_SPLUNK** | Splunk search result | Indexed investigation result | Authorization |
| **SIMULATED** | `makeresults` / fixtures | Teaching positive control | Live proof |
| **INFERRED** | Analyst or join logic | Derived from other evidence | Telemetry |
| **DOCUMENTED_EXTERNAL** | Vendor README / blog / spec | Capability claims not executed here | OBSERVED_SCANNER |

Phase 8D already uses SIMULATED for DET-MCP-001 positive-control rows. That discipline stays.

`telemetry.fidelity` on schema 1.5.0 (`OBSERVED` / `SYNTHETIC` / `MIXED`) applies to **runtime `security_event` only**. Do not overload it for scanner findings.

---

## Schema gap (documented, not patched)

| Need | Schema 1.5.0 | Gap |
|------|--------------|-----|
| Scanner identity / version | Absent on `security_event` | **Intentional.** Findings must not ride `mcp.started` / control events |
| Scanner severity | Absent | Keep on a separate evidence object / future sourcetype |
| Artifact SHA-256 of *exported catalog file* | Runtime hashes the **description** (`agentsec.content.hash`) | File-level hash of `tools[].json` may differ from description hash; both should be recorded in the scanner pack |
| LLM-used / network-used flags | Absent on security_event | Adapter metadata, not a 1.5.0 field |
| Evidence class enum | Not on schema | Document in the pack; do not bump schema automatically |

**Recommendation:** keep scanner evidence **off** `otel:agentic:json` until a dedicated lab spec proposes a **new** event family or a **new sourcetype** with its own contract. Phase 9B kept findings in file packs. Phase 9C (not started) would propose ingest.

---

## Provenance (every imported finding)

A future normalized finding should answer:

| Question | Record |
|----------|--------|
| Which scanner? | `scanner.name` (adapter field; not a Splunk indexed field until discovered) |
| Which version? | version string + git SHA or release tag if known |
| Which repository/release? | URL + pin |
| When was it run? | ISO-8601 scan timestamp |
| Against what artifact? | path + role (`mcp.catalog.snapshot`, lockfile, …) |
| Artifact fingerprint? | **SHA-256** of exact bytes scanned |
| Which rule/check? | scanner-native rule id (YARA rule name, Snyk risk name, …) |
| Scanner severity? | **as reported by the scanner**, unmodified |
| Scanner confidence? | as reported, or `absent` |
| LLM involved? | yes/no + model id if any |
| Network access? | yes/no + destinations if known |
| Code executed? | yes/no (stdio MCP, eval, …) |
| Raw evidence? | path + SHA-256 of raw JSON/SARIF |
| Transformed by AgentSec? | adapter version + transform notes |

Do **not** convert scanner severity into AgentSec severity silently. If a later workshop displays both, label columns `scanner.severity` vs `agentsec.control.decision`.

---

## Artifact fingerprinting

Use **SHA-256** only. Do not use MD5 or SHA-1 (workspace crypto rule).

Possible targets (when those artifacts exist):

| Target | Notes |
|--------|--------|
| MCP catalog snapshot JSON | First 9B target; mcp-scanner `--tools` shape |
| Tool description UTF-8 bytes | Already hashed at runtime as `agentsec.content.hash` |
| MCP server configuration | If scanned |
| Package lockfile | If aibom / supply-chain later |
| AI BOM | Inventory artifact |
| Agent configuration | If scanned |
| Prompt template | If scanned |
| Policy file | If scanned |
| Scanner output | Hash the raw finding file too (tamper-evident pack) |

**Hash equality proves artifact equality only.** It does not prove:

- the tool is safe
- the scanner is correct
- two different descriptions with the same hash (impossible) or different tools with similar text are equivalent in security
- the runtime will ALLOW or DENY

TOCTOU: a scan of file A then a runtime load of file B is a **different** experiment unless hashes match.

---

## Evidence bundle layout (future, not created now)

Conceptual:

```text
artifacts/<run-id>/scanner/
  manifest.json          # provenance, hashes, adapter version
  input/catalog.json     # exact bytes scanned
  raw/<scanner>-output.json
  normalized/findings.json
```

`manifest.json` is AgentSec-authored. Raw output is scanner-authored. Normalized findings cite both hashes.

---

## Correlation keys (design)

Join **only** on keys that exist on both sides after discovery:

| Runtime (already indexed in 8D) | Scanner pack (future) |
|---------------------------------|------------------------|
| `agentsec.content.hash` (description) | SHA-256 of description field inside scanned JSON, if exported identically |
| `agentsec.run.id` | optional `correlated_run.id` if the scan was attached to a run |
| `gen_ai.tool.name` | tool name in scanner finding, if present |

Do not invent Splunk fields in this document. After 9B ingest, run indexed field discovery (`docs/SCANNER_SPLUNK_INTEGRATION_DESIGN.md`).

---

## What this model does not claim

- That YARA will flag the MALICIOUS fixture (unknown until a scan is run in 9B)
- That Snyk Agent Scan will agree with Cisco mcp-scanner
- That empty scanner output means INV-002 held
