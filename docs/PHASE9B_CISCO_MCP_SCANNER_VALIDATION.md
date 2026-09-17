# Phase 9B — Cisco mcp-scanner static validation

**Date:** 2026-09-16  
**Scanner:** `cisco-ai-mcp-scanner==4.8.4`  
**Mode:** static YARA `--tools`  
**Schema:** 1.5.0 **unchanged**  
**Splunk:** **NOT ATTEMPTED**

Evidence class: **OBSERVED_SCANNER** (live CLI). Pytest of adapter/export/isolation: **MEASURED**. Phase 8D runtime outcomes cited below are **OBSERVED** in `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md` (not re-run in 9B). README capabilities are **DOCUMENTED_EXTERNAL**. No SIMULATED scanner execution.

Canonical packs: `docs/phase9b-evidence/`.

---

## Upstream pin

| Field | Value |
|-------|--------|
| Package | cisco-ai-mcp-scanner |
| Version | 4.8.4 |
| Wheel SHA-256 | cd25f68d4f22c6e40b74578a8c28e2dfc350f69ebf4122801d9d05f804e769cd |
| License | Apache-2.0 |
| Repository | https://github.com/cisco-ai-defense/mcp-scanner |
| GitHub main at verify | be87b90d88bca2527a6e2075769a7608decd8f27 (not asserted as wheel contents) |
| Binary | `tools/cisco-mcp-scanner/.venv/bin/mcp-scanner` |
| API key | not used |
| LLM | not used |

Argv (MEASURED in manifests):

```text
mcp-scanner --analyzers yara --format raw --log-level error static --tools <absolute tools.json>
```

---

## Catalog export (MEASURED)

| Fixture | artifact.sha256 | description_sha256 (matches 8D) | bytes |
|---------|-----------------|----------------------------------|------:|
| NORMAL | `sha256:d706a2f8f8476ed0a972d2b7f371a42450addbfbafa2448488d8223e370bac60` | `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3` | 826 |
| MALICIOUS | `sha256:5e0bf29c6546a9a3d791918b59f7f6a99ac09dd9462f3295be8cbacc64c84cb7` | `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` | 963 |

MALICIOUS description is the **existing** 8C/8D fixture. It was not strengthened after seeing the scan.

---

## NORMAL scan (OBSERVED_SCANNER)

| Field | Value |
|-------|--------|
| scan_id | `b3061c4e-7a81-445c-8fd8-3108dd14c419` |
| exit_code | 0 |
| timed_out | false |
| finding_count | **0** |
| classification | null (NORMAL) |
| llm_used | false |
| network_required | false (argv; isolation not guaranteed) |
| target_executed | false |
| duration_ms | 1985 |
| stderr | empty (`sha256:e3b0c442…`) |
| agentsec.run.id | **null** |

YARA labeled both catalog tools `is_safe: true` / `severity: SAFE` in native JSON. Adapter records **zero** findings (SAFE + empty `threat_names` is not a finding).

---

## MALICIOUS scan (OBSERVED_SCANNER)

| Field | Value |
|-------|--------|
| scan_id | `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8` |
| exit_code | 0 |
| finding_count | **1** |
| classification | **DETECTED_BY_SCANNER** |
| native_rule_id / category | PROMPT INJECTION (scanner-native) |
| native_severity | HIGH (scanner-native; not remapped) |
| native_confidence | absent (omitted) |
| summary | Detected 1 threat: prompt injection |
| tool_name | lookup_policy |
| analyzer | yara_analyzer |
| duration_ms | 1532 |
| agentsec.run.id | **null** |

`lookup_customer_tier` remained SAFE. Only the poisoned `lookup_policy` description was flagged.

---

## Native JSON caveat (OBSERVED)

Both raw outputs include `"server_url": "https://mcp.deepwiki.com/mcp"`. Canonical argv **did not** pass `--server-url` and **did not** start MCP stdio. This is scanner-native formatter data, not proof AgentSec connected to DeepWiki. Network isolation is **not** claimed.

---

## Scanner vs Phase 8D runtime (same MALICIOUS description hash)

| Stream | Outcome | Class |
|--------|---------|--------|
| Scanner (9B) | HIGH PROMPT INJECTION on `lookup_policy` | OBSERVED_SCANNER |
| 8D ATTACK `a0937bff-…` | METADATA-001 OBSERVE; follow-on ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`; tier handler **1** | OBSERVED_RUNTIME (prior phase) |
| 8D RETEST `23c222ea-…` | Same malicious hash; follow-on DENY `tool_not_granted`; tier handler **0** | OBSERVED_RUNTIME (prior phase) |

The scanner finding does **not** tell us whether execution occurred. The same metadata coexists with ALLOW+execute and DENY+no execute depending on profile/overlay.

---

## False positive / false negative teaching

| Case | This experiment |
|------|-----------------|
| Scanner flags poison; runtime still executes (ATTACK) | **OBSERVED pairing** of 9B DETECTED + 8D ATTACK handler 1 |
| Scanner flags poison; runtime DENY (RETEST) | **OBSERVED pairing** of 9B DETECTED + 8D RETEST handler 0 |
| Scanner misses; runtime still vulnerable | Not this specimen (scanner **did** flag) |
| Scanner FAIL as AgentSec DENY | **Must not.** RETEST DENY reason remains `tool_not_granted` |

Do not call the YARA hit a “block.”

---

## Authorization isolation (MEASURED)

- AST: `authorize.py`, `policy.py`, `metadata_trust.py`, `pipeline.py` do not import `agentsec.scanners`
- `coded_policy().allowed_tools` unchanged after export and after live scans (`policy_unchanged: true`)
- CTRL-MCP-001 ALLOW `tool_granted` / DENY `tool_not_granted` unchanged
- CTRL-MCP-METADATA-001 OBSERVE unchanged
- Pytest: 483 passed, 1 skipped (live Splunk/Ollama marker, not scanner)

---

## Splunk readiness (Phase 9C input — do not implement)

| Topic | Recommendation |
|-------|----------------|
| Sourcetype | Candidate `agentsec:scanner:finding` still; same index `agentsec_telemetry` |
| Store | Raw JSON in a field or as a separate file reference; normalized allow-listed fields for search |
| Correlation | `description_sha256` ↔ `agentsec.content.hash`; optional `artifact.sha256` |
| Provenance | scanner.name/version, scan_id, argv (no secrets), exit_code |
| Privacy | Finding summaries and tool descriptions are untrusted text; do not dump full native `mcp_taxonomies.description` into notable-style alerts |
| Cardinality | `scan_id` high; scanner version low; native_rule_id moderate |
| Do **not** index | Fake `agentsec.run.id`; remapped AgentSec severity; `is_safe` as authorization; default `server_url` as destination evidence |
| Field contract | Required before any SPL. Indexed discovery after first HEC event |

No props.conf, SPL, detections, or Studio in 9B.

---

## Phase 9C not started
