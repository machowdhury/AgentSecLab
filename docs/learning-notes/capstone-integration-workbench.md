# Capstone integration workbench

## What is it?

The Capstone is an investigation of one deterministic multi-stage agent incident. A closed malicious lending-policy document is retrieved, persisted, recalled later, and used to form a privileged tool request. The learner must determine how influence became intent, where authority entered, and what actually executed.

It is not a sixth security domain and does not replay every prior vulnerability.

## Why does it exist?

Individual labs isolate one boundary. The Capstone checks whether those distinctions survive composition:

- retrieved content is not trusted authority
- stored and recalled memory is not a grant
- a request is not authorization
- an authorization decision is not execution
- indexed telemetry is not enforcement

## How does it work?

Each ATTACK or RETEST launch creates three correlated runs:

1. **RETRIEVE** — the RAG pipeline loads a closed document and `CTRL-RAG-CONTEXT-001` records `OBSERVE`.
2. **WRITE** — the exact document bytes are persisted as a memory record.
3. **RECALL** — a later run recalls the bytes, `CTRL-MEMORY-CONTEXT-001` records `OBSERVE`, and a closed interpreter forms a `lookup_customer_tier` request.

`CTRL-MCP-001` then evaluates the request. The vulnerable ATTACK profile applies an explicit lab fail-open overlay. The defended RETEST uses coded authority and denies the ungranted tool. The ToolRegistry handler count measures execution.

The primary `run_id` is the RECALL run. The RETRIEVE and WRITE IDs are siblings. Recall `source_run_id` links to WRITE. Exact `content.hash` equality links RETRIEVE to WRITE because schema 1.9.0 has no direct retrieve-to-write field.

## Where does it sit in AgentSec?

The workbench is the final LIVE investigation in Level 1. Earlier workbenches teach individual evidence planes. Capstone reduces guidance and asks the learner to:

`RUN ATTACK → INVESTIGATE → FORM HYPOTHESIS → RUN RETEST → COMPARE → PROVE`

The Splunk workshop mirrors that progression with MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS.

## What is the trust boundary?

- retrieved bytes entering agent context
- retrieved bytes becoming persistent memory
- recalled data influencing a later request
- a tool request crossing into the MCP PDP
- an authorization result crossing into ToolRegistry execution
- runtime telemetry crossing into Splunk

Splunk is downstream evidence. It is not between the PDP and handler.

## What could an attacker control?

Only the allowlisted malicious document bytes in this experiment. The browser cannot submit profile, grants, content, trust labels, tool policy, or control decisions.

## What can go wrong?

- treating RAG or memory OBSERVE as a grant
- treating `lookup_customer_tier` request fields as proof of execution
- treating ALLOW as handler invocation
- treating missing `mcp.started` as proof of prevention
- merging three run IDs into one
- claiming a matching content hash makes whole experiments identical
- blaming Goal or Identity without packet evidence
- treating Splunk as the control that changed RETEST

Dependency/runtime failures are ERROR, not DENY.

## What telemetry should exist?

- RAG document ID, hash, provenance, trust, control ID, decision, reason
- memory ID, write/recall hash, source run ID, trust, control ID, decision, reason
- requested tool, scope, and resource
- MCP control ID, decision, reason, and allowed scope
- operation-specific `mcp.started`, completed, or failed evidence
- profile, mode, schema, sequence, and run IDs
- local event counts for RETRIEVE, WRITE, and RECALL

## How will Splunk show it?

Existing validated Q-* hunts reconstruct each evidence plane. No Q-CAPSTONE or DET-CAPSTONE is added. Path A starts from questions and progressive hints. Path B reveals validated SPL, expected result shape, interpretation, and limitations.

Splunk corroborates emitted evidence when local and indexed counts match. HEC acceptance alone is not completeness.

## What control could change the result?

`CTRL-MCP-001` is the sole tool PDP. ATTACK and RETEST retain the same adversarial bytes and request. The server-owned ExperimentContext changes the MCP decision and therefore whether the privileged handler executes.

RAG and memory controls remain OBSERVE in both modes. They classify influence; they do not authorize the tool.

## What test proves the logic?

Deterministic tests assert:

- three distinct run IDs per launch
- RECALL is primary
- exact hash continuity
- `source_run_id == write_run_id`
- ATTACK MCP ALLOW and handler count 1
- RETEST MCP DENY and handler count 0
- coded policy does not gain `lookup_customer_tier`
- Goal and Identity control fields remain absent
- the browser launch contract cannot submit authority

Fresh LIVE runs and local-versus-Splunk counts are required to measure the deployed lab; pytest does not prove Splunk or production control effectiveness.

## Known limitations

- localhost educational environment
- deterministic closed fixtures, not universal attack coverage
- no production authentication, OAuth/OIDC, signed delegation, mTLS/PKI, or workload identity
- no direct retrieve-to-write correlation field in schema 1.9.0
- Studio cannot accept arbitrary fresh run IDs from Attack Service
- Splunk is not enforcement
- screen-reader coverage is PARTIAL unless tested with assistive technology

## What I should now be able to explain

1. Why does persistence prove influence but not authority?
2. Why are three run IDs required?
3. What exact object does the Capstone fingerprint cover?
4. Which controls only OBSERVE?
5. Which control is the tool PDP?
6. Why does ALLOW not prove execution?
7. What changes between ATTACK and RETEST?
8. What remains identical?
9. What can Splunk corroborate, and what can it not prove?
10. Why are Goal and Identity not part of this incident's active causal chain?
