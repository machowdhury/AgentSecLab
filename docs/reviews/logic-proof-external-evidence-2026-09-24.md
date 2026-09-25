# Logic proof — External Security Evidence

## Security property

Cisco findings, garak evaluations, Academy metadata, and Splunk results cannot
change CTRL-MCP-001 authorization or cause a tool handler to execute.

## Assumptions

- `authorize_tool` remains the tool PDP.
- Tool handlers remain downstream of authorization.
- External adapters and HEC scripts run beside the runtime.
- Splunk is downstream evidence and is not called before a tool operation.

## Attacker-controlled input

Catalog descriptions, native external-tool output, malformed/missing pack
files, probe prompts, model responses, HEC availability, indexed fields, and
learner-supplied SPL/time ranges can be untrusted or incomplete.

## Trust boundary

External native output crosses adapter and ingestion boundaries into
ExternalEvidence and Splunk. A runtime tool request separately crosses the
CTRL-MCP-001 authorization boundary before the handler.

## Code paths

External:

```text
Cisco pack → scanners.hec_events → HEC → Splunk
garak JSONL → GarakEvaluationAdapter → garak_pack.hec_event → HEC → Splunk
```

Runtime:

```text
tool request → authorize_tool → ALLOW/DENY → handler → runtime telemetry
```

`src/agentsec/mcp/*.py` imports neither garak nor
`agentsec.external_evidence`.

## Decision points

External adapters validate/normalize evidence class and known fields. They do
not make policy decisions. `authorize_tool` makes the tool authorization
decision from coded policy, requested scope/tool, registration, profile, and
explicit lab overlays—not findings or evaluations.

## Dangerous operation

The governed MCP tool handler invocation.

## Where validation occurs

CTRL-MCP-001 evaluates the request before the handler. External evidence is not
an argument to `authorize_tool`.

## Failure path

- Missing Cisco/garak pack: explicit `FileNotFoundError`; no event or grant.
- Malformed garak JSONL: explicit `ValueError`; no normalized event or grant.
- HEC unavailable: explicit `RuntimeError`; no false success claim.
- Splunk unavailable: explicit `RuntimeError`; no false evidence-ready claim.
- Empty/no matching row: dashboard states `NO EVIDENCE FOUND`; not SAFE/DENY.

## Fail-open possibility

External-evidence failure cannot fail open into ALLOW because no external
result enters the PDP. Any intentionally vulnerable runtime profile remains an
existing lab behavior governed by runtime code, not a scanner/evaluation result.

## Telemetry

External evidence records producer, tool/version, class, known subject,
timestamp, native result, raw reference/hash, and a source-specific correlation
method. Runtime schema 1.9.0 separately records PDP and execution events.

## Test evidence

UNIT TEST:

- `tests/unit/test_external_evidence.py`
- `tests/unit/test_garak_external_evidence.py`
- `tests/unit/test_external_evidence_failures.py`

NEGATIVE TEST:

- HIGH and zero findings do not affect authorization.
- Unknown evidence class is rejected.
- Missing/malformed packs fail explicitly.

INTEGRATION TEST:

- `tests/splunk/test_external_evidence_live.py` submits canonical HEC events
  and asserts real Splunk results when `AGENTSEC_LIVE_SPLUNK=1`.

BYPASS TEST:

- AST/source tests reject external-evidence imports in `src/agentsec/mcp`.
- `authorize_tool` signature has no finding/external argument.
- HEC payload tests reject manufactured `agentsec.run.id`.

## Required questions

**Could the dangerous operation happen before validation?**
Not through these external paths. They never call the handler. Existing runtime
tests separately prove the PDP-before-handler ordering.

**Could missing context become ALLOW?**
Missing external evidence is not runtime authorization context and cannot
change the decision. It becomes an explicit evidence failure/absence.

**Could one agent silently inherit another agent’s authority?**
This feature carries no agent authority, delegation, or runtime run ID.

**Could telemetry report DENY after the operation already happened?**
External telemetry reports no ALLOW/DENY. Runtime control ordering remains
covered by existing runtime tests.

**Which security assertion currently lacks a test?**
Fresh upstream CLI execution is not part of this E2E proof. Screen-reader
behavior and a browser-injected Splunk outage remain NOT PROVEN/PARTIAL.

## Verdict

PASS for PDP isolation and fail-safe external-evidence behavior. External
evidence can inform investigation but cannot authorize or execute.
