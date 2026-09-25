# External evidence E2E and Academy integration

## What is it?

External security evidence is information produced by an independent security
tool and normalized so a learner can investigate it beside AgentSec runtime
telemetry. Cisco mcp-scanner emits static catalog findings. garak emits
adversarial model evaluations.

## Why does it exist?

No single source answers every security question. A static scanner can identify
suspicious catalog content without knowing whether a runtime authorized or
executed it. A model evaluation can characterize one tested response without
proving tool impact. Runtime telemetry can record a request, decision, and
execution state without replacing independent negative testing.

## How does it work?

Canonical native output is preserved in an evidence pack. A tool-specific
adapter maps known fields into ExternalEvidence 1.0.0 and omits unknowns. The
HEC builder sends pack-derived events to a dedicated sourcetype:

```text
Cisco → finding → agentsec:scanner:finding
garak → evaluation → agentsec:external:evaluation
AgentSec runtime → schema 1.9.0 → otel:agentic:json
```

Splunk makes all three searchable. It does not authorize.

## Where does it sit in AgentSec?

It sits beside the runtime. CTRL-MCP-001 remains before the dangerous tool
operation. External adapters do not import or call the PDP. The Academy presents
the scanner workshop first, then the External Security Toolbox replay workshop.

## What is the trust boundary?

Native tool output and indexed copies are observations. They cross a
normalization and ingestion boundary where provenance, missing fields, parsing,
and duplicates matter. The authorization trust boundary remains where a tool
request meets CTRL-MCP-001.

## What could an attacker control?

Depending on the experiment, an attacker may influence catalog text, probe
input, model output, malformed external files, or identifiers used in a search.
Those values cannot grant authority merely because an adapter or Splunk indexes
them.

## What can go wrong?

- HEC or Splunk can be unavailable.
- A pack can be missing or malformed.
- Fields can fail extraction even after HEC returns HTTP 200.
- Duplicate HEC submissions can inflate event counts.
- A hash or identity tuple can be mistaken for a causal runtime relationship.
- Native HIGH, PASS, or FAIL can be overclaimed.
- Zero rows can be mistaken for safety.

## What telemetry should exist?

When genuinely known: producer, tool and version, evidence class, subject,
timestamp, native result, raw reference and SHA-256, correlation method, and
correlation value. Unknown values stay absent.

## How will Splunk show it?

`Q-GARAK-EVALUATION.spl` reconstructs the evaluation and provenance.
`Q-EXTERNAL-EVIDENCE-PLANES.spl` groups runtime, static finding, and
adversarial evaluation sourcetypes while showing both total and distinct raw
counts. Grouping is not a join and does not assert causality.

## What control could change the result?

CTRL-MCP-001 can change whether an AgentSec tool request is allowed. It cannot
change what Cisco or garak previously observed. External evidence can motivate
investigation or defensive engineering, but it does not feed this PDP.

## What test proves the logic?

Unit tests prove adapter mapping, malformed/missing-pack failures, provenance
digests, distinct sourcetypes, and AST isolation. The opt-in
`test_cisco_and_garak_external_evidence_e2e` submits canonical pack events
through HEC and asserts actual Splunk results. Dashboard tests prove packaging
and teaching semantics, not rendering.

## What I should now be able to explain

1. Why is a scanner finding not an authorization decision?
2. Why is a garak PASS not proof of universal safety?
3. What does a Cisco description-hash match establish?
4. Why does garak use an identity tuple instead of a runtime run ID?
5. Why is HEC HTTP 200 insufficient evidence of field completeness?
6. Why can `count` differ from `dc(_raw)` after repeated ingestion?
7. Which evidence proves ALLOW, execution start, and successful completion?
8. How should NO EVIDENCE FOUND affect an investigation?
9. Which external-validation questions remain open?
10. Why do these evidence-discipline principles apply beyond AI security?
