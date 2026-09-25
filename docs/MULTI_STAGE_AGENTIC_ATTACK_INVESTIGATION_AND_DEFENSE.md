# Multi-Stage Agentic Attack, Investigation & Defense

## Purpose

L9 is AgentSec's first major integration phase. It asks learners to establish
which stages of a complex agentic incident occurred, which merely could have
occurred, what controls mattered, what evidence supports each claim, and how
the architecture should change.

It is a bounded educational `REPLAY`, not autonomous hacking, production
incident response, SOAR, or a universal attack graph.

## Canonical incident

`AGENT-2026-009` reuses the validated Capstone packet:

```text
untrusted RAG context
  → fixture-equivalent memory write
  → later recall
  → privileged lookup_customer_tier request
  → CTRL-MCP-001 authorization
  → bounded fixture execution and completion on ATTACK
```

The defended packet preserves the same influence fingerprint and request but
CTRL-MCP-001 returns `DENY tool_not_granted`; the handler count is zero.

Goal Integrity and Identity/Delegation are relevant domains but not observed
in this packet. Authentication, human approval, cryptographic delegation, and
production IAM remain `NOT MODELED`.

## Evidence-state model

- `PROVEN`: direct authoritative evidence establishes the bounded claim.
- `SUPPORTED`: multiple evidence items support the claim but an assumption or
  missing edge remains.
- `OBSERVED`: an event or artifact is present without broader interpretation.
- `INFERRED`: reasoned from evidence and explicitly labeled.
- `NOT OBSERVED`: the instrumented packet contains no relevant event.
- `NOT MODELED`: the architecture does not implement the capability.
- `NOT PROVEN`: available evidence cannot establish the claim.
- `REFUTED`: evidence contradicts the proposed explanation.

Text always accompanies visual status. `CLAIM STRENGTH <= EVIDENCE STRENGTH`.

## Investigation methodology

```text
DISCOVER → NARROW → CORRELATE → SEQUENCE → COMPARE → CHALLENGE
```

Learners begin with an approximate window, workflow, and two observables—not
run IDs or answers. They write and decompose a hypothesis, discover candidate
control decisions, pivot to event families, construct a timeline, compare the
defended condition, and actively seek contradictory evidence.

## Influence versus authority

RAG, memory, prompts, and model output may influence requests. They do not mint
tool authority. CTRL-MCP-001 evaluates tool, scope, and resource before the
handler. Splunk observes a copy after runtime decisions.

## Authorization versus execution

Each stage needs separate evidence:

```text
REQUEST → DECISION → INVOCATION → COMPLETION → OUTCOME
```

An ALLOW event proves the bounded decision, not invocation. Handler count and
`mcp.started` support invocation. `mcp.completed` plus successful hop outcome
supports bounded completion. No packet proves production banking impact.

## Persistence

Memory evidence includes write, stored record, later recall, reuse, memory ID,
canonical hash, and `source_run_id`. Hash equality between retrieve and write
supports equivalent bytes but does not establish a direct copy edge because
that edge is not modeled in schema 1.9.0.

## Data and privacy consequence

The fixture returns a synthetic customer-tier result. Learners separately ask
whether the action was authorized, execution was expected, data was necessary,
where it traveled, what appeared in telemetry, and what persists. Production
customer exposure, field-level necessity, provider retention, and breach
status are not proven.

## External evidence and false lead

The Cisco mcp-scanner HIGH finding is a plausible false lead. Its description
hash differs from the incident fingerprint and no runtime join establishes
involvement. The garak PASS targets another evaluation context and carries no
AgentSec runtime run ID. Scanner finding is not exploitation; evaluation pass
is not safety.

## Bounded evidence graph

Allowed edges are `PRECEDES`, `CORRELATES_WITH`, `REQUESTS`,
`AUTHORIZED_BY`, `EXECUTED_BY`, `PRODUCED`, and `REFERENCES`. `CAUSED` is not
used because causality is not independently established for every link.

## Control analysis

RAG and Memory controls triggered as OBSERVE classifiers. The ATTACK's labeled
vulnerable fail-open at CTRL-MCP-001 is the control failure. RETEST removes
that condition and CTRL-MCP-001 succeeds with fail-safe denial. Splunk supports
reconstruction but does not enforce.

## Containment, remediation, and hardening

Immediate educational containment includes restricting the affected workflow,
removing suspect context, isolating associated memory, constraining tool scope,
and preserving evidence. Root-cause remediation removes the fail-open
condition. Architectural hardening adds least privilege, scoped retrieval and
memory, downstream authorization, argument minimization, complete telemetry,
retention design, and tested recovery.

## Detection engineering

The candidate SPL searches for authority mismatch followed by execution. It
must be tested against ATTACK, RETEST, and expected baseline activity. It is
not installed as a saved search and is not a production detector.

## Hunt expansion

The expanded hunt starts from behavior rather than a known run ID. Analysts
document hypothesis, range, candidates, pivots, exclusions, conclusion, and
limitations. Empty results are `NO EVIDENCE FOUND`, never `SAFE`.

## Operational feedback

The threat model gains explicit influence and authority boundaries, grant
integrity, fail-open risk, and cross-run telemetry requirements. The privacy
model adds customer-tier data, purpose/minimization questions, tool-result and
telemetry exposure, and unresolved retention.

## Communication

The final artifact contains evidence-backed SOC/IR detail, engineering
remediation/control placement, and an executive summary of bounded impact,
proven facts, uncertainty, response, and residual risk.

## Limitations

The packet is synthetic and historical. It does not establish authentication,
human approval, production IAM, cryptographic delegation, production customer
impact, direct retrieve-to-write causality, provider behavior, universal
resistance, or compliance. Runtime schema remains `1.9.0`; ExternalEvidence
remains `1.0.0`; CTRL-MCP-001 remains the tool PDP.
