# Goal and Identity Security Experiment Workbenches

## What is it?

Two compact LIVE workbenches and two Splunk workshops:

- Goal / Instruction Integrity separates an overall objective from each operation used while pursuing it.
- Agent Identity / Delegation separates claimed identity from established lab facts, authentication, and authorization.

They reuse the AgentSec workbench grammar without copying MCP's security conclusion.

## Why does it exist?

A simple handler total is misleading for Goal Integrity. Defended RETEST legitimately executes `lookup_policy` once for `summarize_lending_policy`, while preventing `extract_full_policy`.

Identity strings are also easy to overstate. The lab records principal, caller, callee, and delegation claims, but it does not cryptographically authenticate them. CTRL-IDENTITY-001 classifies the claim; CTRL-MCP-001 decides tool authority.

## How does it work?

Goal:

```text
server-owned task
→ untrusted instruction
→ proposed change
→ Goal control
→ effective action
→ MCP tool authorization
→ in-task / wrong-goal execution counts
```

Identity:

```text
identity/delegation claim
→ Identity OBSERVE
→ privileged request
→ MCP tool authorization
→ privileged handler count
```

ATTACK and RETEST use the same canonical domain input but different server-owned profiles and fresh run IDs. Fingerprint equality proves only equality of the hashed object.

## Where does it sit in AgentSec?

The browser remains an untrusted launcher. It sends only `lab_id`, `specimen_id`, `mode`, and `execution`. AcmeBank creates ExperimentContext, evaluates controls, runs handlers, and emits local evidence. Splunk receives a copy for investigation; it is not a policy decision point.

## What is the trust boundary?

- Browser → Attack Service: closed launch contract.
- Untrusted instruction → server task: CTRL-GOAL-INTEGRITY-001.
- Identity/delegation claim → coded authority: CTRL-IDENTITY-001 classification, then CTRL-MCP-001 authorization.
- Authorized request → handler: control check must complete before execution.
- Runtime → Splunk: evidence transport only.

## What could an attacker control?

In these deterministic labs, the attacker influence is represented by closed fixtures: malicious instruction bytes or an A2A-shaped delegation claim. The attacker cannot submit profiles, grants, policy decisions, run IDs, or control outputs through the browser.

## What can go wrong?

- Treating any Goal RETEST execution as defense failure.
- Treating a granted tool as authorization for every goal.
- Treating a principal or agent string as authentication.
- Treating Identity OBSERVE as tool ALLOW.
- Treating DENY as proof of non-execution without a runtime count.
- Treating missing Splunk events as prevention.
- Confusing an infrastructure ERROR with policy DENY.

## What telemetry should exist?

Goal needs task/instruction/proposed fingerprints, proposed and effective action, Goal decision/reason, MCP decision/reason, and in-task/wrong-goal counts.

Identity needs claim/request fingerprint, principal/caller/callee attribution, claim trust, Identity decision/reason, requested authority, MCP decision/reason, authentication limitation, and privileged handler count.

Both need run correlation, local event count, schema version, and enough ordered events to reconstruct the decision before execution.

## How will Splunk show it?

The Studio workshops use MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS. Path A starts with a minimal run.id search and progressive hints. Existing validated Q-* SPL remains unchanged. Path B contains the detailed legacy material, expected shapes, and proof limits.

Completeness compares local primary event count with Splunk `dc(_raw)`. HEC HTTP success alone is not completeness.

## What control could change the result?

- Goal: CTRL-GOAL-INTEGRITY-001 changes the effective action; CTRL-MCP-001 independently authorizes `lookup_policy`.
- Identity: the claim control stays OBSERVE; CTRL-MCP-001 changes from labeled fail-open ALLOW in ATTACK to `tool_not_granted` DENY in RETEST.

## What test proves the logic?

Deterministic security tests assert control order, closed authority fields, frozen check/use state, exact decisions/reasons, identical scoped fingerprints, and operation-specific handler counts. Browser tests assert the correct distinctions remain visible. Studio tests bind the canonical SPL byte-for-byte and ensure every data source remains rendered.

These tests prove repository logic, not production security effectiveness or live Splunk completeness.

## What I should now be able to explain

1. Why can Goal RETEST execute `lookup_policy` and still prevent the prohibited objective?
2. Why is total handler count insufficient for Goal Integrity?
3. Which Goal control decides task expansion, and which control decides tool authority?
4. What exactly does each Goal fingerprint cover?
5. Why is a principal string not authentication?
6. Why does CTRL-IDENTITY-001 OBSERVE not grant a tool?
7. What is CLAIMED, ESTABLISHED IN LAB, and NOT MODELED in the Identity lab?
8. What does runtime evidence prove that Splunk only corroborates?
9. Why is ERROR not DENY?
10. What would falsify each lab's expected RETEST result?
