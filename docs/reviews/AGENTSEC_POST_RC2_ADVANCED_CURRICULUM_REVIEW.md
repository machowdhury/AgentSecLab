# AgentSec post-RC2 advanced curriculum review

**Date:** 2026-09-27
**Mode:** read-only. No runtime, UI, lab, detector, tool, schema, or contract change.
**Reviewed commit:** `1be214b92f840f843aaf27fb2b9536f764dd7126` (`v1.0.0-rc2`, also `develop` and `origin/develop`)
**Schema:** 1.9.0. **ExternalEvidence:** 1.0.0.

An untracked file `docs/plans/AGENTSEC_5DAY_ADVANCED_EXTERNAL_INTEGRATION_ADDENDUM.md` is a 2026-09-24 plan against an older commit. It is not part of RC2. This review does not adopt it as the next build.

## 1. Executive Summary

RC2 is a complete foundational academy: L0 through L10, seven LIVE labs, and a separate Mastery Check. It already teaches the invariants that later work must keep: a claim is not proof, observation is not enforcement, authorization is not execution, an allowed action is not allowed data use, an empty result is not safety, and an external finding is not a grant.

The academy is investigation-rich and honest about what it does not model. It is not yet a place where a learner can move from a pasted `run.id` to an independent hunt, and then design identity, retrieval authorization, or human approval. Those later topics are real gaps. They are the wrong next build.

The next build should be a **Splunk Defender Bridge** between the L5 LIVE Capstone and L6. It reuses telemetry that already exists. It does not add a PDP, a detector, a scanner, or a schema field. Without that bridge, L6 through L10 and every advanced lab after them stay either guided or abrupt.

Final 1.0 quality work stays separate. Do not hide it inside an exciting feature.

## 2. RC2 Capability Baseline

MEASURED: HEAD equals `v1.0.0-rc2^{}`.

DOCUMENTED from `learning/academy/curriculum.json` and the RC2 inventory, checked against code positions already established for this tag:

| Capability | Class |
|------------|-------|
| L0 Orientation | STATIC |
| L1 Direct Prompt Injection, Tool Authorization | LIVE |
| L1 Scope Escalation, Parameter / Resource Authorization | REPLAY |
| L2 RAG, Memory | LIVE, SIMULATED fixtures |
| L2 Tool Result Trust, Tool Catalog, Scanner, garak | REPLAY |
| L3 Goal Integrity, Identity / Delegation | LIVE, educational claims |
| L3 Confused Deputy | REPLAY |
| L4 Investigation craft | STATIC, practiced on LIVE Path A. No separate workshop |
| L5 Lending Assistant Investigation | LIVE. Last launcher |
| L6 Blue Team AI-2026-001 | REPLAY |
| L7 Threat modeling | STATIC reasoning. Curriculum mode field is REPLAY because it is not a launcher |
| L8 Privacy PRIV-2026-001 | REPLAY |
| L9 AGENT-2026-009 | REPLAY |
| L10 MASTER-2026-001 | REPLAY |
| Mastery Check | STATIC, unscored, not a certification |
| Attack Service | IMPLEMENTED. Closed launcher. Does not authorize |
| CTRL-MCP-001 | IMPLEMENTED. Tool PDP |
| CTRL-IDENTITY-001 | IMPLEMENTED as claim classification. Code states it never authorizes a tool |
| Cisco mcp-scanner 4.8.4 | IMPLEMENTED adapter. Learner path is REPLAY / pack-based |
| garak 0.17.0 | IMPLEMENTED adapter. Learner path is REPLAY / pack-based. License NEEDS_EXTERNAL_VALIDATION |
| DET-MCP-001 | Packaged and disabled. Not an enabled detector |
| Q-RUN, Q-DENY | Disabled placeholders |
| Workshop detection SPL | Candidate / educational. Not installed |
| Production NHI, OAuth, A2A protocol, HITL, vector ACL, provider retention, tamper-evident audit | NOT MODELED |

## 3. Learner Mission

AgentSec remains an agentic security academy. Personas A through D should move from understanding a lab to observing it, investigating it, modeling it, placing a control, detecting, hunting, responding, architecting, and communicating.

The transferable principles, already in learner-facing RC2 text and in control code, stay invariants:

- claim strength is no stronger than the evidence
- observation is not enforcement
- authorization is not execution
- an authorized action is not authorized data use
- a negative result is not proof of safety
- a control in the lab is not risk eliminated
- an external finding is not an authorization decision
- correlation is not causality

## 4. Current Capability Map

What a learner can actually do on RC2:

- Launch seven LIVE comparisons and copy a fresh `run.id`.
- Separate a tool request from CTRL-MCP-001.
- See retrieved text and recalled memory influence a request without minting a grant.
- See an authorized tool that is not an authorized objective.
- See an identity claim that is not authentication.
- Investigate canonical packets for a scanner finding and a garak result without treating them as the PDP.
- Reconstruct one integrated LIVE chain (L5).
- Investigate a REPLAY incident without being handed the story as the start of L6, then model one architecture, one privacy incident, one multi-stage case, and one mastery case.
- Write bounded conclusions, including NOT PROVEN.

What they cannot honestly claim:

- They authenticated an agent.
- They authorized a document for a user.
- They approved a human action.
- They proved a clean install.
- They installed a detector and measured its false-positive rate.
- They selected among a marketplace of security products.

## 5. Current Gaps

The gaps that matter, in learning order:

1. L4 is not a workshop. Path A still starts from a pasted `run.id`. L6 then asks for investigation without that scaffold.
2. Enabled detection coverage is empty. One detector exists and is off. Candidates are not validated as detections.
3. Identity is a claim. Workload identity, token audience, expiry, and revocation are not modeled.
4. Delegation is a fixture and a REPLAY confused-deputy case, not an authenticated agent-to-agent chain.
5. RAG proves influence. It does not prove document authorization, tenant isolation, or retrieval control.
6. Memory proves write and recall in-process. It does not prove ownership, deletion, or cross-user isolation.
7. There is no human-approval object, so learners cannot test replay of an approval or a parameter change after approval.
8. Supply chain is two pinned tools plus an ecosystem research note. There is no learner inventory of model, tool, prompt, and dependency.
9. Framework names are educational. The backlog still marks OWASP, ATLAS, MAESTRO, and NIST as NEEDS_EXTERNAL_VALIDATION.
10. Enterprise depth is one bank. Transfer is implied, not practiced on a second system.

## 6. External Tool Ecosystem

AgentSec should teach placement and evidence. It should not reimplement the tool.

| Tool | Value | Plane | Disposition |
|------|-------|-------|-------------|
| Cisco mcp-scanner | Already integrated. HIGH as the static MCP evidence example | Static scanning | KEEP. Do not extend into live MCP connect in the next phase |
| garak | Already integrated. HIGH as model-evaluation evidence | Model evaluation | KEEP. License and probe fidelity remain NEEDS_EXTERNAL_VALIDATION |
| Cisco aibom | HIGH later, as imported inventory evidence | Inventory / supply chain | DEFER. Do not build a private BOM. NEEDS_EXTERNAL_VALIDATION before any adapter |
| Cisco skill-scanner | MEDIUM after a skill surface exists | Static scanning | DEFER. No skill lab exists |
| Cisco DefenseClaw | NOT APPROPRIATE as a control | Policy / admission | DO NOT embed. It would collapse a finding into a deny |
| Cisco AI Defense inspect API | LOW for the academy core | Commercial inspection | DO NOT require. Network and API dependence |
| Snyk Agent Scan | MEDIUM comparison, DUPLICATES the scanner plane | Static or dynamic MCP scan | DEFER. Docs already warn the default path may start an MCP server |
| Promptfoo | MEDIUM, DUPLICATES the garak plane | Prompt / model eval | DEFER. Reference only until a reason exists that garak does not cover |
| PyRIT | LOW until a multi-turn model-chosen tool path exists | Red team orchestration | DEFER. Current tools are server-owned specimens, not model-selected |
| MITRE ATLAS, OWASP, CSA MAESTRO, NIST | HIGH as question frameworks | Knowledge, not evidence | REFERENCE. Identifiers stay NEEDS_EXTERNAL_VALIDATION |
| Splunk | Already the workbench. HIGH | Investigation | KEEP. Do not build a second SIEM |

## 7. AI Asset Inventory

A vendor-neutral inventory is worth teaching: agent, model, MCP server, tool, prompt, RAG source, memory, credential, policy, scanner. It supports attack-surface discovery and threat modeling.

Do not introduce Cisco aibom, or a homegrown BOM, as the next build. L7 already asks what the system is. An inventory workshop is P2, and it should be a reasoning artifact over the system the learner already ran, with each row marked IMPLEMENTED, SIMULATED, or NOT MODELED. Importing aibom output is a later evidence-plane exercise, not a new authorization path.

## 8. Identity and Credentials

CTRL-IDENTITY-001 records a claim. The module states that OBSERVE is not ALLOW, not DENY, and not a verified identity. That is the correct foundation.

A future module should separate claimed identity, authenticated identity, authorized principal, and executing actor. Static tokens, scoped tokens, short-lived credentials, rotation, and revocation are worth a lab only as comparisons on a fixture broker. A safe demonstration is: the same tool request with a long-lived claim versus a short-lived claim, and a use after the claim is expired or revoked. The PDP stays CTRL-MCP-001. The lab must not ship an OAuth server.

This is a major later module. It is not next. Evidence risk is high if the UI says “authenticated” for a string comparison.

## 9. A2A Security

The useful model is Agent A, delegation, Agent B, tool, downstream system: audience, expiry, scope narrowing, confused deputy, privilege amplification, replay, and revocation.

RC2’s identity lab and LAB-MCP-006 are synthetic. `docs/AGENTSEC_BUILD_VS_INTEGRATE.md` already says a later A2A lab should follow the public protocol rather than a fake regex. Building that now is a new trust domain. Defer until the defender bridge exists, and do not call a fixture “A2A authentication.”

## 10. HITL

Human approval is not universal security. The useful questions are who may approve, what evidence they saw, what parameters were bound, whether approval expires, whether it can be replayed, and whether a later parameter change bypasses it.

HITL should follow identity and delegation. An approval of an unauthenticated caller teaches the wrong lesson if it comes first. NOT MODELED today. P2.

## 11. Advanced RAG

Current RAG is fixture retrieval and context influence. The missing principle is: a retrieved document is not a document authorized for this user, agent, and purpose.

Poisoning, stale documents, excessive retrieval, metadata filters, and tenant isolation deserve an advanced lab later. A vector database should not be added. A second fixture corpus with an allow and a deny on retrieval purpose is enough when that phase is authorized. Not next. Learners still need to investigate the influence lab they already have.

## 12. Advanced Memory

Current memory is write, persist, recall, reuse, in-process, with fixture provenance. Direct retrieved-output-to-write causality is NOT PROVEN and should stay that way until a test shows it.

Missing: write authorization, recall authorization, ownership, deletion, retention, and cross-session or cross-user contamination. Those are P2. They must not be described as a production memory service.

## 13. Semantic and Input Security

CTRL-INPUT-001 is already an educational input check. It is not a general model firewall. A later lesson should keep the order: input control, then agent, then request, then authorization, then tool. A classifier must not become the tool PDP. Prompt filters, argument schemas, and output checks are P2 reference comparisons, not a product to build next. Do not embed LlamaFirewall or NeMo as the bank.

## 14. MCP and Tool Security

Beyond CTRL-MCP-001, RC2 already has REPLAY labs for scope, parameters, tool-result trust, catalog metadata, and confused deputy. Description poisoning is taught as data, with scanner evidence beside it.

Still unmodeled: dynamic registration, server substitution, rug pull, and transitive tool chaining as a fresh execution. Those should stay REPLAY or architecture exercises until a defender can hunt them. Do not open live third-party MCP in the core lab.

## 15. Supply Chain

Learners can see two pins and a research catalog. They do not practice model source, package hash, dataset, or attestation. Signing and attestation must not be claimed.

P2 is a static inventory of what this repo already pins, marked hashed or unpinned (`ollama/ollama:latest` is unpinned). That is honesty, not a new scanner. Dependency scanning products are out of scope.

## 16. Model Security

Jailbreaks, unsafe tool suggestions, and model provenance are real. garak already occupies model evaluation. Promptfoo and PyRIT would duplicate that plane.

AgentSec’s job is to ask what the model output was allowed to do next. Model intent is not capability, not authority, not execution, and not impact. Do not build a model-evaluation framework.

## 17. Autonomous Attack Reality

A flagship scenario should eventually force the questions: what authority, credentials, network path, tools, target, policy, approval, and telemetry existed, and what actually ran. The progression is intent, capability, authority, execution, impact.

RC2 already has the pieces in separate labs. A single “autonomous hack” story before learners can separate those stages will confirm the fear or dismiss it. That scenario is P2, after the defender bridge, and it must leave at least one impact claim NOT PROVEN. It is a good later mastery case. It is not the next build.

## 18. Advanced Privacy

L8 already separates authorized action from appropriate data use. Provider retention, training use, cross-border transfer, embedding leakage, and deletion verification are NOT MODELED. Teach them as questions and evidence gaps. Do not emit legal conclusions. P2.

## 19. Detection Engineering

The right progression is investigation, hunt, hypothesis, detection candidate, validation on ATTACK, RETEST, and BASELINE, then false positives and blind spots. RC2 stops at candidates and one disabled detector.

Do not enable DET-MCP-001, and do not add a detector, in the next phase. A later phase may let learners author one candidate and show that zero rows are not safe. Enabling a saved search is a product change and needs its own evidence.

## 20. Splunk Skill Development

Current path: paste `run.id`, read fields, compare ATTACK and RETEST, then L6 expects a hunt. The missing rungs are: find events without a known id, change one query, write a small `stats` query, and say what an empty result means.

`dc(_raw)` stays the completeness check. Indexed count stays the wrong execution count. Transactions stay something to justify, not a default.

## 21. Threat Hunting

Future hunts can target authority mismatch, repeated denies, fail-open allow, sensitive-field access, and delegation that widens scope. They must start from a behavior hypothesis. L6 and L10 are the right shape. They are hard because the search skills jump. Fix the bridge before adding hunt topics.

## 22. Threat Modeling

L7 is strong for one system. Later, a learner should place the same control question on five sketches: single agent and MCP, RAG plus memory plus tools, multi-agent, human approval, and a downstream production system. That comparison is P2. It is static. It should reuse L7’s method, not replace it.

## 23. Framework Synthesis

One crosswalk page would help: which framework answers which question, and what it cannot certify. Do not build it as a compliance engine. Any new identifier stays NEEDS_EXTERNAL_VALIDATION until the backlog item is closed. Not the next build.

## 24. Attack-Surface Architecture

The stack from human input through model, context, memory, goal, identity, authority, tool, and downstream impact, with supply chain, external evidence, observability, approval, and privacy beside it, matches how RC2 is already arranged. Use it as the picture in the defender bridge and in later architecture labs. Do not implement it as a new runtime.

## 25. Flight Recorder

A vendor-neutral checklist of input, context, memory, plan, identity, request, authorization, approval, invocation, execution, outcome, data change, and external finding is a good teaching view. Missing stages stay NOT MODELED, NOT OBSERVED, NOT CORRELATED, or NOT PROVEN. RC2 events already cover several of those stages. A flight recorder product is out of scope. A one-page evidence checklist inside the defender bridge is in scope.

## 26. Blue-Team Competencies

Completion should mean the learner can show work, not receive a certificate. Useful competencies: evidence reading, SPL, timeline, authority, execution proof, hunt, detection reasoning, privacy, external evidence, threat model, control placement, architecture review, response, and two kinds of writing (engineering and executive). L9 and L10 already ask for several of these. They are honor-system. Do not add a score store in the next phase.

## 27. Red and Blue Balance

RC2 is appropriately attack-then-investigate through L5, then investigation-heavy from L6 to L10. It is not too attack-heavy. The weakness is that blue-team skill arrives late and steep. External tools belong beside the timeline as evidence, after the learner can search.

## 28. Beginner-to-Expert Progression

Keep one academy. Tracks would split a story that is finally coherent. Optional depth can be marked on workshops (skip ORIENT if you already know agents) without a second curriculum. Revisit tracks only after the defender bridge and one advanced architecture lab exist.

## 29. Enterprise Scenarios

Three scenarios with the best transfer, all using the same principles:

1. **Banking customer operations.** Already the spine. Authority, customer data, and purpose limitation. Do not add a second bank.
2. **Software-engineering agent.** Tool execution against a repository, dependency trust, and blast radius. High transfer to anyone who ships code.
3. **IT or cloud operations agent.** Credentials, reachability, and change. Teaches capability versus authority without a new cloud.

Healthcare and customer-service variants add legal color more than new security reasoning. Defer them.

## 30. AI Security Toolbox

A toolbox workshop is worth P2: one page that compares tools by purpose, evidence plane, what they prove, and whether they enforce. Categories: MCP scanning, inventory, model evaluation, prompt testing, dependency scanning, runtime inspection. Cisco mcp-scanner and garak are the worked examples. Other names stay “not integrated.” This teaches selection. It is not a marketplace and not the next build.

## 31. Mastery Deliverables

L10 already expects an investigation, a threat-model update, a hunt, a detection candidate, and audience-specific writing. Keep those. Add, only after the bridge exists, a short evidence checklist and a system inventory with NOT MODELED rows. Do not add a certified badge. Do not require an AI-BOM file.

## 32. Final 1.0 Debt

Separate from advanced curriculum:

- Clean-room install is NOT PROVEN.
- Screen reader is NOT TESTED. No WCAG claim.
- `ollama/ollama:latest` is unpinned.
- garak license and probe fidelity are NEEDS_EXTERNAL_VALIDATION.
- Running lab images observed during RC2 validation still reported `1.0.0rc1` until rebuilt.
- Default clone is still `main`, which is RC1.
- Early mission cards reveal ATTACK outcomes. Path B is visible. Two evidence vocabularies remain. These are accepted teaching debt, not 1.0 blockers by themselves.

## 33. Five-Day Priorities

### P0 — before project delivery

No new feature. If someone will run the lab in front of learners:

- Use tag `v1.0.0-rc2`, not `main`.
- Say the clean-room install is not proven.
- If the live stack is shown, either rebuild so health matches `1.0.0rc2` or say the image is older than the tag.

### P1 — high-value next

One build: the Splunk Defender Bridge in section 35.

### P2 — after delivery

System inventory worksheet. Toolbox comparison page. One advanced RAG authorization fixture. Memory ownership and deletion questions. Detection-candidate validation on ATTACK, RETEST, and BASELINE, still not installed. Cross-architecture threat-model comparison. Software-agent and operations-agent scenarios.

### P3 — research

Authenticated delegation and a real A2A slice. JIT credential broker. HITL with expiry and replay. Imported aibom evidence. Snyk Agent Scan only if it can run on a static file. Framework identifier validation. Autonomous-operations mastery case.

## 34. Prioritization Matrix

Scores are judgment, not a formula. Complexity 5 is hardest. Evidence risk 5 is the easiest way to over-claim.

| Candidate | Learn | Security | Hands-on | Transfer | Reuse | Complexity | Evidence risk |
|-----------|-------|----------|----------|----------|-------|------------|---------------|
| Splunk Defender Bridge | 5 | 4 | 5 | 5 | 5 | 2 | 1 |
| Detection engineering, candidate only | 4 | 5 | 4 | 5 | 4 | 3 | 3 |
| AI inventory worksheet | 4 | 4 | 3 | 4 | 4 | 2 | 2 |
| Toolbox comparison page | 3 | 3 | 2 | 4 | 5 | 1 | 2 |
| Advanced RAG authorization | 4 | 5 | 4 | 4 | 3 | 4 | 3 |
| NHI / JIT credentials | 5 | 5 | 4 | 5 | 2 | 5 | 5 |
| A2A delegation | 5 | 5 | 4 | 4 | 2 | 5 | 5 |
| HITL | 4 | 4 | 4 | 4 | 2 | 4 | 4 |
| Another scanner or eval tool | 2 | 2 | 2 | 2 | 3 | 3 | 4 |

The bridge wins because it is the missing skill under every later row, and it can be wrong in a way a learner can see in Splunk without pretending a new control exists.

## 35. Recommended Next Build

**Splunk Defender Bridge**

Why this is next: L6, L9, and L10 already ask for independent investigation. L1 through L5 still hand the learner a `run.id` and, often, the conclusion. Adding identity, RAG authorization, or another scanner on top of that jump produces more pages the learner cannot search.

Learner value: they leave able to find events, change a search, and refuse to call an empty result safe.

Security value: hunt and detection start from behavior and evidence, not from a known incident id.

Architecture reuse: index `agentsec_telemetry`, sourcetype `otel:agentic:json`, existing LIVE and REPLAY runs, `dc(_raw)`, CTRL-MCP-001 fields. No new grant. No schema bump. No ExternalEvidence change. Splunk stays downstream.

Expected shape:

- STATIC lesson: what a search proves.
- REPLAY exercises on evidence already in the academy: discover without a pasted id, modify one query, write one `stats` query, compare ATTACK, RETEST, and BASELINE, and record one NOT PROVEN claim.
- No new LIVE attack required.
- A one-page flight-recorder checklist with explicit NOT MODELED rows for approval, authenticated identity, and retrieval authorization.

Evidence required: the searches run on the existing lab volume or on a documented REPLAY pack. Empty results stay “no evidence,” not safe. Do not count duplicate indexed copies as extra executions.

Maximum scope: one workshop, no new lab id on the Attack Service allowlist, no enabled detector, no new tool, no navigation redesign beyond adding the workshop if a later phase authorizes the UI change. This review does not authorize that implementation.

## 36. What NOT To Build Next

- A production OAuth server, PKI, or IAM.
- A custom model scanner, vulnerability scanner, SIEM, vector database, or AI firewall.
- DefenseClaw, or any path from scanner HIGH to DENY.
- A second eval harness beside garak.
- Cisco aibom or a private BOM implementation.
- Live third-party MCP.
- A new schema version or ExternalEvidence version.
- An enabled detector.
- L11 as a new attack domain.
- A broad UI rewrite.
- A certification or compliance engine.
- Several third-party integrations in one phase.

## 37. Longer-Term Roadmap

1. Splunk Defender Bridge.
2. Keep final 1.0 debt visible and close it only with measurement.
3. Static system inventory and a toolbox comparison that uses the two tools already integrated.
4. Advanced RAG purpose check and memory ownership as fixture labs, still not production stores.
5. Detection candidates validated against ATTACK, RETEST, and BASELINE, still not installed until a separate decision.
6. Identity and delegation that can say authenticated only when the lab actually checks a credential.
7. HITL after that, with expiry and replay.
8. One enterprise scenario beyond the bank, using the same invariants.
9. An autonomous-operations case whose impact line is allowed to remain NOT PROVEN.

Framework identifiers stay educational until externally validated. External tools stay evidence. CTRL-MCP-001 stays the tool PDP.
