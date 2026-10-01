# AgentSec final RC3 readiness review

Reviewed from the repository and from measurements in this gate. Parent commit `f4f9a43ff76658f3388e9345b04d4d5e16627ad0`. This review is part of the candidate that moves the product version to `1.0.0rc3`. It does not treat simulated or replayed workshop packets as newly measured runtime enforcement.

## Repository Integrity

`main` and `origin/main` are `e6115b6d1c03a1672b4364e84748c7840671fbfc`. Peeled `v1.0.0-rc1` is that same commit. Peeled `v1.0.0-rc2` is `1be214b92f840f843aaf27fb2b9536f764dd7126`. `git diff --check` was clean. Untracked `docs/plans/` and earlier identity and detection-engineering reviews were left untracked. PASS.

## Curriculum Integrity

L0–L10 identifiers are unchanged. The eight workshops sit on the published path as REPLAY checkpoints. No additional workshop was added in this gate. PASS.

## Security Semantics

CTRL-MCP-001 remains the tool PDP. Packet reasons for approval binding, credential lifetime, purpose, recall, provenance, code-agent scope, and change scope are teaching-packet strings and are not new branches in `authorize.py`. Searches of learner-facing text found the forbidden equivalences stated as claims to reject, not as instructions. DET-MCP-001 remains disabled. PASS.

## Workshop Coverage

Human approval, credential lifetime, RAG purpose, memory isolation, asset inventory, component provenance, code-agent bounds, and change bounds are present. ATTACK and RETEST share the malicious request in each packet that teaches a direct comparison. BASELINE uses a different disclosed request. Evidence class on those packets is SIMULATED or REPLAYED. PASS.

## Splunk Progression

The path still runs from the early LIVE labs through the Defender Bridge, Detection Engineering, identity, A2A, the new REPLAY workshops, L9, and L10. Mastery remains a separate check. DET-MCP-001 is not an enabled detector. PASS.

## Identity/NHI

The identity workshop still teaches that a claim is not authentication and that CTRL-IDENTITY-001 does not authenticate. PASS.

## A2A

The A2A workshop remains REPLAY. Delegation match is not authorization. No production A2A protocol was added. PASS.

## HITL

Approval binding mismatch is a teaching DENY in the packet. Human approval is not tool authorization. PASS.

## Short-Lived Credentials

An expired synthetic credential is not authority. The credential reference is simulated. PASS.

## RAG Purpose Authorization

Retrieval of the lending-policy fixture is not purpose authorization. CTRL-MCP-001 is not invoked for that workshop. PASS.

## Memory Isolation

Recall of another user's memory is not ownership. PASS.

## Asset Inventory

The inventory packet is a documented list. Trust is NOT ESTABLISHED. Cisco AI-BOM compatibility is NOT CLAIMED. PASS.

## Supply Chain / Provenance

`ollama/ollama:latest` is explicitly unpinned. A known component is not a tool grant. PASS.

## Software Engineering Scenario

Code Agent Bounds is SIMULATED / REPLAYED. It states that no GitHub credential is used. PASS.

## IT / Cloud Operations Scenario

Change Bounds is SIMULATED / REPLAYED. It states that no cloud account credential is used. A start is not a completed change. PASS.

## UI / UX

Headless Chrome on the running Academy, after app refresh, at 1920, 1440, 1280, and 1024. Measured titles were the view label plus ` | Splunk 10.2.7`. `undefined | Splunk` was not observed. At 1024 the A2A tab strip is wider than the viewport and sits in an `overflow: auto` container. Focusing CONCLUDE scrolled it into view (`scrollLeft` moved, and the tab rectangle fit inside 1024). At 200% CSS zoom on a 1024px window, Tool Authorization `scrollWidth` was 1920 and the last tab extended about 2px past the viewport while remaining hittable. PASS, with that Splunk tab-strip behavior recorded in `docs/KNOWN_LIMITATIONS.md`.

## Keyboard Accessibility

On Change Bounds, Tab walked Splunk chrome, the app navigation (including the new workshop labels), and the Studio toolbar, then reached the dashboard tab `MISSION` at Tab stop 42. Shift+Tab moved backward. ArrowRight then Space selected the next tab. The focused tab had `outline: none` and a blue inset `box-shadow`. A Splunk script node (`__splunkd_partials__`) appeared in the tab order. That node is Splunk chrome. No keyboard trap was observed in 60 Tab presses. PARTIAL, because of the Splunk script stop. AgentSec tabs themselves were reachable.

## Screen Reader

SCREEN READER: NOT TESTED. No WCAG claim.

## Clean-Room Installation

PROVEN for a fresh Compose project with new volumes. Details and clocks are in `docs/releases/V1_0_0_RC3_RELEASE_NOTES.md`. The model pull on that fresh volume failed with an x509 error against `registry.ollama.ai`. Service boot and Academy views did not depend on that pull. The original Splunk var volume was still mounted after the clean project was deleted.

## Version Alignment

Clean-room AcmeBank health, Attack Service health, and Splunk `app.conf` all reported the rc3 product version. In-process metadata: `1.0.0rc3`, schema `1.9.0`, ExternalEvidence `1.0.0`. No OCI image label is set. PASS.

## Third-Party Validation

Classified in `docs/reviews/AGENTSEC_RC3_THIRD_PARTY_CLASSIFICATION.md`. Nothing in that table is VALIDATED. Ollama digest was not invented. PARTIAL, meaning the backlog is explicit and unclosed.

## Test Reliability

Ten runs before the title fix: each `1 failed, 1063 passed, 3 deselected`, same assertion, deterministic. Ten runs after the fix: each `1064 passed, 3 deselected`. Final suite after the version-string update: `1064 passed, 3 deselected` in 10.18s. The RAG concurrency test did not fail in these runs. PASS.

## Secret Hygiene

No new private key, cloud key, or GitHub token was added. Synthetic credential names remain simulated. `.env` was not committed. PASS.

## Schema Integrity

`SCHEMA_VERSION` is `1.9.0`. PASS.

## ExternalEvidence Integrity

`EXTERNAL_CONTRACT_VERSION` is `1.0.0`. PASS.

## RC1 Integrity

Peeled `v1.0.0-rc1` is unchanged. PASS.

## RC2 Integrity

Peeled `v1.0.0-rc2` is unchanged. PASS.

## Learner perspectives

These are readings of the academy text and the measured UI, not timed studies with four people.

1. IT practitioner. Start at Academy Home. LIVE versus REPLAY is labeled. The code-agent and change workshops say they are REPLAY and that no GitHub or cloud credential is used. The fresh-volume model pull is now a documented step because health stays degraded without the model.
2. Security analyst or student. ATTACK, RETEST, and BASELINE are separate rows. BASELINE is a different request. An empty search is still taught as not proof of safety.
3. Blue-team defender. Splunk is downstream. Detection Engineering does not enable DET-MCP-001. A scanner finding and a garak result are not authorization.
4. AI-security practitioner. Claim, authentication, approval, retrieval, recall, inventory, and provenance stay separated from tool authorization. Execution is separated from completion and from impact in the change workshop.

No HIGH or MEDIUM learner blocker remained after the title fix, the operational-detection wording fix, and the model-pull documentation fix.

## Counts

| Severity | Count |
|----------|-------|
| BLOCKER | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 4 |

LOW-1. `ollama/ollama:latest` is unpinned. No digest was measured.

LOW-2. Screen reader was not tested.

LOW-3. Splunk's tab strip scrolls horizontally at 1024px on the longest workshops, and a Splunk script node is in the Tab order.

LOW-4. On this host, `ollama pull llama3.2:1b` inside a fresh container failed TLS verification. That is an environment observation. It is not a reason to disable certificate checks.

## Decision

BLOCKER 0. HIGH 0. No unresolved MEDIUM affects correctness, security semantics, installation of the academy stack, or learner understanding of the teaching distinctions. Clean-room service installation was proven. Version alignment passed. Secret hygiene passed. RC1 and RC2 were unchanged. Schema and ExternalEvidence were unchanged. The offline suite passed.

GO — CREATE v1.0.0-rc3
