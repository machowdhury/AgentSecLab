# AgentSec v1.0.0 final release review

Qualification parent: `v1.0.0-rc3` peeled commit `6c7af8e87f96cda4ee929664fbb17ec763dd135c`. This review is the qualification record. It does not create the `v1.0.0` tag. Package version remains `1.0.0rc3` until an authorized tag. Schema remains `1.9.0`. ExternalEvidence remains `1.0.0`.

## Repository Integrity

Working tree changes for this qualification are install honesty for the Ollama model, preflight port matching for the lab's own collector, and these release documents. `git diff --check` was clean. Untracked `docs/plans/` and earlier review files were not staged. PASS.

## RC1 Integrity

Peeled `v1.0.0-rc1` is `e6115b6d1c03a1672b4364e84748c7840671fbfc`. PASS.

## RC2 Integrity

Peeled `v1.0.0-rc2` is `1be214b92f840f843aaf27fb2b9536f764dd7126`. PASS.

## RC3 Integrity

Peeled `v1.0.0-rc3` is `6c7af8e87f96cda4ee929664fbb17ec763dd135c`. The tag object is `853b7c33bbc82945431e90c87df3da86e1eb8b4f`. This qualification does not move it. PASS.

## Main Integrity

`main` and `origin/main` are `e6115b6d1c03a1672b4364e84748c7840671fbfc`. Not merged. PASS.

## Develop Integrity

`develop` was `6c7af8e87f96cda4ee929664fbb17ec763dd135c` and matched `origin/develop` at the start of this qualification. PASS.

## Product Identity

Package `1.0.0rc3`. Splunk app `1.0.0-rc3`. These strings were not changed to `1.0.0` because the tag was not created. PASS.

## Version Alignment

Clean-room AcmeBank and Attack Service health reported `1.0.0rc3`. Attack Service `schema_version` was `1.9.0`. Splunk `app.conf` in the clean container was `1.0.0-rc3`. PASS.

## Schema Integrity

`SCHEMA_VERSION` is `1.9.0`. PASS.

## ExternalEvidence Integrity

`EXTERNAL_CONTRACT_VERSION` is `1.0.0`. PASS.

## LIVE Labs

Seven LIVE labs remain the launchable set. Clean-room AcmeBank reported `status: degraded` and `ollama_reachable: false` because `llama3.2:1b` was not listed. That is not a PASS for LIVE generation. PASS for the lab inventory. LIVE model use is DEGRADED on this host.

## REPLAY Workshops

Twenty-four REPLAY academy surfaces remain. Their packets stay SIMULATED or REPLAYED. PASS.

## Curriculum Integrity

L0–L10 identifiers were not changed. No workshop was added. PASS.

## Security Semantics

CTRL-MCP-001 remains the tool PDP. DET-MCP-001 was not enabled. No authorization branch was added. Searched learner text did not add a new claim that equates identity, delegation, approval, retrieval, recall, inventory, provenance, scanner output, or garak output with authorization. PASS.

## Splunk Semantics

Splunk remains downstream evidence. `lab-ready` now says SERVICE READY and, when the model is missing, `MODEL ABSENT` and `DEGRADED, not PASS`. PASS.

## Detection Engineering

The workshop remains REPLAY. DET-MCP-001 stays disabled. PASS.

## Identity/NHI

A claim is still not authentication. CTRL-IDENTITY-001 is not an authenticator. PASS.

## A2A

Delegation is still not authorization. No production protocol was added. PASS.

## HITL

Approval is still not tool authorization. PASS.

## Credential Lifetime

A synthetic credential status is still not authority. PASS.

## RAG Purpose Authorization

Retrieval is still not purpose authorization. PASS.

## Memory Isolation

Recall is still not ownership. PASS.

## Asset Inventory

The inventory is still not trust and is not a Cisco AI-BOM. PASS.

## Supply Chain / Provenance

`ollama/ollama:latest` remains unpinned. The local image that reproduced the TLS failure identified as `sha256:684d8674b4315fa18f4f0e973a118ec2652ed96f67563277839985175858e0ba`. That id was read from the local image. It was not written into Compose. PASS.

## Software Engineering Scenario

Code Agent Bounds stays SIMULATED / REPLAYED and states that no GitHub credential is used. PASS.

## IT / Cloud Operations Scenario

Change Bounds stays SIMULATED / REPLAYED and states that no cloud credential is used. PASS.

## External Tools

| Item | Class |
|------|--------|
| garak v0.17.0 git tag LICENSE file | DOCUMENTED. Fetched 2026-10-02 from the tag. The file is Apache License 2.0. The installed wheel hash was not compared to that tag. |
| garak `dan.Dan_11_0` and detector `DAN` | DOCUMENTED names in tag `v0.17.0`. Upstream detector text says a pass is absence of a `[DAN]` marker. That was not run here. Behavioral fidelity stays NEEDS_EXTERNAL_VALIDATION. A pass is not "safe". |
| Cisco mcp-scanner role | EDUCATIONAL ONLY. A finding is not a DENY. |
| mcp-scanner JSON stability | NEEDS_EXTERNAL_VALIDATION. Local specimen version remains 4.8.4. Not re-measured. |
| Cisco AI-BOM | NEEDS_EXTERNAL_VALIDATION. Compatibility stays NOT CLAIMED. |
| OWASP, NIST, MITRE ATLAS | EDUCATIONAL ONLY. Not compliance. ATLAS tags still say revalidation is required. |
| Ollama image provenance | DOCUMENTED local image id above. Tag `latest` is unpinned. Model pull inside that image is an external TLS failure. |

PARTIAL. No item was upgraded to a compliance claim.

## UI / UX

Dashboard XML was not redesigned. The RC3 viewport measurement still applies: titles are the view labels, and the longest tab strip scrolls at 1024px. PASS for the unchanged shell, with that Splunk behavior in the known limitations.

## Keyboard Accessibility

PARTIAL. The RC3 keyboard walk still applies because the tab widgets were not changed. Tab reached dashboard tabs. Arrow and Space changed the selected tab. A Splunk script node is in the tab order. Focus used a blue inset ring.

## Screen Reader

SCREEN READER: NOT TESTED. VoiceOver was not running. It was not started. No WCAG claim.

## Clean-Room Installation

PROVEN for a new Compose project and new volumes on 2026-10-02.

| Mark | UTC | From start |
|------|-----|------------|
| Compose start | 2026-10-02T00:37:59Z | 0 |
| Ollama and Splunk containers started | 2026-10-02T00:38:21Z | 22s |
| Earliest retained Splunk healthy check | 2026-10-02T00:41:19Z | 3m 20s |
| Compose exit 0 | 2026-10-02T00:42:37Z | 4m 38s |
| `lab-ready` SERVICE READY and Home sentence confirmed | 2026-10-02T00:44:06Z | 6m 7s |

AcmeBank health: HTTP 200, `version` `1.0.0rc3`, `status` `degraded`, `ollama_reachable` false. Attack Service: HTTP 200, `version` `1.0.0rc3`, `schema_version` `1.9.0`, `status` healthy. Splunk container: healthy. App version: `1.0.0-rc3`. Sixteen academy views returned HTTP 200 on the restored stack after the clean project was removed. The original Splunk var volume was mounted again.

## Ollama Dependency

DOCUMENTED EXTERNAL DEPENDENCY. Host `curl` to `https://registry.ollama.ai/v2/library/llama3.2/manifests/1b` returned HTTP 200. The same pull inside `ollama/ollama:latest` failed with `x509: certificate signed by unknown authority`, including on this fresh volume at 2026-10-02T00:38:23Z. Certificate verification was not disabled. Preflight warns when the model is absent. `lab-ready` prints `MODEL ABSENT` and `DEGRADED, not PASS`.

## Third-Party Validation

PARTIAL. See the table above. Unresolved items are release debt.

## Test Reliability

Ten consecutive offline suites after these changes: each `1065 passed, 3 deselected`, exit 0. Durations were 8s to 11s. No failure was discarded. PASS.

## Secret Hygiene

No new credential, private key, or certificate was added. `.env` was not committed. PASS.

## Documentation

Quickstart and README now say the container tries the model pull, that a TLS failure is a trust-layer problem, and that a missing model is degraded rather than ready. Relative links in README, Quickstart, Getting Started, and Known Limitations resolved on disk. PASS.

## Counts

| Severity | Count |
|----------|-------|
| BLOCKER | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 4 |

LOW-1. `ollama/ollama:latest` stays unpinned.

LOW-2. Screen reader was not tested.

LOW-3. Splunk tab-strip scrolling and a Splunk script node in the Tab order remain platform limits.

LOW-4. Garak wheel hash, probe execution, Cisco JSON stability, Cisco AI-BOM, and framework mappings stay unclosed.

## Accepted Release Debt

1. Ollama model pull fails inside the published image on this host because of TLS verification. LIVE generation stays degraded until that trust path works. Academy REPLAY does not use the model.
2. External tool and framework items in the table above that are not VALIDATED.
3. No screen-reader pass, and no WCAG claim.
4. No final `v1.0.0` tag in this qualification.

## Decision

`GO — v1.0.0 RELEASE QUALIFIED`

The tag was not created by this review. `main` was not modified by this review.

## Promotion note

An authorized promotion may change the product identity from `1.0.0rc3` / `1.0.0-rc3` to `1.0.0` after this review. That change does not rewrite the measurements above. Clean-room health on 2026-10-02 reported the rc3 strings and a degraded model. SCREEN READER: NOT TESTED. No WCAG claim. The Ollama TLS failure remains a documented external dependency. Degraded LIVE generation is not healthy.
