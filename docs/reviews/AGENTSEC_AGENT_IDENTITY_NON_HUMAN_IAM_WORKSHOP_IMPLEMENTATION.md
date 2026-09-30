# Agent Identity and Non-Human IAM workshop — implementation

Evidence classes below are MEASURED only where a Splunk export or a test process ran in this change. Design text is DOCUMENTED. Browser pixels were not collected.

## Starting commit

`91f3e089b99a85a631c25aade311ba9d483990bb`

`origin/develop` matched that commit before this change. `main` and `origin/main` were not moved. `v1.0.0-rc2` was not moved. No RC3 tag was created.

## Ending commit

The commit that adds this report. The completion message records the hash after `git rev-parse`.

## Curriculum placement

Checkpoint `AGENT-IDENTITY-NHI`, placement `L7 → Identity/NHI Workshop → L8`. Levels remain L0–L10. Navigation collection **Agent Identity** sits after Security Architecture and before Privacy. L8 prerequisites name this workshop. Home describes it as a REPLAY checkpoint, not a LIVE launcher.

## Workshop mode

REPLAY / static. `live_launcher` is false. `LAB-AGENT-IDENTITY-NHI` is not in `known_lab_ids()` and has no `lab-manifest.json`. No new attack was launched.

## Measured corpus

Filter: `agentsec.workflow.entry=/identity/delegate` on `index=agentsec_telemetry`. Indexed lab id on those rows: `agentsec-local`.

Search for `agentsec.lab.id=LAB-AGENT-DELEGATION-001`: count 0. That lab id is not the indexed key.

Run counts from `Q-ID-MODES.spl` (MEASURED, existing corpus, no new attack):

- ATTACK 6
- RETEST 6
- BASELINE 1

These are run counts. They are not one shared CTRL-MCP-001 decision.

`Q-ID-CONTROLS.spl` (MEASURED):

- Every mode: CTRL-IDENTITY-001 OBSERVE, reason `identity_claim_is_not_grant`
- ATTACK: CTRL-MCP-001 ALLOW, reason `vulnerable_profile_fail_open:caller_identity_derived_authority` (6 runs)
- RETEST: CTRL-MCP-001 DENY, reason `tool_not_granted` (6 runs)
- BASELINE: CTRL-MCP-001 ALLOW, reason `tool_granted` (1 run)

`Q-ID-STARTS.spl` (MEASURED):

- ATTACK: 6 starts, `gen_ai.agent.id=acme-agent-fulfillment-006`, `agentsec.principal.type=user`
- BASELINE: 1 start, same agent id and principal type
- RETEST: no start rows

The start rows did not return `agentsec.control.id`. A start can carry an agent id without a control id.

`who_authenticated` search: count 0. Authentication is NOT MODELED.

The same counts were still present after `./scripts/lab-up.sh --refresh-app`.

## Identity semantics

`applicant-web` is a principal label. The workshop states it is not proven to be a human, not proven authenticated, and not proven to have caused the tool call.

`acme-agent-advisor-005` is a caller claim. `acme-agent-fulfillment-006` is a callee claim. Neither is presented as an authenticated principal or as legitimate delegated authority.

`agentsec.principal.type=user` is taught as an emitter limitation, including on callee events. The emitter and schema 1.9.0 were not changed.

## Authorization semantics

CTRL-IDENTITY-001 observes a claim. OBSERVE is not ALLOW. It does not authenticate a principal and does not authorize a tool.

CTRL-MCP-001 remains the tool policy decision point. Its decision event is the authorization evidence.

`caller_identity_derived_authority` is labeled an authorization fault. It is not authenticated delegation, legitimate delegation, verified identity, valid agent authority, or production IAM.

## Execution semantics

Execution evidence is `event.name=agentsec.mcp.started`, bounded to observed runtime execution. `gen_ai.agent.id` does not by itself prove execution. Splunk remains downstream.

## Splunk searches

- `learning/level_1/LAB-AGENT-IDENTITY-NHI/searches/Q-ID-MODES.spl` — run counts by mode
- `Q-ID-CONTROLS.spl` — control, decision, and reason by mode
- `Q-ID-STARTS.spl` — start events by mode

All three use `earliest=0` and the workflow entry. None filter on `LAB-AGENT-DELEGATION-001`. Path A does not contain a run identifier. Path B holds the finished searches. The mission does not state the mode comparison.

## Evidence ledger

The EVIDENCE LEDGER tab lists the required claims and the boundary for each: human attribution NOT PROVEN, authentication NOT PROVEN / NOT MODELED, identity control FALSE as authentication and FALSE as tool authorization, agent id FALSE as execution proof, CTRL-MCP-001 SUPPORTED only by its decision event, and `agentsec.mcp.started` YES as bounded execution evidence.

## Failure states

The page uses NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, AUTHENTICATION NOT OBSERVED, ATTRIBUTION NOT PROVEN, and CORRELATION NOT ESTABLISHED. It tells the learner not to write SAFE, AUTHENTICATED, TRUSTED, or AUTHORIZED HUMAN without evidence.

## Production identity gaps

GAPS lists authenticated principal, issuer, authentication method, workload identity, session, tenant, owner, lifetime, issuance, expiry, rotation, revocation, delegation proof, audience, and scope as NOT MODELED. Nothing in that list was implemented.

## Future bridge

Authenticated A2A, delegated authority, short-lived credentials, human approval, retrieval authorization, memory ownership, AI bill of materials, and supply-chain trust are labeled FUTURE / NOT MODELED.

## UI validation

`./scripts/lab-up.sh --refresh-app` restaged the app and returned READY.

Splunk REST `servicesNS/nobody/agentsec/data/ui/views/ws_lab_agent_identity_nhi` returned HTTP 200. The body contained the label `Agent Identity and Non-Human IAM` (3 hits).

Viewport checks at 1920, 1440, 1280, and 1024, keyboard focus, and 200% zoom were not executed. The browser runner did not complete. Screen reader was not available and was not tested. No WCAG conformance claim.

## Accessibility

NOT TESTED for keyboard, visible focus, zoom, and screen reader, for the reason above. No WCAG claim.

## Tests

`tests/splunk/test_agent_identity_nhi_workshop.py` is the focused contract (placement, REPLAY, no run id, unindexed lab id not required, claim boundaries, schema and external-evidence versions, no saved-search stanza for this lab).

Full offline command:

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

Result: 1042 passed, 3 deselected, 9.57s.

## Secret hygiene

No passwords, tokens, API keys, private keys, or certificates were added. No new cryptography. `.env` was not committed. The measurement process read `SPLUNK_PASSWORD` from `.env` inside the process and did not print it. The one-shot measurement scripts were deleted before commit. Codeguard credential, certificate, and crypto rules were applied by not introducing those materials; this workshop teaches identity claims without implementing credentials.

## Known limitations

1. `agentsec.principal.type=user` remains an emitter behavior. This change does not fix it.
2. `who_authenticated` is not an indexed attribute. Count was 0.
3. Start events in this corpus omitted `agentsec.control.id`.
4. RETEST has identity and tool decisions and no `agentsec.mcp.started` rows.
5. Browser layout, keyboard, zoom, and screen reader were not measured.
6. Run counts 6 / 6 / 1 are corpus size, not a shared authorization outcome.

## Git status

Unrelated untracked files were left untracked: `docs/plans/`, the detection-engineering independent review, the identity design independent review, and the identity design re-review. This implementation does not modify `main`, the RC tags, schema 1.9.0, ExternalEvidence 1.0.0, `savedsearches.conf`, or the Attack Service allowlist.
