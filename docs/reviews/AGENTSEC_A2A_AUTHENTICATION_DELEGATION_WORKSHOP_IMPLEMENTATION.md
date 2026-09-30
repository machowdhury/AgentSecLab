# A2A Authentication and Delegation workshop — implementation

## Repository

Starting Commit: `7335a540d2259e191fc477b6644e19f578402add`

Ending Commit: the bounded implementation commit recorded in the completion response after `git rev-parse HEAD`

Remote Sync at start: PASS. `HEAD`, `develop`, and `origin/develop` matched the reviewed design commit.

The design and remediation report were tracked. The GO design re-review was a valid local authorization artifact and is included with this implementation. Unrelated `docs/plans/` and older untracked review files were preserved.

`main` remained `e6115b6d1c03a1672b4364e84748c7840671fbfc`. Peeled `v1.0.0-rc2` remained `1be214b92f840f843aaf27fb2b9536f764dd7126`. No RC3 was created.

## Workshop

Workshop Mode: REPLAY / STATIC

Curriculum Placement: `L7 → Identity/NHI Workshop → A2A Authentication & Delegation Workshop → L8`

Exactly one workshop was added: `LAB-A2A-AUTH-DELEGATION`, Studio view `ws_lab_a2a_auth_delegation`. Levels remain L0–L10. The workshop has no `lab-manifest.json`, is not in `known_lab_ids()`, and is not a LIVE launcher.

The learner flow is:

MISSION → CLAIMS → AUTHENTICATE → DELEGATE → REQUEST → AUTHORIZE → EXECUTE → COMPARE → LEDGER → CONCLUDE → PATH B

## Evidence

Historical Evidence Status: CLAIM-ONLY. The historical search is restricted to `agentsec.lab.id=agentsec-local` activity selected by `agentsec.workflow.entry=/identity/delegate`. The workshop states the previously measured run counts as ATTACK 6, RETEST 6, BASELINE 1, and the previously measured zero counts for `who_authenticated` and `LAB-AGENT-DELEGATION-001`. It does not relabel those events as authentication or delegation.

Simulated Authentication Status: CLEARLY LABELED. `evidence.packet.json` uses `SIMULATED AUTHENTICATION RESULT`, synthetic `sim-auth-ref-*` metadata, and no credential material. It says the packet is not runtime telemetry or production IAM.

Simulated Delegation Status: CLEARLY LABELED. The packet uses `SIMULATED DELEGATION DECISION`, a synthetic delegation id, and separate tool, scope, resource, audience, and time fields.

ATTACK Request: `lookup_customer_tier` / `cust-001`

RETEST Request: `lookup_customer_tier` / `cust-001`

BASELINE Request: `lookup_policy` / `lending-basics`

ATTACK and RETEST share the same MISMATCH against the `lookup_policy` / `lending-basics` grant. ATTACK has the labeled vulnerable CTRL-MCP-001 ALLOW. RETEST has DENY `tool_not_granted`. BASELINE is a different in-scope request with MATCH and ALLOW `tool_granted`.

## Security boundaries

Tool Scope vs Resource Scope: SEPARATED. The ledger requires delegated and requested tool and resource columns. A same-tool / different-resource case is explicitly NOT MODELED in this workshop.

Authentication vs Delegation: SEPARATED. Authentication results do not create a grant.

Delegation vs Authorization: SEPARATED. MATCH and MISMATCH are evidence, not tool ALLOW or DENY.

Authorization vs Execution: SEPARATED. CTRL-MCP-001 ALLOW is not `agentsec.mcp.started`.

Execution vs Resource Impact: SEPARATED. A start does not prove completion or downstream change. Resource impact stays NOT PROVEN.

CTRL-IDENTITY-001 Role: claim observation only.

CTRL-MCP-001 Role: the existing tool PDP.

Splunk Role: downstream investigation and comparison. Splunk does not authenticate, delegate, authorize, execute, or prove resource impact.

## Validation

Focused Tests:

`60 passed in 0.27s`

After the full suite exposed the repository-reserved `Q-A2A*` prefix, the historical investigation search was renamed to `Q-AUTH-DELEGATION-HISTORICAL.spl`. The relevant regression set then passed:

`19 passed in 0.06s`

Full Offline Tests:

`1047 passed, 3 deselected in 9.76s`

The first full attempt was `1044 passed, 3 deselected, 3 failed`; all three failures were the reserved search-prefix contract. No assertion was weakened. The final suite passed.

These tests validate repository and workshop contracts. They do not prove runtime A2A authentication or delegation enforcement.

`git diff --check`: PASS.

Schema: unchanged at `1.9.0`.

ExternalEvidence: unchanged at `1.0.0`.

DET-MCP-001: unchanged and disabled. `savedsearches.conf` was not modified.

Runtime and authorization code: unchanged.

## Live Splunk validation

`./scripts/lab-up.sh --refresh-app` restaged the app and returned READY. The deployed container contains `ws_lab_a2a_auth_delegation.xml`. The unauthenticated web route returned HTTP 303 to login, which is expected.

An authenticated REST export of the historical search was attempted but the command was blocked by the execution approval layer. No new Splunk counts are claimed. The 6 / 6 / 1 counts in the workshop remain previously measured evidence.

## UI / UX

The generated Dashboard Studio definition uses the existing Academy visual language, shared Studio defaults, `layout_options()`, no run-id input, and no GFM markdown table. The app was restaged successfully.

Browser viewport validation at 1920, 1440, 1280, and 1024 was attempted. The unrestricted browser command was blocked by the execution approval layer; the sandboxed retry could not launch Chrome. Therefore horizontal overflow, obscured tabs, toolbar overlap, keyboard tab behavior, visible focus, and 200% zoom/reflow are NOT TESTED for this new view.

The previously observed Splunk toolbar overlap at narrower widths remains a known platform risk. It is not hidden or reported as fixed.

Accessibility: screen reader NOT TESTED. No accessibility or WCAG compliance claim.

## Secret hygiene

PASS. Focused scans found no API keys, tokens, passwords, private keys, certificates, Authorization headers, JWT-shaped values, or `.env` content in the packet, builder, or generated view.

Credential references are visibly synthetic identifiers: `sim-auth-ref-advisor-001` and `sim-auth-ref-fulfillment-001`. They are metadata, not proof of possession.

No certificate data or cryptographic implementation was introduced. Codeguard was applied by excluding credentials, certificates, and crypto from this static teaching packet.

## Known limitations

1. The packet is SIMULATED / REPLAYED. It is not runtime authentication or delegation enforcement.
2. Historical corpus counts were not newly measured in this implementation.
3. The teaching case changes tool and resource together. A same-tool / different-resource case is NOT MODELED.
4. Resource impact remains NOT PROVEN in every mode.
5. Browser and screen-reader validation are NOT TESTED because the browser launch approval was unavailable.
6. The implementation report cannot embed its own final commit hash; the completion response records it.

## Git status

The implementation commit includes only the bounded workshop, its generated Academy surfaces, registration, focused tests, learning note, this report, and the related GO design re-review. Unrelated untracked files remain excluded.

# BUILD COMPLETE — READY FOR INDEPENDENT REVIEW

STOP.

DO NOT BEGIN HITL.

DO NOT BEGIN SHORT-LIVED CREDENTIALS.

DO NOT BEGIN RAG AUTHORIZATION.

DO NOT BEGIN MEMORY ISOLATION.

DO NOT BEGIN AI-BOM OR SUPPLY-CHAIN SECURITY.

Await independent A2A workshop review.
