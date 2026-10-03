# AGENTSEC VISUAL LEARNING EXPERIENCE IMPLEMENTATION

Evidence classes stay separate. A passing test is not a Splunk-hosted render. A local static dump is not Dashboard Studio. HEC health is not indexed evidence.

Starting Commit: `c0621083c0af66b698c03302f59f8cb7c01c2718`
Ending Commit: pending this commit
Origin/Develop: `c0621083c0af66b698c03302f59f8cb7c01c2718` before push
Remote Sync: pending push

Independent visual brief: style Your Path, differentiate inline evidence tables, decide progress versus navigation, add workshop flow diagrams, and strengthen predict-before-click. Security semantics were not changed.

## PRECONDITION — YOUR PATH

Rendered Before Styling: YES on a local static page that injected `agentsec_learner_path.js` from a `DOMContentLoaded` handler. Headless Chrome dump contained `Direct Prompt Injection`, `agentsec-progress-tally`, `NOT STARTED`, `Reset learning progress`, and `data-agentsec-mounted`.
Curriculum Visible: YES on that local page.
Progress Visible: YES. Fresh learner state was `NOT STARTED`.
Reset Visible: YES.
Stale Asset Observed: NOT MEASURED on Splunk or EC2. This machine did not open `/en-US/app/agentsec/learner_path` in a running Splunk.
Classification: SOURCE FIX ALREADY PRESENT. LOCAL STATIC RENDER PROVEN. SPLUNK-HOSTED PAINT NOT MEASURED.

## ITEM 1 — YOUR PATH VISUAL DESIGN

Files Modified: `splunk_app/agentsec/appserver/static/agentsec_learner_path.js`, `tests/unit/test_learner_progress.py`
Design System Used: `docs/AGENTSEC_UI_DESIGN_SYSTEM.md` palette. Navy `#0B1F33`, teal `#007F86`, page `#F6F8FB`, success `#2E7D32`, warning `#B7791F`, text `#17202A`, border `#D9E0E7`.
Page Hierarchy: title `Your path`, intro that progress is navigation, then a summary card, then workshop cards.
Progress Summary: tally remains `#agentsec-progress-tally` and now names INVESTIGATED n of catalog size plus the next workshop title. Counts stay the existing three states. No score.
Workshop Cards: each catalog row is a card with the existing link, status id, and two native buttons.
NOT STARTED Treatment: muted left edge `#8AA0B4` and muted status text.
IN PROGRESS Treatment: amber/warning-family left edge and status `#B7791F`.
INVESTIGATED Treatment: green/success-family left edge and status `#2E7D32`, with copy that the mark is not a safety verdict.
Buttons: native `button` elements, hover/active, teal focus outline, 2.75rem minimum height.
Keyboard: native links and buttons. Focus outline `#007F86`.
1920: NOT MEASURED
1440: LOCAL STATIC dump after styling contained the curriculum, tally, cards, and reset. Window size was 1440x900. Overflow not measured as a layout metric.
1280: NOT MEASURED
1024: NOT MEASURED
True Browser 200% Zoom: NOT MEASURED
Live Render: LOCAL STATIC after styling. Dump contained `Your path`, `agentsec-path-card`, `agentsec-path-summary`, `INVESTIGATED means you marked`, and the reset control. Splunk-hosted paint NOT MEASURED.
Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED for the Splunk-hosted page.

## ITEM 2 — INLINE EVIDENCE TABLES

Labs Inventoried: 31 workshop dashboards. 13 contain `viz_guide_events` / `viz_guide_summary`.
Tables Inventoried: 26 guide tables.
Dashboard Studio Supported Mechanism: `splunk.table` `options.columnFormat` plus `context` `matchValue` arrays. Documented in Splunk Enterprise Dashboard Studio table / dynamic options syntax.
Unsupported Mechanisms Rejected: app stylesheet injection, custom Studio JavaScript, vendor JS patches, invented table properties, SPL edits for color.
ALLOW Treatment: informational blue text `#3568A8` on `#E8EEF5`. Not green.
DENY Treatment: warning-family `#B7791F` on `#F6EBD8`. Not a grade.
executed=true Treatment: navy `#0B1F33` with white text. Distinct from ALLOW.
executed=false Treatment: muted `#3D4654` on `#EEF1F4`.
Labs Updated: the 13 labs that already used the guide-table pattern. Future `table()` helper output in `scripts/agentsec_studio.py` keeps the same format.
Live Render: NOT MEASURED. Studio tables were not opened in Splunk.
ALLOW-is-not-execution Preserved: YES. ALLOW is not green. Execution uses a different color family. Existing table descriptions still say a decision column is not execution.
Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED in Studio with a real run.id.

## ITEM 3 — PROGRESS / NAVIGATION

Progress Storage: `agentsec.learner.progress.v1` in browser localStorage.
Dashboard Studio Access: none. Studio views do not load AgentSec JavaScript.
Native Navigation Access: none. Native Splunk chrome has no supported AgentSec injection point.
Supported Extension Point Found: NO for live badges on Home or native nav.
Evidence: classic Your Path view already runs `agentsec_learner_path.js`. Studio views were previously proven not to load an app stylesheet. `tests/unit/test_learner_console.py` still forbids `stylesheet=` on `ws_*.xml` and forbids `agentsec_studio_focus.css`.
Chosen Architecture: Your Path remains the authoritative progress surface. Home and troubleshooting now say that explicitly. Workshop “Record navigation on Your path” cues were left in place.
Your Path Authoritative: YES
Native Nav Modified: NO
Home Progress Modified: NO
Unsupported Injection Added: NO
Status: PLATFORM LIMITATION — YOUR PATH REMAINS AUTHORITATIVE

## ITEM 4 — WORKSHOP FLOW DIAGRAMS

Total Workshops: 31
Existing ASCII/Structured Flows Found: 13
Converted From Existing Flow: 13
Authored From Workshop Prose: 18
Insufficient Source: 0
SVG Assets Added: 31 under `splunk_app/agentsec/appserver/static/flows/`
Dashboard Views Updated: 31 JSON definitions and 31 Studio XML views
Live Rendered: LOCAL file render of `flow-lab-pi-001.svg` was attempted; the screenshot file was not captured. Asset XML/SVG validity is proven in tests. Studio image placement NOT MEASURED.
Answer Leakage: diagrams use structural ALLOW / DENY language. They do not name expected ATTACK or RETEST results.
Horizontal Overflow: NOT MEASURED in Studio. Image blocks are 1440x200 with `preserveAspectRatio: true`.
Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED in Studio.

| Lab | Existing flow | Source | Diagram | Control | Execution | Telemetry | Asset | Live |
|---|---|---|---|---|---|---|---|---|
| LAB-PI-001 | YES | ASCII | YES | CTRL-INPUT-001 | Ollama / acmebank.llm_call | Splunk investigation | `flows/flow-lab-pi-001.svg` | NO |
| LAB-MCP-001 | YES | ASCII | YES | CTRL-MCP-001 | Tool handler | Splunk (observe only) | `flows/flow-lab-mcp-001.svg` | NO |
| LAB-MCP-003 | YES | ASCII | YES | CTRL-MCP-001 | Tool handler | Splunk | `flows/flow-lab-mcp-003.svg` | NO |
| LAB-MCP-004 | NO | PROSE | YES | CTRL-MCP-001 | Tool handler | Splunk | `flows/flow-lab-mcp-004.svg` | NO |
| LAB-MCP-005 | YES | ASCII | YES | CTRL-MCP-001 | lookup_policy, then follow-on handler | Splunk | `flows/flow-lab-mcp-005.svg` | NO |
| LAB-MCP-006 | YES | ASCII | YES | CTRL-DELEGATION-001 then CTRL-MCP-001 | Tool handler | Splunk | `flows/flow-lab-mcp-006.svg` | NO |
| LAB-MCP-CATALOG | YES | ASCII | YES | CTRL-MCP-001 | Handler only after ALLOW | Splunk | `flows/flow-lab-mcp-catalog.svg` | NO |
| LAB-RAG-CONTEXT | YES | ASCII | YES | CTRL-MCP-001 | Handler | Splunk | `flows/flow-lab-rag-context.svg` | NO |
| LAB-MEMORY-001 | YES | ASCII | YES | CTRL-MEMORY-CONTEXT-001 then CTRL-MCP-001 | Handler | Splunk | `flows/flow-lab-memory-001.svg` | NO |
| LAB-SCANNER-RUNTIME-EVIDENCE | YES | ASCII | YES | CTRL-MCP-001 remains the runtime PDP | Runtime handler, separate from scanner | Splunk scanner sourcetype | `flows/flow-lab-scanner-runtime-evidence.svg` | NO |
| LAB-EXTERNAL-EVALUATION-GARAK | NO | PROSE | YES | CTRL-MCP-001 | Runtime handler, separate from evaluation | Splunk copy | `flows/flow-lab-external-evaluation-garak.svg` | NO |
| LAB-AGENT-GOAL-INTEGRITY-001 | YES | ASCII | YES | CTRL-GOAL-INTEGRITY-001 then CTRL-MCP-001 | Operation-specific handler | Splunk | `flows/flow-lab-agent-goal-integrity-001.svg` | NO |
| LAB-AGENT-DELEGATION-001 | YES | ASCII | YES | CTRL-IDENTITY-001 then CTRL-MCP-001 | Handler | Splunk | `flows/flow-lab-agent-delegation-001.svg` | NO |
| LAB-AGENTSEC-CAPSTONE-001 | NO | PROSE | YES | RAG / MEMORY OBSERVE, CTRL-MCP-001 | lookup_customer_tier handler | Splunk | `flows/flow-lab-agentsec-capstone-001.svg` | NO |
| LAB-SPLUNK-DEFENDER-BRIDGE | NO | PROSE | YES | CTRL-MCP-001 in historical evidence | Historical runtime copy | Splunk Search | `flows/flow-lab-splunk-defender-bridge.svg` | NO |
| LAB-BLUE-TEAM-INCIDENT-001 | NO | PROSE | YES | CTRL-MCP-001 in historical evidence | Historical runtime copy | Splunk Search | `flows/flow-lab-blue-team-incident-001.svg` | NO |
| LAB-DETECTION-ENGINEERING | NO | PROSE | YES | CTRL-MCP-001 in compared evidence | Historical copies compared by predicate | Splunk Search | `flows/flow-lab-detection-engineering.svg` | NO |
| LAB-THREAT-MODELING-001 | YES | ASCII | YES | CTRL-MCP-001 at TB-04 | Tool registry / fixture records | OTel → Splunk | `flows/flow-lab-threat-modeling-001.svg` | NO |
| LAB-AGENT-IDENTITY-NHI | NO | PROSE | YES | CTRL-IDENTITY-001 then CTRL-MCP-001 | Handler evidence | Splunk | `flows/flow-lab-agent-identity-nhi.svg` | NO |
| LAB-A2A-AUTH-DELEGATION | NO | PROSE | YES | CTRL-IDENTITY-001 then CTRL-MCP-001 | Handler evidence | Splunk | `flows/flow-lab-a2a-auth-delegation.svg` | NO |
| LAB-HITL-APPROVAL | NO | PROSE | YES | CTRL-MCP-001 | Submitted action evidence | Splunk | `flows/flow-lab-hitl-approval.svg` | NO |
| LAB-CREDENTIAL-LIFETIME | NO | PROSE | YES | CTRL-MCP-001 | Handler evidence | Splunk | `flows/flow-lab-credential-lifetime.svg` | NO |
| LAB-PRIVACY-DATA-GOVERNANCE-001 | YES | ASCII | YES | CTRL-MCP-001 | Fixture tool | Splunk copy | `flows/flow-lab-privacy-data-governance-001.svg` | NO |
| LAB-RAG-PURPOSE | NO | PROSE | YES | Purpose evaluation; retrieval does not invoke CTRL-MCP-001 | Retrieval is not tool execution | Splunk observe | `flows/flow-lab-rag-purpose.svg` | NO |
| LAB-RECALL-ISOLATION | NO | PROSE | YES | CTRL-MEMORY-CONTEXT-001 then CTRL-MCP-001 | Recall is not a tool grant | Splunk | `flows/flow-lab-recall-isolation.svg` | NO |
| LAB-ASSET-INVENTORY | NO | PROSE | YES | CTRL-MCP-001 remains the tool PDP | Inventory is not execution | Documented component list | `flows/flow-lab-asset-inventory.svg` | NO |
| LAB-COMPONENT-PROVENANCE | NO | PROSE | YES | CTRL-MCP-001 | Identified component is not authorized | Splunk / documented provenance | `flows/flow-lab-component-provenance.svg` | NO |
| LAB-CODE-AGENT-BOUNDS | NO | PROSE | YES | Binding plus tool decision | Simulated start is not an install | Splunk / workshop ledger | `flows/flow-lab-code-agent-bounds.svg` | NO |
| LAB-CHANGE-BOUNDS | NO | PROSE | YES | Binding plus tool decision | A started action is not a completed change | Splunk / workshop ledger | `flows/flow-lab-change-bounds.svg` | NO |
| LAB-MULTI-STAGE-INCIDENT-001 | NO | PROSE | YES | CTRL-MCP-001 in the packet | Stage-specific handler evidence | Splunk investigation | `flows/flow-lab-multi-stage-incident-001.svg` | NO |
| LAB-ADVANCED-CAPSTONE-MASTERY-001 | NO | PROSE | YES | Named from evidence, not assumed | Named from evidence, not assumed | Splunk investigation | `flows/flow-lab-advanced-capstone-mastery-001.svg` | NO |

## ITEM 5 — PREDICT BEFORE YOU CLICK

Files Modified: `src/agentsec/templates/attack.html`, `src/agentsec/templates/attack_mcp.html`, `src/agentsec/static/agentsec.css`, `src/agentsec/static/agentsec-workbench.css`
Control Prediction: native radios ALLOW / DENY / ERROR / UNKNOWN.
Execution Prediction: native radios YES / NO / UNKNOWN.
Touch Targets: choice cards use `min-height: 2.75rem`.
Selected State: `:has(input:checked)` teal inset.
Prediction Recorded State: `#prediction-recorded` reads `PREDICTION RECORDED` after a change. Radios remain changeable.
Disclaimer Preserved: not sent to Splunk, not graded, not a control decision.
Browser-Only Semantics Preserved: `savePrediction` still uses sessionStorage. Launch JSON still omits `predict-control`.
Keyboard: native radios remain.
Answer Leakage: no expected decision is printed before launch.
Live Render: Flask test client returned HTTP 200 for `/` and `/labs/LAB-MCP-001` with the radio cards present. Browser click/focus NOT MEASURED.
Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED on Attack Service.

## INLINE INVESTIGATION

Existing Run-ID Investigation Preserved: YES. Guide SPL and tokens were not edited.
Inline SPL Editing Added: NO
Advanced Splunk Search Preserved: YES

## REGRESSION

13-Entry Guided Navigation: YES. `default.xml` was not edited.
Your Path: lifecycle tests still pass.
LIVE: launch templates still post `execution: "live"`.
REPLAY: diagrams do not claim a fresh launch.
Inline Investigation: guide tables remain.
Arena: not edited.
Mastery: not edited.
Answer Leakage: diagram and prediction tests reject expected ATTACK/RETEST answers.
Authorization vs Execution: ALLOW is not green; executed uses a separate treatment.
CTRL-MCP-001: not semantically changed.
CTRL-INPUT-001: not semantically changed.
DET-MCP-001: remains disabled.

Schema: `1.9.0`
ExternalEvidence: `1.0.0`

## VALIDATION

Focused Tests: visual learning, progress, learner console, navigation, guided learning, representative dashboard tests.
Full Offline Suite: `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` — `1106 passed, 3 deselected`, 9.24s.
Actual Exit Code: 0
Repeated Tests: visual learning + progress + learner console, three times, each process exit 0.
1920: NOT MEASURED
1440: LOCAL STATIC Your Path dump OBSERVED
1280: NOT MEASURED
1024: NOT MEASURED
True Browser 200% Zoom: NOT MEASURED
Physical Keyboard: NOT TESTED
Screen Reader: NOT TESTED
WCAG Claim: none

## SECURITY / RELEASE BOUNDARIES

Credentials Added: NO
Certificates Added: NO
Keys/Tokens Added: NO
Cryptography Added: NO
TLS Verification Disabled: NO
Docker Socket Added: NO
Privileged Container Added: NO
Splunk Core Modified: NO
Vendor JavaScript Modified: NO
Unsupported Studio Injection Added: NO

Codeguard: no hardcoded credentials, certificates, or new crypto were introduced. `.env` remains untracked. The rule was applied by keeping demo UI copy credential-free and leaving Splunk TLS settings unchanged.

## FILES / GIT

Files Modified: Your Path script; Attack Service prediction CSS/HTML; 31 workshop JSON definitions; 31 Studio views; `scripts/agentsec_studio.py`; learner docs; dashboard tests that now allow supported `splunk.image`; privacy/threat-model markdown helpers that skip image viz.
Assets Added: 31 SVG flows; `src/agentsec/workshop_flows.py`
Tests Added/Modified: `tests/unit/test_visual_learning.py`, progress tests, selected dashboard tests
Documentation: README, GETTING_STARTED, TROUBLESHOOTING, this review
Commit Created: pending
Push: pending
Main Modified: NO
Existing Tags Modified: NO
New Tag: NO
GitHub Release: NO

## ITEMS NOT INDEPENDENTLY VERIFIED

- Splunk-hosted Your Path paint after a real Academy login
- Stale Splunk static-asset cache on EC2
- Studio-hosted flow images at 1920 / 1440 / 1280 / 1024
- Studio table coloring with a live run.id
- True browser 200% zoom
- Physical keyboard on Attack Service
- Screen reader
- Public-host Attack Service prediction click
- EC2 deploy of this candidate

## EXTERNAL REVIEW TARGETS

1. Hard-refresh Your Path in Splunk. Confirm the curriculum, tally, cards, and reset render. Confirm INVESTIGATED is not labeled SAFE.
2. Confirm native nav still has 13 top-level entries and no progress badges.
3. Open Direct Prompt Injection LEARN. Confirm the flow image is visible, sized, and does not leak the ATTACK/RETEST answer.
4. Paste a LIVE run.id into the inline table. Confirm ALLOW is not green and `executed=true` looks different from ALLOW.
5. On Attack Service, use keyboard and mouse to set a prediction. Confirm PREDICTION RECORDED, then change it, then launch. Confirm the launch body still omits the prediction.
6. Confirm schema 1.9.0, ExternalEvidence 1.0.0, DET-MCP-001 disabled, and no Studio stylesheet injection.

EC2 update, if used, on the existing checkout without deleting volumes:

```sh
git fetch origin --tags --prune
git checkout develop
git merge --ff-only origin/develop
./scripts/precheck.sh --remote
./scripts/lab-up.sh --build --refresh-app --remote
```

FINAL VERDICT:

READY FOR INDEPENDENT VISUAL LEARNER REVIEW
