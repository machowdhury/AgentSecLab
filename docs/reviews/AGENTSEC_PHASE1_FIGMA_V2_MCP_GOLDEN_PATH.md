# AgentSec Phase 1 — Figma v2 production integration, MCP golden path

Implementation report for the LAB-MCP-001 reference journey.

| | |
|---|---|
| Branch | `develop` |
| Starting SHA | `c6370e0` |
| Ending SHA | `1ef50ba` |
| `origin/main` | `0178c70` — unchanged, not merged |
| Tags | unchanged; no tag created or moved |
| AgentSec version | 1.1.0 |
| Runtime schema | 1.9.0 — unchanged |
| ExternalEvidence contract | 1.0.0 — unchanged |
| Deployed to | `i-03e570d023ce16d6f` (`agentic_lab_machine`, us-east-2, 3.17.29.24) |
| Deployed SHA on host | `1ef50ba` |
| Report date | 2026-10-05 |

---

## 1. Final verdict

**CONDITIONAL — REMEDIATION REQUIRED BEFORE INDEPENDENT PILOT**

The evidence chain at the heart of the golden path is implemented and verified
live against real indexed telemetry. Two things block an independent pilot:

1. **Every click-dependent behaviour is NOT TESTED.** This was the agreed
   validation scope. See §7 for the browser checklist that closes it.
2. **The System/Build Information surface was not implemented.** See §6.3.

Neither is an architectural or evidence blocker. The runtime, control,
telemetry and SPL layers are sound and measured.

Two items originally listed here as blockers were closed after this report was
first written, and are verified live on the host:

- AcmeBank being unreachable by a remote learner — resolved in `8c195d4` by
  serving WORLD 1 read-only from the Attack Service, without exposing AcmeBank.
  See §6.1.
- The unowned flow image across 30 other views — resolved in `fe8934a` by
  giving `agentsec.workshop_flows` a named pipeline stage. See §6.2.

---

## 2. What was built

Four commits on `develop`, each a vertical slice.

| SHA | Slice |
|---|---|
| `553c637` | Attack Workbench: five independent state dimensions |
| `3893ed6` | AcmeBank: "See how the AI did this" |
| `1ed98f3` | Splunk evidence notebook, plus a generator-ownership fix |
| `89626f9` | Golden-path invariant tests |
| `1ef50ba` | Comparison column rename after live verification |

### 2.1 Attack Workbench — five states, measured separately

The workbench previously collapsed control decision, evidence readiness and run
completion into one status pill, computed as:

```js
const state = data.error_class === "ERROR" ? "ERROR" :
  controlDecision === "DENY" ? "DENIED" :
  data.evidence_state === "EVIDENCE_READY" ? "EVIDENCE READY" : "COMPLETED";
```

One word therefore stood in for four unrelated facts, and a DENY run could not
also report that its evidence was indexed.

Now the pill reports the launcher only (`RUN COMPLETE` / `ERROR`), and five
dimensions are painted from their own sources into their own cards: control
decision, execution evidence, launcher terminal state, Splunk evidence
readiness, and the learner's browser-local prediction. Decision and execution
are rendered as an explicit `≠` pair, so ALLOW is never presented as proof that
a handler ran.

A business-story band separates the AcmeBank narrative from the security
mission, and the eight-stage learning loop is visible as a stepper. ATTACK and
RETEST stay locked until a prediction is recorded; `UNKNOWN` is accepted,
because "I do not know" is an honest answer in this curriculum.

### 2.2 AcmeBank — "See how the AI did this"

An expandable section explains the four in-process pipeline roles that handled
the loan, then the separate MCP tool-authorization path the workshop
investigates, then a glossary for tool, MCP, control decision, execution,
telemetry, and what Splunk is and is not doing.

The section is explicitly labelled **DOCUMENTED architecture**, distinct from
the measured `run.id` evidence above it, so the diagram cannot be read as run
evidence. The onward link builds its host from `window.location`, so it does
not send a remote learner to loopback.

### 2.3 Splunk evidence notebook

The EVIDENCE tab was a grid of correct SPL with no interpretive scaffolding.
Five notebook cells now interleave with the evidence that answers them. Each
states the question, **what the answer shows**, and **what it does not prove**:

1. Did the agent request a tool it was not granted?
2. What did CTRL-MCP-001 decide?
3. What scope was requested, and what scope was allowed?
4. Did the tool handler actually begin?
5. Is the evidence complete enough to conclude anything?

A new `ds_live_pair` query puts the learner's own two runs side by side from
indexed evidence, matched on `agentsec.testbed.mode`. It needs no new input:
learner views are limited to a single paste box by
`tests/splunk/test_agentsec_ui_shell.py`, and that rule was kept rather than
relaxed.

---

## 3. Design decisions that changed the Figma prototype

### 3.1 The AcmeBank business story is the real one

**Decision taken by the repository owner.** Normal behaviour is the granted
`lookup_policy` / `policy:read` call the BASELINE specimen already makes. The
attack is the ungranted `lookup_customer_tier` / `customer:read` request. Same
pedagogy, all evidence real, and **no runtime change** — no new tool, no new
control, no new scenario. The prototype's retail-banking chat and
`get_customer_transactions` tool do not exist in AgentSec and were not created.

### 3.2 Notebook Question 3 is not the prototype's question

The Figma prototype's notebook asks about "LLM calls: 4". **LAB-MCP-001 emits no
`agentsec.llm.*` event on either ATTACK or RETEST** — OBSERVED by executing the
pipeline in-process, and confirmed against indexed evidence in §5. A call-count
question would have had no answer. Question 3 asks requested-versus-allowed
scope instead, which is recorded on both runs and is the actual authority gap.
A test now forbids any notebook cell from asking about model calls.

### 3.3 The prototype's SPL cannot run

The prototype's field names do not match the AgentSec telemetry contract. All
SPL in this implementation is real, executes against `index=agentsec_telemetry
sourcetype=otel:agentic:json`, and is verified live in §5.

---

## 4. A latent defect found and fixed

While regenerating the workshop, three parts of the learner surface turned out
to exist **only inside the generated artifacts**, produced by no generator:

| Element | What it is |
|---|---|
| `viz_flow_diagram` | architecture image pinned to the top of MISSION |
| `viz_guide_events` formatting | ALLOW/DENY and executed colour semantics |
| `viz_guide_summary` formatting | the same, on the summary table |

Running `scripts/build_lab_mcp_001_dashboard.py` deleted all three, and nothing
failed at the point of deletion — a later unrelated test happened to catch it.
This is the same shape as the Your Path clobber fixed in the previous task.

Fixed by giving the generators ownership:
`build_lab_mcp_001_dashboard.py` now emits `viz_flow_diagram`, and
`apply_guided_learning.py` now emits the semantic column formatting and pins an
existing flow image above its guide blocks.

`tests/splunk/test_generator_owns_mcp_workshop_surface.py` runs the real
generators and asserts the surface survives and that regeneration is
byte-identical. **The test was verified to fail when either bug is
reintroduced**, then pass again once restored.

**Known debt, not fixed:** 30 other views carry a `viz_flow_diagram` that no
generator owns. Re-running any of their build scripts will delete it the same
way. Out of scope here; it should be closed before those generators are run.

---

## 5. Live validation

Deployed to the lab host and verified at HTTP and SSM level. Evidence class is
stated for every line.

### 5.1 Deployment

| Check | Result | Class |
|---|---|---|
| `develop` fast-forwarded on host | `c6370e0` → `1ef50ba` | MEASURED |
| `lab-up.sh --build --refresh-app --remote` | exit 0, 2m48s | MEASURED |
| All 16 Academy views available via Splunk REST | yes | MEASURED |
| `ws_lab_mcp_001` REST | HTTP 200 | MEASURED |
| App build the browser will see | `build = 4` | MEASURED |
| Splunk app static assets changed this phase | none, so no build bump needed | MEASURED |
| `scripts/static_cache_identity.py --check` | exit 0 | MEASURED |

### 5.2 Attack Workbench over HTTP

`GET http://<host>:5001/labs/LAB-MCP-001` → HTTP 200, 30961 bytes. All eleven
markers present: `business-story`, `loop-stepper`, the five `fact-*` cards,
`fact-pair__not-equal`, `record-prediction`, the disabled `fire-attack` button,
and `RUN COMPLETE`. **No occurrence of `localhost`, `127.0.0.1` or the host IP
in the served page.** The stylesheet served at HTTP 200 with the new
components. (MEASURED)

`GET http://127.0.0.1:5000/` on the host → HTTP 200, with "See how the AI did
this", "DOCUMENTED architecture", the glossary, the onward link, and no
hard-coded host. (MEASURED)

### 5.3 Two real runs

`POST /api/launch` over HTTP, closed four-field payload.

| | ATTACK | RETEST |
|---|---|---|
| `run.id` | `cd1269f1-c93f-443f-99d3-43f8bc423510` | `bfc1d635-03f8-4539-911a-cf1dfd6ed52a` |
| profile | vulnerable | defended |
| CTRL-MCP-001 decision | ALLOW | DENY |
| reason | `vulnerable_profile_fail_open:…` | `tool_not_granted` |
| runtime handler count | 1 | 0 |
| terminal | `completed_allowed` | `completed_denied` |

Run IDs differ. (MEASURED)

### 5.4 Indexed evidence

Executed inside the Splunk container. Credentials stayed in the container
environment and were never printed.

| `run.id` | indexed events | event names |
|---|---|---|
| ATTACK | 7 | control.decision, hop.started, hop.completed, **mcp.started, mcp.completed**, run.started, run.completed |
| RETEST | 6 | control.decision, hop.started, hop.completed, **pipeline.stopped**, run.started, run.completed |

The indexed counts match the runtime exactly, so both copies are complete. The
ATTACK carries execution events; the RETEST carries none. **No
`agentsec.llm.*` event on either run**, confirming §3.2. (MEASURED)

### 5.5 The new comparison query, executed live

The deployed `ds_live_pair` query, extracted from the live Splunk app and run
against indexed evidence, returned exactly the two runs above:

```
mode,run_id,profile,tool,requested_scope,allowed_scope,scope_gap,decision,reason,execution_state,matched_events,last_seen
ATTACK,cd1269f1-…,vulnerable,lookup_customer_tier,customer:read,policy:read,requested != allowed,ALLOW,vulnerable_profile_fail_open:…,mcp.completed,3,2026-10-05 23:54:26
RETEST,bfc1d635-…,defended,lookup_customer_tier,customer:read,policy:read,requested != allowed,DENY,tool_not_granted,no_mcp_execution_event,1,2026-10-05 23:54:39
```

(MEASURED)

This run caught a real presentation defect. The column was first named
`indexed_events` but returns 3 and 1 for runs carrying 7 and 6 events, because
it counts only the events this query matches. A learner answering Question 5
would have read it as the completeness answer. Renamed to `matched_events`,
with the description saying so, and redeployed.

### 5.6 Security posture unchanged

| Invariant | State | Class |
|---|---|---|
| DET-MCP-001 | `disabled = 1`, `enableSched = 0` | MEASURED on host |
| CTRL-MCP-001 | unchanged; still the MCP PDP | DOCUMENTED, diff review |
| Runtime schema | 1.9.0 | MEASURED |
| ExternalEvidence contract | 1.0.0 | MEASURED |
| Phase 2 labs registered | none | MEASURED, test-enforced |
| Phase 2 controls created | none | MEASURED, test-enforced |
| New public firewall exposure | none opened | MEASURED |
| `origin/main` | unchanged at `0178c70` | MEASURED |

---

## 6. Open items

### 6.1 AcmeBank is not reachable by a remote learner — RESOLVED (`8c195d4`)

`docker-compose.yml` binds AcmeBank to `127.0.0.1:5000:5000` with no
`AGENTSEC_BIND_ADDRESS`, unlike Splunk Web (8000) and the Attack Service (5001).
Confirmed on the host: `agentsec_acmebank|127.0.0.1:5000->5000/tcp`, and
`curl http://3.17.29.24:5000/` fails **even from the host itself**. (MEASURED)

So the documented journey's first step — "learner enters AcmeBank" — could not
be opened from a remote browser. `tests/security/test_remote_listener_bindings.py`
locks this binding deliberately, and exposing a deliberately vulnerable LLM
target publicly would be a security regression, so **the binding was not
changed**.

Resolved instead by rendering WORLD 1 read-only from the Attack Service, which
already listens on 5001: `GET /acmebank` returns the same template with
`read_only=True`. No form, no submit button, no `/process` call, no script at
all. This is not an HTTP proxy — there is no caller-supplied upstream and no
path, query or body is forwarded — so it adds no request-forgery surface from
the browser into the lab host. No new listener and no new firewall rule.

Only the profile and model labels come from the target, over the fixed
`/health` probe the Attack Service already makes. They render `NOT MEASURED`
when AcmeBank is unreachable rather than asserting a profile the page cannot
see.

Live on the host after deploy (MEASURED):

| Check | Result |
| --- | --- |
| `GET http://3.17.29.24:5001/acmebank` | HTTP 200, 5449 bytes |
| `POST http://3.17.29.24:5001/acmebank` | HTTP 405 |
| `GET http://3.17.29.24:5000/` | connection refused — still unexposed |
| Rendered profile / model | `defended` / `llama3.2:1b` — probed, not asserted |
| Loan form, `/process`, any `<script>` | absent |

`tests/security/test_acmebank_read_only_view.py` (17 tests) pins GET-only,
upstream rejection, the absent form and script, and that AcmeBank's own page is
unchanged. The guards were verified to fail when the route is mutated into a
POST-accepting proxy and when the form is shipped.

### 6.2 Thirty views carried an unowned flow image — RESOLVED (`fe8934a`)

See §4. The diagnosis in §4 was incomplete: the logic *did* exist, in
`src/agentsec/workshop_flows.py`, which owns `viz_flow_diagram` and the
decision/executed colour semantics for all 31 workshops. The real defect was
narrower and worse — `apply_dashboards()` and `write_svgs()` had **no caller
anywhere**, so they ran once and nothing re-applied them.

Fixed by adding `scripts/apply_workshop_flows.py` as a named pipeline stage and
establishing the order:

```
build_lab_*_dashboard.py  ->  apply_workshop_flows.py  ->  apply_guided_learning.py
```

The duplication introduced in `1ed98f3` was removed: the hardcoded flow block in
the LAB-MCP-001 build script, and the `EVIDENCE_COLUMN_FORMAT` /
`EVIDENCE_CONTEXT` copies in `apply_guided_learning`, which were byte-identical
to the canonical constants.

One artifact change fell out of this: the LAB-MCP-001 mission canvas height
moves 540 → 748, because `_insert_flow_viz` bumps it by the image height and the
hardcoded block did not. 748 matches the convention every other workshop uses.

Tests now cover all 31 views, not just the one this phase touched: the stage
restores every workshop after a simulated rebuild, and running it twice changes
nothing. Verified the flow image is absent when the stage is skipped, so the
guard is load-bearing.

Separate pre-existing item, **not fixed**: on all 31 workshops the first tab's
declared canvas height is smaller than its content bottom, because
`apply_guided_learning` adds roughly 1400px without bumping the height. This
predates the golden path work and changing it would touch every view.

### 6.3 System / Build Information surface — NOT IMPLEMENTED

In scope per the brief and not built. No partial version was shipped and
nothing was faked. The underlying facts (app build 4, version 1.1.0, schema
1.9.0, external contract 1.0.0) are all available; only the surface is missing.

### 6.4 Splunk KV Store

Pre-existing environment debt: the bundled MongoDB is incompatible with the
host kernel. Unchanged, not investigated, no infrastructure upgrade attempted.

---

## 7. Browser checklist — these gates are NOT TESTED

Everything below depends on a rendered browser and was outside the agreed
validation scope. **None of it has been observed.** Treat each as NOT TESTED
rather than passing.

WORLD 1 read-only view, `http://<host>:5001/acmebank`:

0a. The page renders with AcmeBank's header and the read-only notice, and there
    is no loan textarea or Submit button anywhere on it.
0b. "See how the AI did this" expands and shows the four pipeline roles, the
    seven-node tool path and the glossary.
0c. The workbench link at the bottom of that disclosure returns to
    `/labs/LAB-MCP-001` on the same host and port, with no port rewrite.
0d. The header reads the live profile and model, not `NOT MEASURED`, while the
    lab is up.

Attack Workbench, `http://<host>:5001/labs/LAB-MCP-001`:

1. ATTACK and RETEST are visibly disabled on load, and "Record prediction and
   unlock launch" enables them.
2. After ATTACK: decision card reads ALLOW in blue, execution card reads
   EXECUTED in white-on-navy, terminal reads `completed_allowed`, and the `≠`
   between decision and execution is visible.
3. After RETEST: decision reads DENY in amber, execution reads NOT EXECUTED in
   grey. No green anywhere.
4. The stepper advances: Predict → Attack → Observe → Investigate → Compare.
5. "Check evidence readiness" updates only the evidence card, and the status
   pill still reads RUN COMPLETE rather than restating a decision.
6. The ATTACK ↔ RETEST table fills with two different run IDs.
7. At 1180px, 820px and 620px the business band stacks, the fact row becomes one
   column, and the `≠` pair stacks without clipping.
8. Keyboard only: skip link, prediction radios, record button, launch buttons,
   and the advanced disclosure are all reachable with a visible focus ring.
9. A screen reader announces the status region and the `≠` as "is not the same
   as".

Splunk workshop, `http://<host>:8000/en-US/app/agentsec/ws_lab_mcp_001`:

10. MISSION shows the architecture image first, above the guided panel.
11. EVIDENCE shows the five notebook cells interleaved with their evidence, and
    the tab scrolls cleanly to the comparison at the bottom.
12. "ATTACK ↔ RETEST (your live run.ids)" renders two rows after a fresh pair.
13. Decision and executed columns carry the semantic tones.

AcmeBank, on the host only until §6.1 is resolved:

14. "See how the AI did this" expands and the onward link opens the workbench
    on the host in the address bar, not loopback.

---

## 8. Test evidence

| Gate | Result |
|---|---|
| A — baseline before changes | 1123 passed, 3 deselected, exit 0 |
| C — new invariants | 21 tests, all passing |
| D — full offline suite | 1149 passed, 3 deselected, exit 0 |
| E — reliability | 10 consecutive full runs, 10/10 exit 0, 1149 passed each |

Command: `uv run --extra test python -m pytest tests -q --tb=line -m "not
live_ollama and not live_splunk"`.

New tests:

- `tests/security/test_phase1_golden_path_invariants.py` — 21 tests covering
  distinct run IDs, decision-is-not-execution against the real pipeline, the
  scope gap on both runs, the absence of LLM events, the five separately
  addressable state dimensions, prediction isolation from the launch payload,
  the DOCUMENTED label, notebook honesty, the Phase 2 boundary, and remote-safe
  navigation.
- `tests/splunk/test_generator_owns_mcp_workshop_surface.py` — 5 tests running
  the real generators, verified to fail when the ownership bugs are
  reintroduced.

Generators are idempotent in the order `build_lab_mcp_001_dashboard.py` then
`apply_guided_learning.py`. `apply_guided_learning.py` must run last.

---

## What I should now be able to explain

1. Why a single status pill that says "DENIED" is a worse security UI than four
   separate cards, even though it contains true information.
2. What evidence establishes that a handler executed, and why the control
   decision is not that evidence.
3. Why the ATTACK run shows ALLOW and still proves a security failure, and what
   `vulnerable_profile_fail_open` actually means.
4. Why the absence of `agentsec.mcp.started` is not proof that nothing ran, and
   what has to be true first before that absence means anything.
5. Why `matched_events` returning 3 for a run with 7 events is not a bug in the
   data, and why the original column name was a real defect anyway.
6. Why a question about "LLM calls" had to be removed from the notebook rather
   than answered.
7. What goes wrong when a hand-edited element lives inside a generated file, and
   why a test that asserts the element exists is not sufficient protection.
8. Why AcmeBank being bound to loopback is both a learner-experience problem and
   a correct security decision at the same time.
9. Why the prediction gate accepts UNKNOWN, and what would be lost if it forced
   a confident answer.
10. What "CONDITIONAL" means here, and precisely which observations would have
    to change to make it READY.
