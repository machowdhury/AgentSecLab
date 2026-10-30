# AI Security Assurance

AI Security Assurance turns **what actually happened in a lab run** into a finding you can read, verify and retest. It is built from the telemetry the workshops produce (`index=agentsec_telemetry`) with two static inputs that are labelled as such (the MAESTRO worked example and the framework map). There are no fabricated metrics and no language model deciding anything. The Nemotron panel reads "Not tested".

**In RC2 you use it inside the Academy: open Academy > Security Assurance (`/learn/assurance`).** The five Splunk dashboards and the finding page are an **optional advanced view** of the same findings (see [Optional advanced view: Splunk dashboards](#optional-advanced-view-splunk-dashboards)); no learner step needs them.

## In the Academy (supported workflow)

The path for every finding is **Overview, Finding, Raw evidence, Investigation notebook, Workshop (defend), Retest comparison.**

| Screen | What it gives you |
|---|---|
| **Overview** (`/learn/assurance`) | One headline ("N findings need your attention"), then Held, Did not hold and Retests validated as *n of N* with their definitions; the source, time window and grain are stated. Control effectiveness, evidence gaps, untested controls and how the numbers are computed are one click away. Three tabs keep the evidence classes apart: **Live · this lab**, **Recorded examples** (committed runs to study, worded as "findings to explore", never as your current posture) and **Test fixtures** (synthetic negative-test data, operator only). |
| **Finding** | Status and evidence class, the event timeline (a missing event is shown as a gap), the seven answers ([below](#reading-a-finding-seven-questions)), the linked retest, and **Go to the workshop with this run** for a live run. |
| **Raw evidence** | The run's events as indexed, shown as text and never run, with copy buttons and the search that finds them. |
| **Investigation notebook** | Press **Run** on an approved, fixed-template search for this run. The Attack Service runs it against Splunk and the Academy shows the rows, a chart and a plain-language reading computed only from those rows. The exact SPL is shown and copyable; no browser-supplied SPL is accepted. For recorded examples the same cells read the committed events and say that no search ran. |
| **Retest comparison** | The attack run and its linked retest, per hop, with the rules' outcome (VALIDATED, NOT_VALIDATED, NO_RETEST). It is built only from the rules' linked runs and computes no score; a retest with incomplete evidence is flagged, not compared. |

Splunk being unreachable, search access not being set up and an empty window are three different states, and none of them shows numbers as if it were a pass. If search access is missing the Academy says so and fails closed (`./agentsec splunk-access`, check with `--check`). Validated on one real Splunk Enterprise 10.2.7 host with the bundled Splunk (2026-10-30 acceptance run); not validated against an external Splunk, Splunk Cloud or an organization-issued certificate.

| Screenshot (captured from the running Academy on a real host) | |
|---|---|
| Overview (Live tab) | ![Academy Security Assurance overview](images/academy-assurance-overview.png) |
| One finding | ![Academy finding](images/academy-assurance-finding.png) |
| Investigation notebook | ![Academy investigation notebook](images/academy-assurance-notebook.png) |
| Retest comparison | ![Academy retest comparison](images/academy-assurance-compare.png) |

## The evidence-to-meaning model

Every finding carries these fields, all produced by rules (not by a model):

| Field | Source |
|---|---|
| Observation | A sentence filled from the observed events: run, mode, profile, control, decision, reason, hop, tool, and whether the same hop shows an execution event |
| Interpretation | The rule's meaning for that status, naming the trust boundary and what the control guards |
| Business and security impact | A fixed statement per status; the vulnerable-profile variant says plainly that it is the lab's teaching condition |
| Supporting evidence | The run's events (sequence numbers and names) and the SPL that lists them |
| Relevant control | The control and its guidance mapping (educational relationships, verified identifiers) |
| Confidence | Verified, Inferred, Incomplete or Unavailable, set by the status |
| Recommended action | The control's remediation text; for incomplete telemetry, the telemetry-health steps |
| Retest outcome | VALIDATED, NOT_VALIDATED, NO_RETEST or NOT_APPLICABLE (see below) |

### Statuses

| Status | Meaning |
|---|---|
| **Verified effective** | The control was exercised and the expected protection was observed from two kinds of event: its DENY decision, and no execution event in the same hop, in a run with complete telemetry |
| **Verified ineffective** | The control was exercised and the protected execution happened. In the intentionally vulnerable profile this is **by design** and labelled so |
| **Finding observed** | Behaviour worth knowing about, but control effectiveness is not established (an OBSERVE-class control, an invalid request, a scanner finding) |
| **Not tested** | No ATTACK or RETEST hop exercised the control in the selected range |
| **Insufficient evidence** | Telemetry is missing or incomplete (a gap in the event sequence, no terminal run event, no hop index, a completed run with no control decision at all) |
| **Verification unavailable** | Data or infrastructure cannot be reached (for example the index is empty) |

Missing telemetry never becomes a pass; a scanner finding never becomes an exploit; a model's stated intention never becomes an executed action (only `agentsec.operation.executed=true` on a handler or model event counts).

### The rules (single source: `learning/assurance/rules.json`)

Evaluated per **guarded operation**: one control decision, identified by run id, hop index and control id. Execution is read from events in the **same run and hop**, never from timestamps being close. Rules are tried in order and the first match decides.

| Order | Rule | Condition | Status |
|---|---|---|---|
| 1 | R-INCOMPLETE | no hop index, or the sequence is not contiguous from 1, or no terminal run event | Insufficient evidence |
| 2 | R-OBSERVE-ONLY | decision OBSERVE | Finding observed |
| 3 | R-ERROR | decision ERROR | Finding observed |
| 4 | R-DENY-HELD | DENY and no execution in the hop | Verified effective |
| 5 | R-DENY-BYPASSED | DENY and an execution in the hop | Verified ineffective |
| 6 | R-FAILOPEN-EXECUTED | ALLOW with a `vulnerable_profile_fail_open` reason and an execution | Verified ineffective (by design) |
| 7 | R-FAILOPEN-NOT-EXECUTED | the same without an execution | Finding observed |
| 8 | R-ALLOW-EXPECTED | an ordinary authorized ALLOW | activity, not a finding |
| 9 | R-UNCLASSIFIED | the decision value is missing or not ALLOW, DENY, OBSERVE or ERROR | Insufficient evidence (shown, never dropped) |

Run-level rules: **RR-NO-DECISION** (an ATTACK or RETEST run completed with no control decision: Insufficient evidence) and **RR-RETEST-NOT-PREVENTED** (a defended RETEST executed with no enforcing denial: Verified ineffective).

The SPL macros (`agentsec_assurance_units`, `agentsec_assurance_findings`, `agentsec_assurance_findings_linked`) are **generated** from this file by `scripts/build_assurance_app.py`, and the Python reference evaluator (`src/agentsec/assurance/engine.py`) reads the same file, so the rules you read are the rules that run.

### Retest linking

An ATTACK finding is linked to RETEST findings with the **same attack id, the same control id and the same evidence class** (a RECORDED retest never validates a LIVE attack, and a fixture validates nothing real); an ATTACK finding with no attack id has NO_RETEST. Nothing else (no timestamp, no ordering) links two events. The outcome is VALIDATED (a linked retest is Verified effective), NOT_VALIDATED (a linked retest exists but is not), or NO_RETEST. For an OBSERVE-class control a retest can only show another observation, so it reads NOT_VALIDATED: protection is judged by the enforcing control's own finding.

## Reading a finding: seven questions

Every finding page answers the same seven questions, so you can read any of them the same way.

| Question | Where the finding answers it |
|---|---|
| What happened? | Observation: the run, mode, profile, control, decision, hop and whether the same hop shows an execution |
| What does it mean? | Interpretation, and the control interpretation |
| Why does it matter? | Business and security impact (a fixed statement per status) |
| What is the evidence? | Supporting evidence and the raw events in order |
| Which control is involved? | Relevant control, with its guidance relationships |
| What should I do? | Recommended action |
| Did the fix work? | Retest outcome: VALIDATED, NOT_VALIDATED, NO_RETEST or NOT_APPLICABLE |

**A deliberately vulnerable profile is not a failed control.** The ATTACK profile is the lab's teaching condition: an execution it allows is labelled *by design* and counted separately. "Verified ineffective" for a *defended* run means a control that should have stopped something did not, and that is the result to act on.

**Scope of the claim.** A finding says how a control behaved in the tested lab run. It is not an organization-wide compliance, certification or conformance statement.

## Metrics

Each metric states its numerator, denominator, time range (the panel's range) and source on the dashboard itself (table on the executive page, from `learning/assurance/rules.json`).

| Metric | Numerator | Denominator |
|---|---|---|
| Attack runs | distinct run ids with mode ATTACK | a count |
| Confirmed unauthorized executions | hop-level guarded operations Verified ineffective (by-design subset shown); run-level retest failures are shown separately | hop-level operations with an ALLOW, DENY or ERROR decision |
| Blocked operations (verified) | operations Verified effective | DENY decisions |
| Retest outcomes | ATTACK findings whose retest is VALIDATED | ATTACK findings Verified ineffective (NOT_VALIDATED and NO_RETEST counted separately) |
| Evidence completeness | runs with a contiguous sequence and a terminal event | all runs |
| Controls without a qualifying test | catalogue controls with no ATTACK or RETEST finding | controls in the catalogue |
| Run start to first control decision | median and maximum seconds within a run | runs with both events |

**Not computed, on purpose:** a compliance percentage or a composite risk score (no defensible methodology exists), and **time to detection**: no alerting detection is enabled by default (DET-MCP-001 is packaged disabled), and timestamps have one-second resolution, so the latency above is control-decision latency inside a run, not detection time.

## Evidence classes

LIVE (not a committed specimen and not a fixture: the telemetry cannot prove which installation produced it), RECORDED (a committed replay specimen, told apart only by the committed list `agentsec_recorded_runs`, because the telemetry says `execution.mode=LIVE` for both), and TEST_FIXTURE (synthetic negative-test data with lab id `assurance-test-fixture`, never produced by the lab). SIMULATED workshop packets and CTF challenges are not in Splunk and never appear. The default view shows LIVE and RECORDED and **always excludes fixtures**; every table has an evidence-class column.

## Framework mapping

`learning/assurance/framework_map.json` holds 38 identifiers checked against primary sources when the map was written (NIST AI RMF 1.0 and AI 600-1 PDFs, OWASP LLM Top 10 2025, OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS v2026.10, CSA MAESTRO) and, for ISO/IEC 42001:2023, a listed secondary source (the standard is paywalled, so those are `VERIFIED_WITH_LIMITS`). Notes: ATLAS released v2026.10 on 2026-10-28 and renamed some items (the older table in `learning/academy/framework_refs.json` is from 2026.09); NIST says AI RMF 1.0 is being revised and has published no revision; CSA describes MAESTRO as officially adopted without a version number. **Every relationship is `RELATED`**: an educational link with a stated rationale, never a statement that an item is satisfied. A lab test shows how a control behaved in the tested environment, not organization-wide compliance, certification or regulatory conformance.

## What it does not cover

- **Execution is matched by run and hop, not by control.** If one hop held two decisions and one execution, the execution is attributed to both; the lab's runs have one guarded call per hop.
- **Join limits.** Some panels combine searches with `join` and `append`, which Splunk limits (50,000 rows, 60 seconds). The lab's volumes are far below that; with much larger data a truncated join would show zeros.
- **The workshop filter** uses the attack id's workshops (and does not apply to scanner or evaluation panels, which say so).

- **The Loan Desk** (`agentsec.loan_desk_event`) uses a different event schema without hop indexes or an ATTACK/RETEST mode, so it is not scored.
- **Scanner and external-evaluation evidence is not ingested by default.** The Cisco MCP scanner packs and the garak packs reach Splunk only when you run their ingest scripts; until then those panels show empty states. **Nemotron has not been evaluated**: the Nemotron panel says "Not tested" and shows no comparison.
- **No AI BOM** is produced; the component table is the *declared* inventory from the lock files, labelled as such.
- **A2A and MCP are the lab's in-process models**, not real transports.
- **The attack id names a lab specimen** (for example MCP-003), not a MITRE technique; technique names come from the control catalogue.

## Reproduce and retest (a learner's path)

1. In the Academy, open a LIVE workshop (for example `LAB-MCP-003`) and run **ATTACK**. As `operator`: the launch card.
2. Open **Academy > Security Assurance** (Live tab). Telemetry arrives seconds to minutes after the run; a run still arriving reads *Insufficient evidence* until its last event is indexed.
3. Open the new finding. Read the observation, interpretation and impact; open **Raw evidence** and compare the `control.decision` row with any `mcp.started` or `llm.started` row in the same hop, or press **Run** in the **investigation notebook**.
4. Run **RETEST** (the defended profile) in the same workshop. The ATTACK finding's retest outcome changes from NO_RETEST to VALIDATED only if the RETEST shows the control effective; **Compare with the retest** shows the two runs side by side.
5. Break something on purpose to see Security Assurance refuse to pass it: the acceptance fixtures (`scripts/assurance_acceptance.py fixtures`, shown on the operator-only **Test fixtures** tab once ingested) are a lost event, a run still arriving, a control that stopped working and a DENY that still executed.

## Optional advanced view: Splunk dashboards

Five Splunk dashboards and one finding page show the same findings inside Splunk Web. They are optional: nothing in the Academy requires them, they are **not routed through the HTTPS gateway** and they use Splunk's own login. The screenshots below are of this optional view, not of the Academy.

> **Status.** Run on a real Splunk in the 2026-10-29 acceptance (record): all 34 data sources run, the five dashboards and the finding page render, and the SPL equals the Python reference evaluator on 118 findings. **CONDITIONAL**: the dashboards live in Splunk Web, outside the gateway's authorization; the row-click drilldown was not exercised; and a run whose telemetry never reaches Splunk is invisible to them (only the Academy's evidence state shows it).

Open them in Splunk Web under **AI Security Assurance** (`/en-US/app/agentsec/ws_assurance_executive`). Splunk Web is on the lab host's loopback (`127.0.0.1:18000`); see the [gateway reference](GATEWAY.md#authentication-and-remote-access). They are not behind the HTTPS gateway and use Splunk's own login.

### The dashboards

| Dashboard (view id) | Answers | Main evidence |
|---|---|---|
| **Executive overview** (`ws_assurance_executive`) | What was attacked, what held, what did not, what is missing, and what needs attention, in a narrative that changes with the data | Findings, metrics with definitions, status trend, untested controls |
| **Agent, MCP and A2A** (`ws_assurance_agent_mcp`) | Tool authorization outcomes, prompt-injection and tool-misuse attempts, delegation behaviour; attempts versus confirmed outcomes; scanner findings; catalog changes | Control decisions and execution events; scanner events; explicit scanner-to-runtime hash link |
| **Supply chain and model** (`ws_assurance_supply_chain`) | Scanner findings, declared components, observed model identity, model evaluations, a Nemotron-versus-baseline panel | `agentsec:scanner:finding`, `agentsec:external:evaluation`, `deploy/*.lock.json` |
| **Threat model coverage** (`ws_assurance_threat_model`) | CSA MAESTRO layers and trust boundaries: modeled threats beside observed evidence | The lab's MAESTRO worked example (modeled) and the findings (observed) |
| **Compliance and governance** (`ws_assurance_compliance`) | Which lab evidence relates to which NIST AI RMF, AI 600-1, OWASP, MITRE ATLAS and ISO/IEC 42001 items, with no compliance claim | `learning/assurance/framework_map.json` and the findings |
| **Finding** (`ws_assurance_finding`, opened from a row) | One finding: observation, interpretation, impact, evidence, control interpretation, action, retest, raw events, guidance | The run's own events |

In Splunk the path is Dashboard, Finding page, Raw events; rows in any findings table open the finding page with the run id, control id and hop. The Academy's own Overview, Finding, Raw evidence, notebook and retest comparison (above) are the supported equivalent.

### What the optional dashboards look like

Captured from the real Splunk dashboards on the acceptance host (Splunk 10.2.7, headless Chromium through an SSH tunnel), not mock-ups. The data is the lab's own runs and committed packs.

| Dashboard | Screenshot |
|---|---|
| Executive overview | ![Executive overview](images/assurance-executive.png) |
| Agent, MCP and A2A | ![Agent, MCP and A2A](images/assurance-agent-mcp.png) |
| Supply chain and model | ![Supply chain and model](images/assurance-supply-chain.png) |
| Threat model coverage | ![Threat model coverage](images/assurance-threat-model.png) |
| Compliance and governance | ![Compliance and governance](images/assurance-compliance.png) |
| One finding (opened by URL; the row-click handler was not exercised) | ![Finding page](images/assurance-finding.png) |

### Maintaining the dashboards

Edit `learning/assurance/rules.json`, `controls.json` or `framework_map.json`, then run `python scripts/build_assurance_app.py` (and `python scripts/apply_guided_learning.py` owns the navigation). `tests/test_assurance_app.py` fails when a generated file is stale. After a change, the Splunk app on a running lab is refreshed by `agentsec up` and Splunk must reload it (restart the Splunk container or use `Settings > Server controls`).

### Acceptance of the dashboards: what is and is not demonstrated

Demonstrated on a real Splunk (record: ASSURANCE_ACCEPTANCE.md): live ATTACK and RETEST runs through the gateway; ingestion with complete telemetry; every data source; rendering of all dashboards; a LIVE attack reading NO_RETEST and then VALIDATED after the live retest, with RECORDED retests not validating it; equality with the reference evaluator (`scripts/assurance_acceptance.py compare`); and negative tests (a run whose telemetry was cut, a lost event, a run still arriving, an ineffective control, a DENY that still executed), none of which reads as success.

Not demonstrated: the row-click drilldown handler (its target page was opened by URL); gateway authorization for the dashboards (they use Splunk's own login); fresh scanner runs (committed packs were ingested); any use of Nemotron evidence (none exists).
