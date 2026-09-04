# How AgentWatch Works

This note is for AgentSec Phase 0. It explains the predecessor lab in simple language first, then with enough technical detail to reuse the right ideas and reject the wrong ones.

**Predecessor location:** `/Users/mahamudc/Documents/AgenticProject` (GitHub: `machowdhury/AgentwatchRange`)  
**Rule:** Read-only. Proven assets only. Do not copy blindly.  
**Evidence:** OBSERVED from source and one packaging-script run; DOCUMENTED from AgentWatch docs. Live Splunk hunts and live attack success rates were **NOT MEASURED** in this pass.

---

## WHAT IS IT?

AgentWatch Range is a **learning range**: a small fake bank with four AI agents, an attack panel, a live local LLM (Ollama), OpenTelemetry, and Splunk dashboards.

It is not a production AI firewall. It is not Cisco AI Defense. AcmeGate and AcmeSentinel are Python regex checks with vendor-style names.

## WHY DOES IT EXIST?

Enterprises are chaining LLMs across intake, tools, memory, and other agents. Traditional AppSec mostly sees HTTP. The interesting failures happen **inside the agent workflow**.

AgentWatch exists so you can:

1. Send a normal loan request (baseline).
2. Send a crafted attack at the same path.
3. Watch a control allow or block.
4. Find the evidence in Splunk.
5. Practice detection and compliance storytelling.

That is the same lifecycle AgentSec wants, with stricter honesty about tests and evidence.

## HOW DOES IT WORK?

Five containers (local Splunk profile):

```text
You
 ├─ Banking app :5000  → four agents in a row → Ollama
 ├─ Attack panel :5001 → POSTs attacks into the banking app
 ├─ Ollama             → real text in, real text out
 ├─ OTel Collector     → batches logs/traces to Splunk HEC
 └─ Splunk             → dashboards and hunts (does not run the LLM)
```

A legitimate loan:

```text
POST /api/v1/process
  → Intake agent prompt + Ollama
  → Document agent prompt + Ollama
  → Credit-risk agent prompt + Ollama
  → Compliance agent prompt + Ollama
  → JSON result in the UI
```

Each hop runs **workflow guards**, then **AcmeGate** (input regex), then **Ollama**, then **AcmeSentinel** (output regex). Blocks stop the pipeline.

An attack is the same path with a malicious string. Outcome is **BLOCKED** (a rule matched) or **INJECTED** (the model answered and rules missed). Because the LLM is live and small, two runs of the same attack can differ. That is useful for detection practice and dangerous if you treat it as a scientific model-safety score.

Agents do **not** call each other over a network. The “router” is a Python for-loop that pastes the previous answer into the next prompt.

## WHERE DOES IT SIT IN AGENTSEC?

AgentWatch is the **predecessor**. AgentSec is the successor learning range.

Reuse:

- the loop (baseline → attack → telemetry → hunt → control evidence)
- the technique registry shape
- LIVE vs SIMULATED labeling
- OTel → HEC → Splunk
- workshop pedagogy (predict, run, explain)

Do not reuse blindly:

- regex-as-MCP / regex-as-A2A / regex-as-RAG
- dashboards that imply 51 equally real live tests
- claims that env flags or Cisco enforce mode change runtime when they do not

## WHAT IS THE TRUST BOUNDARY?

The real boundary is:

**Attack Panel / browser / HTTP client → Banking app process → Ollama HTTP API**

Everything after that (collector, Splunk) is observability. Splunk does not enforce policy.

Inside the banking app, docs draw four trust labels (`external_dmz`, `internal_processing`, `privileged_internal`). Those labels are **not** separate networks. They are names on sequential prompts.

## WHAT COULD AN ATTACKER CONTROL?

From the Attack Panel or any HTTP client:

- the user message / payload
- which agent is targeted (`/api/v1/agent/<id>` vs full pipeline)
- optional tags (`campaign_week`, `technique_id`, `testbed_mode`) if they use the richer APIs

They cannot, in the default lab, break out of Docker just by clicking Top 10 — unless you later add a **real** MCP/tool runtime. Today “shell command” attacks are mostly **strings that look like tools**.

## WHAT CAN GO WRONG?

1. **Regex misses paraphrases** and over-blocks benign finance language.
2. **Output DENY is after the LLM ran.** The dangerous inference already happened.
3. **Marker-based guards fail open** if the payload omits `execute_shell_command(`, `did:acme:`, `FOUNDRY_TRACE_STATE`, and similar lab tells.
4. **SIMULATED techniques never hit those guards.** They inject OTel. Splunk still lights up.
5. **Four live agents do not share one incident/trace.** Hunting “the run” is harder than the kill-chain demo suggests.
6. **`session.id` vs `session_id`** can hide correlation in Splunk.
7. **Docs say 45 or 51** depending on the page. YAML has 51.
8. **No automated tests.** A refactor can break a control with no alarm.
9. **Guard enable env vars are displayed, not honored** on the LLM path.
10. **HITL defaults off.** High-value auto-approve is a teaching gap, not a locked gate.

## WHAT TELEMETRY SHOULD EXIST?

AgentWatch already emits a useful vocabulary (keep the ideas, rename for AgentSec):

- identity: `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.request.model`
- usage: input/output tokens, latency
- control: `workflow.blocked`, `workflow.block_reason`, input/output guard fields
- scenario: `testbed_mode`, `campaign_week`, `technique_id`
- chain: `incident_id`, `chain_id`, `stage_num` (strong on simulated chains)
- frameworks: ATLAS / OWASP / MAESTRO / NIST tags on events

AgentSec still needs `run.id` and a single correlation id for a full pipeline run. AgentWatch does not provide that on the live 4-agent path.

Baseline traffic uses `testbed_mode=BASELINE_TRAFFIC` so hunts can exclude it.

## HOW WILL SPLUNK SHOW IT?

Primary index `acme_agentic_telemetry`, sourcetype `otel:agentic:json`.

Teaching extras: simulated vendor JSON, third-party JSON, registry snapshots — normalized with `norm_*` fields in `props.conf`.

Highest-value views to study (not to copy on day one):

- Exercise Runner — predict then hunt
- Technique Coverage Matrix — attempted vs detected
- Control Attestation — measurement of control tags
- Cross-App Normalization — why SIEM exists
- Kill-Chain Timeline / Actor Chain Story — `incident_id` storytelling
- Executive Governance — CISO language over the same events

All practitioner dashboards in the canonical app are Dashboard Studio v2 except a classic setup page. Generators in `scripts/sync_*_dashboard.py` write the XML.

This Phase 0 pass ran `validate_splunk_app.sh`. Studio JSON/XML checks passed. The script **failed** on leftover OrchestraACME strings in old rename scripts. Packaging is not fully green.

## WHAT CONTROL COULD CHANGE THE RESULT?

| Control | When it can change the result |
|---------|-------------------------------|
| Workflow MCP/orchestration/A2A/memory regex | Before Ollama, if lab markers are present |
| AcmeGate | Before Ollama, if input patterns match |
| AcmeSentinel | After Ollama; hides output, does not un-infer |
| HITL | Only if enabled; default does not block |
| Control validator | Does not change the action; tags evidence afterward |
| Cisco enforce mode | **Does not** change the action today (function never called) |
| SIMULATED executor | Does not exercise runtime controls at all |

## WHAT TEST PROVES THE LOGIC?

**None in AgentWatch.** There is no unit/integration/security test pack.

AgentSec must add tests that do not need the LLM for deterministic guards:

- normal input → ALLOW
- malicious marker/payload → DENY before inference
- malformed input → ERROR or DENY, not crash
- missing security context → not silent ALLOW unless the lab profile is explicitly vulnerable
- telemetry reason present
- no DENY claimed after a successful dangerous operation

Live Ollama tests, if any, are behavioral and non-deterministic. Keep them separate.

---

## Simple map of the 51 techniques

- **10 Top scenarios:** curated live stories (supply chain, orchestration, input, shadow model, output jailbreak, MCP, token DoS, A2A, RAG, memory/SOAR).
- **45 core ATLAS IDs + 6 emerging (T0070–T0075):** coverage library. Modes are LIVE, HYBRID, or SIMULATED. Many non–Top-10 LIVE payloads are generic “lab replay” strings.
- **6 kill chains:** multi-stage stories with shared `incident_id`. Default OTel stages; Attack Panel can add hybrid live legs.

Coverage dashboards can look “complete” after Run All 51 even when many events never touched a real control. That is the main lesson for AgentSec research integrity.

---

## What I should now be able to explain

1. Why AgentWatch is a range and not a production AI-security product.
2. What happens, step by step, on a legitimate loan request versus an Attack Panel click.
3. Why the four agents are not a real A2A network.
4. Where AcmeGate runs versus AcmeSentinel, and why that matters for claiming DENY.
5. The difference between LIVE, HYBRID, and SIMULATED, and which `testbed_mode` values go with each.
6. Why baseline traffic exists and how to keep it out of attack hunts.
7. Which Splunk pieces are the teaching core versus optional Cisco/MLTK overlays.
8. Why `run.id` / shared `incident_id` is a Phase 1 problem even though AgentWatch already logs many fields.
9. Which AgentWatch controls are regex theater, and which placement idea is still worth keeping.
10. What must be true before AgentSec copies a dashboard or a technique from the old lab.
