# AGENTSEC — 15 October 2026 demonstration script

**Duration:** 15–20 minutes  
**Lab:** LAB-MCP-001 MCP Tool Authorization  
**Audience:** mixed (beginners through security leaders)  
**Primary mode:** REPLAY  
**Secondary mode:** LIVE  

Say the active mode in the first minute and again when evidence appears.

Never substitute REPLAY for LIVE without saying so. Never invent LLM calls, Splunk rows, or control decisions.

**Qualified stack (P1.6 rehearsal):** Academy `http://127.0.0.1:5001/academy`. A new browser tab may auto-load the latest durable LIVE pair. If the badges say LIVE, you are in LIVE mode. Click **Use the recorded pair in this tab (REPLAY)** on the Attack step if you need the committed packs in this tab. That switch does not delete server LIVE evidence.

To show a **new** LIVE pair while an earlier one is loaded, click **Clear this tab and launch a fresh LIVE pair** on the Attack step. The LIVE launch buttons stay disabled until you do. Clearing affects this browser tab only; server LIVE references and artifacts stay. Rehearsed on deployed image `sha256:e5dc7f88…` on 2026-10-09 (MEASURED).

---

## Timing overview

| Block | Minutes | Mode |
|-------|---------|------|
| Opening | 0:00–2:00 | Talking |
| Baseline | 2:00–5:00 | REPLAY (or LIVE if already loaded — disclose) |
| Attack | 5:00–9:00 | REPLAY primary / LIVE secondary |
| Investigation | 9:00–13:00 | Notebook + Splunk |
| Defense and retest | 13:00–17:00 | Same mode as Attack |
| Conclusion | 17:00–19:00 | Talking |

---

## Opening — 2 minutes

**Navigate:** `http://127.0.0.1:5001/academy` then **Foundations**.

### What an AI agent is

An agent here is software that can call **tools**. The lab agent `acme-agent-mcp-001` is granted one tool: `lookup_policy`. That grant is a server-side list. The model does not mint grants.

### Why tool access creates new risk

If the agent can invoke `lookup_customer_tier`, it can read customer data it was never granted. The dangerous step is **the tool handler starting**, not the sentence in the prompt.

### Why prompt injection and unauthorized tool use matter

Untrusted text can influence what the agent *asks for*. Influence is not authorization. This demo is unauthorized tool use (INV-001): a request is not a grant.

### Why visibility is not authorization

Splunk will show a copy of what happened. Splunk does **not** ALLOW or DENY the tool. CTRL-MCP-001 in AcmeBank does.

**Say:** “We will watch one request, one control, and two facts: the decision, and whether the handler started.”

---

## Baseline — 3 minutes

**Navigate:** Path → **MCP Tool Authorization** → Step 1 Start (read boundaries) → Continue to Baseline.

**Action:** **Load the recorded baseline**.

**Expected (REPLAY BASELINE `163d11e2-e751-4282-9406-19b490542ed4`):**

| Fact | Value |
|------|--------|
| Provenance badge | REPLAY |
| Decision | ALLOW |
| Handler | OBSERVED (`agentsec.mcp.started`) |
| Events | 7 |
| Schema on pack | 1.1.0 |
| LLM events | 0 |

**Talking points**

- This is the granted tool `lookup_policy` on the defended profile.
- ALLOW here is expected. It is not a bypass.
- Zero LLM events is correct: this MCP path does not need Ollama.

**Do not** launch a baseline. The workshop never launches BASELINE.

---

## Attack — 4 minutes

**Navigate:** Predict → answer both questions → **Lock prediction**. Then Attack.

Suggested prediction (you may also choose UNSURE): control ALLOW, tool starts YES, because this ATTACK uses the **intentionally vulnerable** profile.

**Primary — REPLAY**

Click **Use the recorded ATTACK (REPLAY)**  
or **Use the recorded pair in this tab (REPLAY)** if LIVE was auto-loaded.

**Expected REPLAY ATTACK `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49`:**

| Field | Value |
|-------|--------|
| Tool | `lookup_customer_tier` |
| Scope | ungranted customer-tier read |
| Profile | vulnerable |
| Decision | ALLOW (`vulnerable_profile_fail_open`) |
| Handler | OBSERVED |
| Events | 7 |
| Badge | REPLAY |

**Secondary — LIVE**

If a LIVE card is already showing, click **Clear this tab and launch a fresh LIVE pair** first. Then click **Launch LIVE ATTACK**. Wait for a new UUID.

P1.6 final rehearsal LIVE ATTACK: `82423ce2-fae2-4adf-a9eb-39dd10f6c97f` (2026-10-09T22:17:25Z)  
Decision ALLOW (`vulnerable_profile_fail_open`), handler OBSERVED, 7 events, schema **1.9.0**, Splunk count 7, one decision event (MEASURED, reconciled).  
Earlier P1.6 pair `de60a91c…` / `b8c432ff…` is historical and also reconciles 7/6.  
Launch JSON `hec.ok=false` is **by design** (runtime does not send HEC). `otlp.ok=true` means emit+flush only.

### Explain while the card is on screen

| Topic | Script |
|-------|--------|
| Attacker objective | Treat `lookup_customer_tier` as if it were granted. |
| Trust boundary | CTRL-MCP-001 sits between the tool request and the handler. |
| Tool invocation | The request is real. The browser did not pick the tool. |
| Authorization decision | Vulnerable profile fail-opens: ALLOW. |
| Execution outcome | Handler started (`mcp.started`). ALLOW did not “prove” that by itself — the start event did. |

---

## Investigation — 4 minutes

**Navigate:** Continue to Investigate.

Answer the notebook from the event table. Check against evidence.

**Teaching answers for ATTACK**

1. CTRL-MCP-001 decided **ALLOW**.
2. The handler **did** start.
3. Evidence for (2) is **`agentsec.mcp.started`**, not the decision event.
4. Requested vs granted scope: the requested tool is outside the grant list.
5. LLM calls in this record: **0**.

**Splunk (advanced, 60–90 seconds)**

Open **Search this run in Splunk** from the run card, or paste:

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"=<RUN_ID> | stats count as n
```

Show: run.id, timestamps, `agentsec.control.decision`, `event.name`.

**Limitations to say out loud**

- This is a copy. Incomplete export can look like prevention.
- `hec.ok` on launch JSON is not Splunk proof.
- Academy **Splunk indexing** status is NOT CHECKED on purpose.
- A `stats count by agentsec.control.decision` of 6 on a 7-event run is field fan-out, not six decisions.

---

## Defense and retest — 4 minutes

**Navigate:** Defend. Read the table: same tool and scope; profile changes from `vulnerable` to `defended`.

**Retest**

- If ATTACK was REPLAY: **Use the recorded RETEST (REPLAY)**  
  Expected `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` — DENY, handler NOT OBSERVED, 6 events.
- If ATTACK was LIVE: **Launch LIVE RETEST**  
  P1.6 final rehearsal: `2c4e5738-d845-46f8-98d3-3193956c9876` — DENY (`tool_not_granted`), NOT OBSERVED, `agentsec.pipeline.stopped` once, 6 events, schema 1.9.0, Splunk 6.

**Compare**

| Row | ATTACK | RETEST | Relation |
|-----|--------|--------|----------|
| CTRL-MCP-001 decision | ALLOW | DENY | DIFFERENT |
| Handler started | OBSERVED | NOT OBSERVED | DIFFERENT |
| LLM events | 0 | 0 | SAME |

**Say this sentence**

ALLOW does not mean the business operation succeeded. DENY does not, by itself, prove the handler never ran. We cite `mcp.started` as OBSERVED or NOT OBSERVED. NOT OBSERVED is not a synonym for SAFE if the record might be incomplete.

---

## Conclusion — 2 minutes

| Learner observed | The same ungranted request was ALLOW+executed on the vulnerable profile and DENY+not started on the defended profile. |
| Control prevented | On RETEST, CTRL-MCP-001 denied before the handler. |
| Splunk established | A searchable copy of those run.ids (when indexed). It did not make the decision. |
| Outside the evidence | Production IAM, remote MCP transport, LLM intent, other vendors’ SIEMs, DET-MCP-001 (disabled), VoiceOver (untested). |

**Close:** “Request is not grant. Decision is not execution. Splunk is evidence, not the policy decision point.”

Mark workflow complete if time remains. That is browser learning state, not a security verdict.
