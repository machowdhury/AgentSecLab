# AGENTSEC — 15 October 2026 technical Q&A

Short answers for a live audience. If you did not measure it this session, say so.

---

## Agent, tools, and authorization

**What is an AI agent here?**  
Software that can request tools. The lab agent is `acme-agent-mcp-001`. It is granted `lookup_policy` only.

**Is this real MCP?**  
In-process JSON-RPC `tools/call` in AcmeBank. It is not a remote MCP product, not stdio, not a marketplace catalog.

**What is the trust boundary?**  
CTRL-MCP-001 in AcmeBank, **before** the tool handler. The Academy page cannot ALLOW or DENY.

**Who is the attacker?**  
Anyone who can cause the agent to request `lookup_customer_tier`. The browser cannot change the specimen.

**Why isn’t this prompt injection?**  
Direct prompt injection is LAB-PI-001. This demo is unauthorized tool invocation (INV-001). Untrusted text still cannot mint a grant (INV-002).

---

## ALLOW, DENY, and execution

**Did ALLOW mean the tool succeeded?**  
No. ALLOW is the control decision. Execution begins at `agentsec.mcp.started`. On ATTACK we observed that event. On RETEST we did not.

**Did DENY mean the tool never ran?**  
On a **complete** local record, handler NOT OBSERVED plus DENY is the defended contract. Missing Splunk rows alone are not proof.

**Why 7 events then 6?**  
RETEST does not record `mcp.started` / completion of the handler. Do not force the counts to match.

**Why 0 LLM events?**  
This MCP authorize path does not call the model. Empty Ollama catalog is DEGRADED, not a demo blocker.

**Why can Splunk show 6 decision fields on a 7-event run?**  
The decision attribute is present on multiple events. The notebook reports one decision fact. Do not teach “six ALLOWs.”

---

## Splunk and evidence

**Is Splunk the policy decision point?**  
No. Never.

**What did Splunk prove in P1.6 rehearsal?**  
For the final rehearsal LIVE ATTACK `82423ce2-…` count 7 and LIVE RETEST `2c4e5738-…` count 6; earlier LIVE `de60a91c-…` 7 and `b8c432ff-…` 6; REPLAY ATTACK `5e8f55f3-…` 7. Each has exactly one decision event in Splunk (MEASURED, `scripts/p1_6_reconcile_live_evidence.py`). Independent search, index `agentsec_telemetry`, sourcetype `otel:agentic:json`.

**Why is `hec.ok` false?**  
AcmeBank does not send HEC. Collector does. Launch JSON `hec.ok` is not ingest proof.

**Why does Academy say Splunk indexing NOT CHECKED?**  
By design. Indexing is proven by search, not by a status light.

**Schema 1.1.0 vs 1.9.0?**  
Committed REPLAY packs were recorded at 1.1.0. New LIVE runtime events are 1.9.0. ExternalEvidence 1.0.0 is for scanner/garak packs, not this lab.

**Can I use the P1.4 LIVE ids?**  
`4eab6700-…` and `2343f9e1-…` were not indexed and were **not backfilled**. Do not present them as Splunk evidence.

---

## Detections and other labs

**Will DET-MCP-001 alert on this ATTACK?**  
No. It is packaged **disabled**. Even enabled, it looks for DENY **then** `mcp.started`. Fail-open ALLOW is silent. Silence is not SAFE.

**Did you change `ws_lab_mcp_001`?**  
No. Accepted dashboard unchanged.

**MCP-005?**  
Result-trust lab. Publication restrictions remain. Do not enable MCP-005 detections in this demo.

**Other SIEM vendors?**  
Not implemented. Sample parsers are not CrowdStrike/Sentinel/Elastic integrations. See the enterprise telemetry matrix.

**Is this AI forensics?**  
You can reconstruct a run from events (decision, handler, provenance). It is not a forensic appliance.

---

## Security posture of the lab

**Is the Attack Service authenticated?**  
No. Educational localhost. Not multi-tenant. Not internet-facing.

**Did you weaken TLS for the demo?**  
P1.5 pointed collector HEC at HTTPS `agentsec_splunk`. Existing lab `SPLUNK_HEC_TLS_SKIP_VERIFY` was not newly introduced in P1.6.

**VoiceOver / WCAG?**  
Genuine Chrome zoom 100/200/400% passed in P1.5. VoiceOver was **not** executed in P1.6. Do not claim WCAG conformance.

**Clean install?**  
Empty-stack Compose recreate is **not fully verified**. Demo day uses the existing stack.

---

## LIVE vs REPLAY

**Which should I trust?**  
Both can be real past or current runs. REPLAY is a committed recording. LIVE is minted now. Mixing them without disclosure is a teaching failure, not a control failure.

**Does switching to REPLAY delete LIVE evidence?**  
No. It changes session state in that tab. Durable `artifacts/` LIVE index remains.
