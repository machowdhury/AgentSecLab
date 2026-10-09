# AGENTSEC — 15 October 2026 facilitator guide

This guide is for someone who did **not** build the platform. You can still deliver the demonstration if the lab stack is healthy.

**Read first:** `AGENTSEC_OCT15_DEMO_SCRIPT.md`, then this file, then `AGENTSEC_OCT15_TROUBLESHOOTING.md`. Keep `AGENTSEC_OCT15_TECHNICAL_QA.md` for questions.

---

## What you are demonstrating

AgentSec Lab is an educational range. A customer-service **agent** may call **tools**. A control named **CTRL-MCP-001** decides ALLOW or DENY **before** the tool runs. You show one experiment (LAB-MCP-001) in a browser workshop called the **Academy**.

You are not selling a production AI-security product. You are teaching a defensible investigation habit.

---

## The story in one paragraph

AcmeBank’s agent is granted `lookup_policy`. In the attack, it requests `lookup_customer_tier` (customer data it was never granted). On the **vulnerable** profile the lab control fail-opens (ALLOW) and the tool handler starts. On the **defended** profile the same request is DENY and the handler is not observed to start. Splunk holds a copy of the telemetry. Splunk does not authorize the tool.

---

## Day-of checklist (30 minutes before)

1. Confirm you may use this host and that unrelated applications are left alone.
2. Open Terminal in the AgentSecLab repo.
3. Run `./scripts/lab-ready.sh`. Expect exit 0. Optional model (Ollama) may be **DEGRADED**. That is OK for this lab.
4. Browser: `http://127.0.0.1:5001/academy` — you should see AgentSec Academy, not an error page.
5. Open `http://127.0.0.1:8000` (Splunk Web on this host only). Sign in with the **lab** credentials from the operator’s local `.env` — never paste them into slides or chat.
6. Decide **mode**:
   - **REPLAY** if you need a deterministic 15 minutes.
   - **LIVE** if you will launch a fresh pair and wait for Splunk.
7. Open a **new** tab for the workshop. If run cards already show **LIVE** UUIDs, you are in LIVE unless you click **Use the recorded pair in this tab (REPLAY)**.
8. Say the mode out loud in rehearsal once.

Do **not** run `docker compose down -v`. That wipes Splunk history used for REPLAY teaching.

---

## Exact click path (REPLAY)

1. `http://127.0.0.1:5001/academy`
2. Foundations (optional, 30 seconds)
3. Your Learning Path → **MCP Tool Authorization**
4. Start — read the story and boundaries → Continue to Baseline
5. Load the recorded baseline → Continue to Predict
6. Choose answers → Lock prediction
7. Use the recorded ATTACK (REPLAY) **or** the recorded-pair switch if LIVE was auto-loaded
8. Continue to Investigate — answer from the table
9. Continue to Defend — read the profile change
10. Use the recorded RETEST (REPLAY)
11. Continue to Compare
12. Continue to Explain — two sentences → Mark workflow complete

Committed REPLAY identifiers (say “recording of a real past run”):

| Role | run.id |
|------|--------|
| BASELINE | `163d11e2-e751-4282-9406-19b490542ed4` |
| ATTACK | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` |
| RETEST | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` |

---

## Exact click path (LIVE)

Same as above through Lock prediction. If the tab already shows a LIVE pair (auto-loaded from the server), click **Clear this tab and launch a fresh LIVE pair** — the LIVE buttons stay disabled until you do. Then **Launch LIVE ATTACK**, wait for a UUID, Investigate, Defend, **Launch LIVE RETEST**, Compare.

Clearing only empties this tab. It never deletes server LIVE references or artifacts. A new tab opened afterwards adopts the newest pair.

P1.6 rehearsal pairs (already indexed and reconciled with Splunk; use them as **historical LIVE**, not as a new launch):

| Role | run.id | Events | Decision | Handler |
|------|--------|--------|----------|---------|
| ATTACK (final rehearsal, 2026-10-09T22:17Z) | `82423ce2-fae2-4adf-a9eb-39dd10f6c97f` | 7 | ALLOW | OBSERVED |
| RETEST (final rehearsal) | `2c4e5738-d845-46f8-98d3-3193956c9876` | 6 | DENY | NOT OBSERVED |
| ATTACK (earlier) | `de60a91c-8aa0-411f-8731-2d79d760d427` | 7 | ALLOW | OBSERVED |
| RETEST (earlier) | `b8c432ff-6e2e-4cec-a259-78761b50b969` | 6 | DENY | NOT OBSERVED |

If you launch **new** LIVE runs, use **those** UUIDs. Do not mix.

---

## What “good” looks like

- Badges match the mode you announced.
- ATTACK and RETEST have **different** run.ids.
- Compare shows ALLOW vs DENY and OBSERVED vs NOT OBSERVED.
- Splunk search for a LIVE id returns the same event count as the notebook (7 and 6 for this contract).
- You never say “the LLM decided to allow it.” The control decided. This path recorded **0** LLM events.

---

## Words to use / avoid

| Use | Avoid |
|-----|--------|
| Intentionally vulnerable profile | “The product was hacked” |
| Fail-open ALLOW | “Splunk allowed the tool” |
| Handler OBSERVED / NOT OBSERVED | “Proven never executed” from missing Splunk rows alone |
| Educational localhost range | “Production MCP gateway” |
| DET-MCP-001 is packaged disabled | “We alerted SOC in real time” |
| Schema 1.1.0 on old recordings, 1.9.0 on new LIVE | “All evidence is the same schema” |

---

## If the audience is beginners

Stay on Academy. Skip Splunk except one search screenshot. Repeat: request ≠ grant, decision ≠ execution.

## If the audience is SOC / detection engineers

Show the Splunk copy, named fields (`agentsec.run.id`, `event.name`, `agentsec.control.decision`), and that DET-MCP-001 is **disabled** and would not fire on fail-open ALLOW anyway (it looks for DENY then `mcp.started`).

## If the audience is security leaders

Spend the extra minute on residual risk: lab allow-list, no production IAM, one retest is not universal assurance, visibility is not authorization.

---

## After the demo

1. Do not reset Splunk volumes.
2. Browser “workflow complete” is local. It is not evidence.
3. Point advanced attendees to `docs/LIVE_VS_REPLAY.md` and `docs/KNOWN_LIMITATIONS.md`.
