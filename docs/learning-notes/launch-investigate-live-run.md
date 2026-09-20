# Launch, then investigate a live run.id

**Lab:** LAB-PI-001 (Phase 14B execution plane)  
**Evidence class:** this note is DOCUMENTED teaching. Live numbers belong in `docs/PHASE14B_ATTACK_SERVICE_IMPLEMENTATION.md` after a real search.

---

## WHAT IS IT?

A path where you **predict**, **launch** an allowlisted specimen, **copy a fresh run.id**, and **hunt it in Splunk Search**. Dashboard Studio still shows canonical REPLAY ids. Those are a different copy.

---

## WHY DOES IT EXIST?

Watching a finished dashboard is not the same as performing the experiment. The Attack Service is only an untrusted button. AcmeBank still decides DENY/ALLOW. Splunk still only observes.

---

## HOW IT WORKS

1. Read ATTACK OBJECTIVE / WHAT WILL CHANGE / WHAT WILL NOT CHANGE.
2. Write a prediction (DENY before LLM vs labeled fail-open).
3. Launch BASELINE or ATTACK. You cannot supply the payload.
4. Copy `run.id`.
5. Open Search. Paste the starter query. Run it.
6. Reuse `Q-RUN-EVENTS` then `Q-CONTROL-DECISION`. Do not create a detector.
7. If Splunk is empty, wait and probe again. Empty is not DENY. Check `artifacts/<run-id>/export.json`.
8. RETEST is not a click in 14B. Same payload + different process env is an operator procedure.

---

## WHERE IT SITS

Execution plane: Attack Service → AcmeBank → OTEL → HEC → index.  
Investigation plane: Search / later 14C Path A.  
Studio is not the launcher.

---

## TRUST BOUNDARY

You control the click. You do not control profile, grants, or `run.id`. Profile lives on AcmeBank. A mismatch is ERROR, not a clever bypass.

---

## WHAT AN ATTACKER CONTROLS

On this service: which allowlisted row to request. Not the injection string, not tools, not SPL, not authorization.

---

## WHAT CAN GO WRONG

- Treating WAITING_FOR_EVIDENCE as a blocked attack
- Mixing a fresh LIVE id into a REPLAY table without labeling
- Assuming HEC 200 means the events are searchable
- Thinking Attack Service DENY’d the loan (it cannot)

---

## TELEMETRY / SPLUNK / CONTROL / TEST

Telemetry: existing schema 1.9.0 PI events.  
Splunk: starter query + Q-RUN-EVENTS.  
Control: CTRL-INPUT-001 on AcmeBank, unchanged.  
Test: `tests/unit/test_phase14b_attack_service.py` (offline). Live: `scripts/validate_phase14b_live_launch.py`.

---

## What I should now be able to explain

1. Why Attack Service is untrusted relative to AcmeBank.
2. Which JSON fields a launch may contain, and why extra fields are ERROR.
3. Why `profile` is echoed from AcmeBank instead of chosen by the learner.
4. Why RETEST is not LIVE in 14B.
5. What REQUESTED / RUNNING / TELEMETRY_SENT / WAITING_FOR_EVIDENCE / EVIDENCE_READY each mean.
6. Why HEC 200 is not EVIDENCE_READY.
7. How to take a fresh `run.id` into Splunk Search without Studio token JS.
8. Why an empty Splunk table is not prevention.
9. Why simulator activity is not a new DET-* notable.
10. What still remains unproven after one LIVE ATTACK (RETEST, GUIDED Path B, MCP-001).
