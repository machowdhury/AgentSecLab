# AGENTSEC — 15 October 2026 troubleshooting

Stay on the **existing** stack. Do not restart unrelated host applications. Do not `docker compose down -v`.

---

## Mode discipline

If badges say **LIVE**, you are not in REPLAY. Either continue in LIVE and say so, or click **Use the recorded pair in this tab (REPLAY)** on the Attack step. That changes **this browser tab only**.

---

## Academy will not load

| Check | Action |
|-------|--------|
| `http://127.0.0.1:5001/academy` not 200 | `docker ps` — `agentsec_attack_service` should be healthy. `./scripts/academy-restart.sh` restarts **only** Attack Service. |
| Connection refused | Do not rebind ports. AgentSec Splunk and Academy are exclusive on `127.0.0.1:8000/8088/5001`. |
| Wrong page / old UI | Attack Service image may be stale. Rebuild **only** `attack_service` if the operator confirms P1.6 JS is required. Do not recreate Splunk. |

---

## lab-ready reports DEGRADED model

Ollama with an empty catalog. **LAB-MCP-001 does not need a model.** Continue. Do not disable TLS to pull models.

---

## Launch LIVE fails or times out

The UI must say **ERROR, not a control decision**. Nothing was recorded; you may retry.

Fall back to **REPLAY** and disclose.

`hec.ok: false` on a **successful** launch JSON is expected. Runtime never sends HEC. Check `otlp.ok` and then **search Splunk**, not `hec.ok`.

---

## Notebook empty / missing evidence

| Symptom | Meaning | Action |
|---------|---------|--------|
| “Run or open an ATTACK first” | No run in this tab | Load REPLAY or launch LIVE |
| UNAVAILABLE / unknown_run | UUID not a committed pack and not an authorized LIVE launch | Do not call it DENY or SAFE |
| Recovered LIVE id, empty table | Artifact missing on disk | Try the other run, or switch this tab to REPLAY |

Malformed ids are rejected. That is not a hunt result.

---

## Splunk has 0 rows for a LIVE id

1. Wait 10–20 seconds; search `earliest=0`.
2. Confirm index `agentsec_telemetry`, sourcetype `otel:agentic:json`.
3. Compare local `artifacts/<run_id>/events.jsonl` line count.
4. If local has events and Splunk has 0: teach **missing copy**, not prevention. Continue from the Academy notebook (authoritative for the workshop).
5. Historical P1.4 LIVE ids `4eab6700-…` and `2343f9e1-…` were **never backfilled**. Do not use them as Splunk proof.

Do not change collector TLS or HEC tokens during the session unless an operator already documented a break.

---

## Splunk Web unreachable

Academy notebook still works from local records. Say: “Splunk is the corroborating copy. It is unavailable; the control decision still happened in AcmeBank.”

Do not point the browser at any other Splunk on the host.

---

## Compare table missing

Complete **both** ATTACK and RETEST in the **same mode**. LIVE ATTACK cannot pair with REPLAY RETEST in the UI. If mixed, start a new tab or use the REPLAY switch (replaces both slots in this tab).

---

## Buttons disabled

| Gate | Cause |
|------|--------|
| ATTACK launch/replay disabled | Prediction not locked, or an ATTACK already recorded in this tab (including a LIVE pair auto-loaded from the server). Click **Clear this tab and launch a fresh LIVE pair** to start over in this tab. |
| LIVE RETEST disabled | ATTACK was REPLAY, or RETEST already present |
| REPLAY RETEST disabled | ATTACK was LIVE |

One run per mode per tab prevents duplicates.

---

## Progress says complete after reload

Browser `sessionStorage`. Not a security control. Reset: close the tab or clear site data for `127.0.0.1:5001`. Durable **LIVE** ids can still reappear from `/api/academy/live-runs` in a new tab. In the current tab, **Clear this tab and launch a fresh LIVE pair** stops that tab re-adopting them.

## Cosmetic: provenance reads "LIVE LIVE —"

The badge and the provenance sentence both say LIVE. Known, harmless, not fixed for Oct 15.

## lab-ready "Academy" line points at Splunk

`lab-ready.sh` prints the Splunk home view `ws_agentsec_home` as "Academy". The browser Academy used in this demo is `http://127.0.0.1:5001/academy`.

---

## Slow backend (45s)

Launch aborts. Message must remain ERROR, not DENY. Retry once, then REPLAY.

---

## Interrupted navigation / accidental refresh

Reload the workshop URL. If LIVE slots rehydrate, badges will say LIVE. Use the REPLAY switch if you need the recording.

---

## Isolation / port conflict

If `127.0.0.1:8000` is not AgentSec Splunk, **stop the demo** rather than reconfiguring someone else’s app. Isolation policy: exclusive AgentSec ports; do not modify unrelated applications.

---

## Nuclear options (operator only, after the session)

| Action | Effect |
|--------|--------|
| `./scripts/academy-restart.sh` | Attack Service only; notebook LIVE index on `artifacts/` survives |
| `./scripts/lab-down.sh` && `./scripts/lab-up.sh` | Restarts lab compose services; **not** a volume wipe if you avoid `-v` |
| `down -v` | Destroys Splunk history — **not for demo day** |
