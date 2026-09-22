# External validation guide — AgentSec v1.0.0-rc1

Use only this repository. Do not ask the builder for unpublished commands.

## 1. Prerequisites

Docker Engine + Compose v2, Git, a browser. Hardware floors are **NOT BENCHMARKED**.

## 2. Install

```bash
git clone <this-repo>
cd AgentSecLab
git checkout v1.0.0-rc1   # after the tag exists
./scripts/lab-preflight.sh
cp .env.example .env      # do not commit .env
./scripts/lab-up.sh --build
./scripts/lab-ready.sh
```

READY is service health, not searchable evidence.

## 3. Health

Open http://127.0.0.1:8000 (admin / password from `.env`), http://127.0.0.1:5001, http://127.0.0.1:5000/health.

## 4. Academy

http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home — read ORIENT.

## 5. First LIVE lab

Direct Prompt Injection. Predict. Launch ATTACK from Attack Service. Copy the **new** run.id.

## 6. Investigate

Search: `index=agentsec_telemetry sourcetype=otel:agentic:json` and quoted `agentsec.run.id`. Path A first.

## 7. ATTACK vs RETEST

Same specimen, RETEST mode. Compare fingerprints and control/execution evidence. One RETEST is not universal security.

## 8–9. Capstone and Mastery

Complete only after Foundations + context + intent. Mastery is unscored.

## 10. Troubleshooting

`docs/TROUBLESHOOTING.md`. Empty Search is not DENY.

## 11. Feedback

`V1_0_0_RC1_VALIDATOR_FEEDBACK.md`.

## Checklist

- [ ] Preflight understood
- [ ] Lab READY
- [ ] Home loads
- [ ] LIVE run.id minted
- [ ] Search found events (or documented delay)
- [ ] Named the PDP
- [ ] Distinguished ALLOW vs execution
- [ ] Stated something NOT proven
