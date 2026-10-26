# Getting started

The one beginner path for release v1.2.0. You do not need to understand Docker networking or Splunk first. Run every command from the repository root.

**Clone → Prerequisites → Configure → Preflight → Start → Verify readiness → Open the Academy → First recorded lab → Investigate → Continue.**

## 1. Clone
```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
```
`main` is release v1.2.0.

## 2. Prerequisites
Git, Docker Engine with Compose v2, `python3`, `curl`, and a browser. Plan for about 8 GB of free disk. The first start can take 10–20 minutes because Splunk initialises. Podman and Windows are not validated. Details: [Prerequisites](AGENTSEC_PREREQUISITES.md).

## 3. Configure
```bash
cp .env.example .env
```
The file holds **lab defaults** for your own machine, not production secrets. Do not commit `.env`. The Splunk `admin` password is `SPLUNK_PASSWORD` in `.env` (default `ChangeMeLab!2026`).

## 4. Preflight
```bash
./scripts/lab-preflight.sh
```
`RESULT FAIL` means fix it before continuing; `WARN` means read it and continue. Ports 5000, 5001 and 8000 must be free (on macOS, turn off AirPlay Receiver if it holds 5000). More: [Troubleshooting](TROUBLESHOOTING.md).

## 5. Start
```bash
./scripts/lab-up.sh
```
It builds and starts the lab and waits for readiness. **If an older AgentSec lab is already on this machine, run `./scripts/lab-up.sh --build` once**: without `--build`, existing images are reused, and the old Attack Service answers `/learn` with `No such Attack Service route` (HTTP 400). Other options are in [Quickstart](QUICKSTART.md).

## 6. Verify readiness
```bash
./scripts/lab-ready.sh
curl -sS http://127.0.0.1:5001/health
```
`SERVICE READY` means the containers and web endpoints answered. `MODEL PRESENT` or `MODEL ABSENT` says whether the LIVE-lab model is listed; `ABSENT` (`DEGRADED`) affects LIVE labs only. **Service readiness is not verified telemetry:** a run's events are searchable in Splunk only when a Splunk search actually returns them. Readiness words are defined in [Quickstart](QUICKSTART.md#6-readiness-words).

## 7. Open the Academy
**<http://127.0.0.1:5001/learn>**: the React Academy, your starting point.

## 8. First recorded lab
Open **LAB-HITL-APPROVAL** (Human Approval and Action Binding). On **Practice**, choose a prediction, reveal the recorded packet, then open **Prove** for sources and SHA-256 digests. **Predict → Reveal → Prove.** It is recorded and simulated: nothing runs live and no model is needed.

## 9. Investigate
Investigation uses Splunk Web at <http://127.0.0.1:8000> (log in as `admin`). Recorded labs show recorded observations; for a LIVE launch, copy its `run.id` and search for it. An empty result means the events are not indexed (yet), not that nothing happened. LIVE versus REPLAY: [LIVE vs REPLAY](LIVE_VS_REPLAY.md).

## 10. Continue learning
Follow the six-step journey in the [Learner guide](LEARNER_GUIDE.md): Learn, Attack, Investigate, EVAL, Risk, Governance.

## Stop and restart (your data is kept)
```bash
./scripts/lab-down.sh      # pauses; containers stop, nothing is deleted
./scripts/lab-up.sh        # resumes on the same volumes
```
Removing containers or deleting data are separate, explicit commands: [Operations](OPERATIONS.md).

## Three numbering schemes (do not mix them up)
| Name | What it is | Where |
|---|---|---|
| **Six-step journey** | Learn, Attack, Investigate, EVAL, Risk, Governance: the Workshop path bar | React Academy |
| **Loan Desk mission stages** | Seven stages: Learn, Prepare, Attack, Investigate, Defend, Retest, Explain (live agent; needs the model) | `/learn/loan-desk` |
| **Legacy L0–L10 curriculum** | The original Splunk-based Academy Home path | [Legacy guide](LEGACY_SPLUNK_ACADEMY_GUIDE.md) |

## Ports, access and security
| Service | Port | Notes |
|---|---|---|
| Academy and Attack Service | 5001 | The Academy is at `/learn`; the same app launches attacks |
| AcmeBank | 5000 | Target application |
| Splunk Web | 8000 | Investigation |
| Telemetry (HEC, OTel) | 8088, 4317, 4318 | Always loopback-only |

- By default everything binds to `127.0.0.1`. The Attack Service has **no built-in authentication or TLS** and launches attacks for anyone who can reach it. Never expose these ports to the Internet.
- For a remote machine use a private SSM or SSH tunnel: [Remote access](REMOTE_ACCESS.md).
- A single authenticated HTTPS entry point is **planned for v1.3.0 and is not implemented in v1.2.0** ([proposal](HTTPS_INGRESS_PROPOSAL.md)).

## For contributors
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test,ui]'
PYTHONPATH=src .venv/bin/python -m pytest          # browser tests need Chromium: playwright install chromium, or set AGENTSEC_CHROMIUM
sh scripts/build_academy_ui.sh                    # rebuild the Academy UI (needs Docker)
```
