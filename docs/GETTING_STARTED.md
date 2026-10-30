# Getting started

> **Legacy: not the supported path.** This page describes the earlier multi-port, plain-HTTP flow (`scripts/lab-up.sh`, published as v1.2.0), in which ports 5000, 5001 and 8000 are published. In RC2 (a release candidate, unreleased) those ports are internal. The supported path is the installer and the single HTTPS gateway: install with `./agentsec` ([Installation and deployment](INSTALLATION_AND_DEPLOYMENT.md)) and open `https://localhost/learn`. Learners investigate inside the Academy; Splunk Web is an optional Advanced view. macOS, Windows and this older flow were **not** part of the RC2 acceptance runs. Do not mix the two flows on one machine without reading [Installer](INSTALLER.md) on existing labs.

The legacy beginner path for release v1.2.0 (for RC2, follow the [README quick start](../README.md#quick-start-ubuntu-2404-docker) and open `https://localhost/learn`). You do not need to understand Docker networking or Splunk first. Run every command from the repository root.

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
The React Academy is your starting point: `https://localhost/learn` in the supported flow; in this legacy flow it is served by the Attack Service at <http://127.0.0.1:5001/learn>.

## 8. First recorded lab
Open **LAB-HITL-APPROVAL** (Human Approval and Action Binding). On **Practice**, choose a prediction, reveal the recorded packet, then open **Prove** for sources and SHA-256 digests. **Predict → Reveal → Prove.** It is recorded and simulated: nothing runs live and no model is needed.

## 9. Investigate
In the supported flow you investigate inside the Academy: the Investigate stage is a notebook where you press **Run** and the Attack Service executes an approved, fixed-template search against Splunk and shows the rows, a chart and a plain-language reading; Splunk Web and the dashboards are an optional Advanced view. In this legacy flow investigation uses Splunk Web at <http://127.0.0.1:8000> (log in as `admin`): copy the LIVE launch's `run.id` and search for it. Recorded labs show recorded observations. An empty result means the events are not indexed (yet), not that nothing happened. LIVE versus REPLAY: [LIVE vs REPLAY](LIVE_VS_REPLAY.md).

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
| **Loan Desk mission stages** | Seven stages: Learn, Prepare, Attack, Investigate, Defend, Retest, Explain (live agent; needs the model). LIVE workshops show eight stages on the same rail: Learn, Predict, Baseline, Attack, Investigate, Defend, Retest, Explain evidence | `/learn/loan-desk` |
| **Legacy L0–L10 curriculum** | The original Splunk-based Academy Home path | [Legacy guide](LEGACY_SPLUNK_ACADEMY_GUIDE.md) |

## Ports, access and security
*Published v1.2.0 deployment (legacy; in RC2 these ports are internal and learners never open them).* The opt-in HTTPS gateway (unreleased, the RC2 installer default) replaces this multi-port layout with exactly one external HTTPS port, 443 or 8000: see [Deployment modes at a glance](GATEWAY.md#deployment-modes-at-a-glance).

| Service | Port | Notes |
|---|---|---|
| Academy and Attack Service | 5001 | The Academy is at `/learn`; the same app launches attacks |
| AcmeBank | 5000 | Target application |
| Splunk Web | 8000 | Investigation |
| Telemetry (HEC, OTel) | 8088, 4317, 4318 | Always loopback-only |

- By default everything binds to `127.0.0.1`. The Attack Service has **no built-in authentication or TLS** and launches attacks for anyone who can reach it. Never expose these ports to the Internet.
- For a remote machine use a private SSM or SSH tunnel: [Remote access](REMOTE_ACCESS.md).
- The **opt-in HTTPS gateway is implemented and tested but unreleased** ([Unified HTTPS gateway](GATEWAY.md)). It is not part of the published v1.2.0 steps above. If you use it, Splunk Web is **not** reachable through the gateway (NOT VERIFIED); on the gateway host it is on `127.0.0.1:18000`.

## For contributors
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test,ui]'
PYTHONPATH=src .venv/bin/python -m pytest          # browser tests need Chromium: playwright install chromium, or set AGENTSEC_CHROMIUM
sh scripts/build_academy_ui.sh                    # rebuild the Academy UI (needs Docker)
```
