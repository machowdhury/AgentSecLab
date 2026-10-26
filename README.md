# AgentSecLab

**A hands-on lab for learning how AI agents fail, how to investigate them in Splunk, and how to turn the evidence into an evaluation, a risk assessment and a governance record.**

AgentSecLab runs a small, deliberately simple bank assistant (AcmeBank) that you attack in controlled experiments, then investigate with real telemetry. Nothing in it is a production system. Everything it shows says whether it was run live, replayed from a committed recording, simulated, or only documented.

## Who it is for

Security learners, instructors running a workshop, SOC analysts and security architects who want a local, reproducible place to practise agentic AI security. You do not need to know agents or Splunk search first.

## What you can do

| Step | Where | What it is |
|------|-------|-----------|
| Learn and practice | `/learn` (32 labs) | Guided experiences on prompt injection, tool authorization (MCP), RAG, memory, identity and delegation, scanner and model evaluations, Splunk investigation, threat modeling and privacy |
| Attack | Attack Service (port 5001) | A closed launcher that runs educational attacks against AcmeBank |
| Investigate | Splunk (port 8000) | Dashboards and searches over the telemetry each run produces |
| Evaluate | `/learn/evals` | Recorded and simulated experiments, test cases, findings, comparisons and a report export |
| Assess risk | `/learn/risk` | Source-backed risks you assess yourself, with a qualitative method and a browser-local draft |
| Map controls | `/learn/governance` | Framework relationships, controls, evidence and gaps, with an export |
| Prove | each page | Source files, SHA-256 hashes, limitations and verification status |

## Release status: read this first

- **Published: v1.2.0**, a multi-port plain-HTTP deployment (this README's quick start and tables). **In development, not released: v1.3.0**, which adds an opt-in HTTPS gateway so a hosted deployment exposes exactly one external port (443 or 8000) and a Splunk integration layer. See [Deployment modes at a glance](docs/GATEWAY.md#deployment-modes-at-a-glance).
- `main` is release **v1.2.0**. It includes the React Academy shell, the Security Assurance workshop, the EVAL Center, the Risk Center, the Governance Center and the Workshop path bar. The previous release, `v1.1.0`, served the original Splunk-based pages, which still work.
- **Recorded versus live.** Everything in the EVAL, Risk and Governance Centers and almost every lab is recorded, replayed or simulated evidence, and says so on the page. Only the Loan Desk mission's Attack stage runs a live agent, and it needs the local model (Ollama).
- **What was tested on this branch's deployed build:** automated headless-Chromium checks (navigation, lazy-loaded pages, exports, recorded workbenches, console errors) through a private tunnel. The live Attack stage was **not** run or verified, and no human or screen-reader pass has been done.

## Quick start

You need Docker Engine with Compose v2, Git, `python3`, `curl` and a browser. Podman is **not validated**. Windows is **not validated**. Hardware minimums are **NOT BENCHMARKED**. The full beginner path is [Getting started](docs/GETTING_STARTED.md); details are in the [Quickstart](docs/QUICKSTART.md) and [Troubleshooting](docs/TROUBLESHOOTING.md).

```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
cp .env.example .env
./scripts/lab-preflight.sh
./scripts/lab-up.sh
```

The commands above start the **local Docker lab**. **External Splunk** is not started by `lab-up.sh`; see [Local Docker lab](docs/LOCAL_DOCKER_LAB.md).

**Start in the React Academy: <http://127.0.0.1:5001/learn>.** Pause the lab with `./scripts/lab-down.sh` (it pauses; it does not delete data).

### What is where

*This table is the published v1.2.0 multi-port HTTP deployment. With the opt-in v1.3.0 gateway (unreleased) only one HTTPS port is externally reachable, and Splunk Web is not reachable through it; see [Unified HTTPS gateway](docs/GATEWAY.md).*

| What | Local URL | Notes |
|---|---|---|
| **Academy (start here)** | <http://127.0.0.1:5001/learn> | The React Academy: labs, Loan Desk mission, EVAL, Risk, Governance. Served by the Attack Service app |
| Attack Service | `http://127.0.0.1:5001` (port 5001) | The same app also serves the launcher API and the original pages (`/`, `/academy`, `/labs/...`). It runs educational attacks |
| AcmeBank | `http://127.0.0.1:5000/health` (port 5000) | The target application; the lab runs it, you rarely open it |
| Splunk Web | <http://127.0.0.1:8000> (port 8000) | Investigation searches and dashboards; log in as `admin` (password in `.env`) |
| Legacy Splunk dashboards | http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home | The original Splunk-based Academy Home. Still works; not the starting point for this release |

### Local access versus private EC2 access
- **Local (default).** Every learner port binds to `127.0.0.1`, so only the machine running the lab can reach it. `./scripts/lab-up.sh` forces this.
- **Private EC2.** Keep the instance in local mode and reach it with an AWS SSM port-forward, which needs no inbound port and no security-group change: forward instance port 5001 to a local port and browse `http://127.0.0.1:<local-port>/learn`. Commands are in [Remote access](docs/REMOTE_ACCESS.md).
- **No authentication, no TLS.** The Attack Service, Academy, AcmeBank and Splunk login travel over plain HTTP and the Attack Service launches attacks for anyone who can reach it. Never expose these ports to the Internet; `--remote` does not make them safe. See [Remote access](docs/REMOTE_ACCESS.md) and the [HTTPS proposal](docs/HTTPS_INGRESS_PROPOSAL.md). The v1.3.0 **opt-in HTTPS gateway** (implemented and tested on the development branch, **unreleased**) provides TLS, authentication and a single external port (443 or 8000); see [Unified HTTPS gateway](docs/GATEWAY.md). Splunk Web through the gateway is NOT VERIFIED, and external Splunk Enterprise/Cloud is mock-tested only ([Splunk integration](docs/SPLUNK_INTEGRATION.md)).

### Versions
This platform release is **v1.2.0** (the GitHub release and tag); v1.3.0 is unreleased development. The embedded Splunk app and the application's health payload still report **1.1.0**; that is expected and is not a mismatch to fix for this release.

## The learning journey

A **Workshop path** bar on lab, mission and Center pages shows six steps in order. These are the six stages of the journey:

1. **Learn**: read a lab or the curriculum.
2. **Attack**: the Loan Desk mission's Attack stage (live agent; locked until you lock a prediction).
3. **Investigate**: prove what happened from recorded Splunk evidence.
4. **EVAL**: read recorded and simulated experiments, findings and a report export.
5. **Risk**: assess source-backed risks yourself in a local, unapproved draft.
6. **Governance**: see framework relationships, controls and gaps, with an export.

The **Loan Desk mission** (`/learn/loan-desk`) is separate from the six steps and has its own seven stages: Learn, Prepare, Attack, Investigate, Defend, Retest, Explain. Its Attack, Investigate, Defend and Retest stages unlock in order. The path bar's Attack and Investigate steps point into that mission; Learn, EVAL, Risk and Governance have their own pages.

The **legacy L0–L10 curriculum** is a third, older numbering from the Splunk-based Academy Home. It still works and is described in the [legacy guide](docs/LEGACY_SPLUNK_ACADEMY_GUIDE.md); do not confuse it with the six steps or the mission stages.

## LIVE and REPLAY

Ollama is the local LLM runtime AgentSec uses for LIVE labs. It is not part of Splunk. **LIVE** labs run a fresh attack. **REPLAY** labs investigate previously captured evidence and do not need Ollama; a REPLAY page is not proof you just ran that attack. See [LIVE vs REPLAY](docs/LIVE_VS_REPLAY.md).

Your first successful experience: open **LAB-HITL-APPROVAL** (Human Approval and Action Binding), choose a prediction on the **Practice** tab (was the action inside the approval's time window, and was the approval bound to it?), reveal the recorded packet, then open **Prove** to see its sources and SHA-256 digests. Then follow the [Learner guide](docs/LEARNER_GUIDE.md) into the EVAL, Risk and Governance Centers. This lab is recorded and simulated; it runs nothing live.

## Documentation

[Documentation index](docs/README.md) · [Getting started](docs/GETTING_STARTED.md) · [Learner guide](docs/LEARNER_GUIDE.md) · [Instructor guide](docs/INSTRUCTOR_GUIDE.md) · [Architecture](docs/ARCHITECTURE_GUIDE.md) · [Evaluation and risk](docs/EVALUATION_AND_RISK_GUIDE.md) · [Governance](docs/GOVERNANCE_GUIDE.md) · [Contributing](CONTRIBUTING.md) · [Full project reference](docs/PROJECT_REFERENCE.md)

## Safety and limitations

- The lab is for **local, educational** use. It intentionally contains vulnerable agent profiles and contains deliberately vulnerable profiles. Do not expose it to the Internet. The default bind address is `127.0.0.1`; see [Remote access](docs/REMOTE_ACCESS.md) before changing it.
- Lab defaults in `.env.example` are not production secrets. Never commit `.env`.
- Recorded evidence shows what happened in one run. It is not a rate, a guarantee or an assessment of any real system.
- Framework relationships are educational links. AgentSecLab makes no compliance or certification claim.
- No run shown in the new Centers has an independent verifier receipt, so they are labelled `NOT_VERIFIED`.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
