# AgentSec Lab

An open agentic AI security learning and SOC experimentation range. Splunk is where you hunt. AcmeBank is where controls run.

See `docs/IMPLEMENTATION_STATUS.md`. LAB-PI-001 Dashboard Studio: `docs/PHASE2C3_DASHBOARD.md`. Local compose: `docs/LOCAL_DOCKER_LAB.md`.

For Splunk knowledge-object work, read `.cursor/rules/33-splunk-agent-skills.mdc`, then use `.cursor/skills/splunk-ko-review/SKILL.md`, and consult the applicable official Splunk Agent Skills. For learner-facing UI also read `.cursor/rules/32-ui-design-system.mdc` and run `/ui-review`. For evidence/security reasoning run `/logic-proof`. Inventory: `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`.

## Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest tests/unit tests/integration tests/security tests/telemetry tests/splunk tests/workshops -q
```

Stub LLM tests prove DENY-before-call with a spy on the LLM client. They do not prove a live Ollama completion or a Splunk query.

`tests/integration/test_ollama_live.py` uses the real Ollama client and **skips** if the configured model is not reachable. A skip is not a pass.

## LOCAL DOCKER LAB

Fully Docker-managed: AcmeBank, Attack UI, Ollama, OTel Collector, Splunk, `agentsec_telemetry`, HEC, AgentSec app, Dashboard Studio `ws_lab_pi_001`.

```bash
cp .env.example .env    # once; never commit .env
./scripts/lab-up.sh
```

That is the normal start. It stages the Splunk app into a writable named volume **before** Splunk is healthy. Do not `docker cp` the app. Do not `chown` inside the container.

| Change | Command |
|--------|---------|
| First start / after `docker compose down` | `./scripts/lab-up.sh` |
| Rebuild AcmeBank / Attack images | `./scripts/lab-up.sh --build` |
| Edit `splunk_app/agentsec/` while the stack is up | `./scripts/lab-up.sh --refresh-app` |
| Check READY without starting | `./scripts/lab-ready.sh` |
| Clean first boot | `docker compose down -v` then `./scripts/lab-up.sh` |

READY means app files, `ws_lab_pi_001`, index, HEC, mesh HEC, and the two Flask health endpoints. A running Splunk process alone is not READY.

- AcmeBank: http://127.0.0.1:5000
- Attack UI: http://127.0.0.1:5001
- Splunk: http://127.0.0.1:8000 (app **AgentSec**)

Do not publish these ports to the internet. Attack Service is unauthenticated.

## EXTERNAL SPLUNK

Not started by `lab-up.sh`. You supply HEC endpoint, token, and index (environment / collector config) and install `splunk_app/agentsec` with **your** Splunk deployment mechanism (UI install, deployment server, cluster bundle, Splunk Cloud app). Do not use the local named-volume init against an external instance.

Details: `docs/LOCAL_DOCKER_LAB.md`.

## Not in this lab slice

MCP, A2A, memory attacks, RAG attacks, MLTK, Cisco tools, attack chains, compliance UI, background ticker.
