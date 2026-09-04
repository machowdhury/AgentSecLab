# AgentSec Lab

An open agentic AI security learning and SOC experimentation range. Splunk is where you hunt. AcmeBank is where controls run.

Phase 2 runtime is a small loop: four sequential agents, one benign loan, one prompt-injection attack, one input control, OpenTelemetry, evidence packs.

## Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest tests/unit tests/integration tests/security tests/telemetry -q
```

Stub LLM tests prove DENY-before-call. They do not prove a live Ollama or Splunk query.

## Local stack (optional)

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local up --build -d
```

- AcmeBank: http://127.0.0.1:5000
- Attack Service: http://127.0.0.1:5001
- Splunk: http://127.0.0.1:8000

Do not publish these ports to the internet. Attack Service is unauthenticated.

## Not in Phase 2

MCP, A2A, memory attacks, RAG attacks, MLTK, Cisco tools, complex governance, Dashboard Studio JSON.
