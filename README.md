# AgentSec Lab

An open agentic AI security learning and SOC experimentation range. Splunk is where you hunt (later). AcmeBank is where controls run.

Phase 2A is the first trustworthy runtime: four sequential agents, one benign loan, one prompt-injection attack, one input reference control, schema 1.0.0 events, local evidence packs. Splunk ingest is **not** part of this slice.

See `docs/IMPLEMENTATION_STATUS.md` and `docs/PHASE2A_RUNTIME_VALIDATION.md`.

## Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest tests/unit tests/integration tests/security tests/telemetry -q
```

Stub LLM tests prove DENY-before-call with a spy on the LLM client. They do not prove a live Ollama completion or a Splunk query.

`tests/integration/test_ollama_live.py` uses the real Ollama client and **skips** if the configured model is not reachable. A skip is not a pass.

## Local stack (optional)

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local up --build -d
```

- AcmeBank: http://127.0.0.1:5000 (`POST /process`)
- Attack Service: http://127.0.0.1:5001
- Splunk: http://127.0.0.1:8000 (not validated in Phase 2A)

Do not publish these ports to the internet. Attack Service is unauthenticated.

## Not in Phase 2A

MCP, A2A, memory attacks, RAG attacks, MLTK, Cisco tools, attack chains, compliance UI, background ticker, validated SPL, Dashboard Studio JSON.
