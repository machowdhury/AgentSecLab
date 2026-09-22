# Contributing

**Contribution policy is not decided.** There is no advertised CLA, issue bot, or guaranteed review SLA.

## Learner workflow

Use [README.md](../README.md) and [docs/QUICKSTART.md](QUICKSTART.md). You should not need a Python venv, pytest, or container shells to complete the Academy.

## Developer workflow

Optional: `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`.

Splunk knowledge-object changes follow repository Splunk engineering rules. Do not add detectors or schema fields without an explicit project decision.

Do not commit `.env`, credentials, or captured production secrets.
