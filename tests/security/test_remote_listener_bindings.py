"""Remote mode publishes only learner ports. These tests do not start Docker."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
LAB_UP = (ROOT / "scripts" / "lab-up.sh").read_text(encoding="utf-8")
REMOTE_DOC = (ROOT / "docs" / "REMOTE_ACCESS.md").read_text(encoding="utf-8")


def _access():
    path = ROOT / "scripts" / "agentsec_access.py"
    spec = importlib.util.spec_from_file_location("agentsec_access", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_compose_keeps_private_ports_literal_and_learner_ports_variable():
    assert "127.0.0.1:5000:5000" in COMPOSE
    assert "127.0.0.1:8088:8088" in COMPOSE
    assert "127.0.0.1:4317:4317" in COMPOSE
    assert "127.0.0.1:4318:4318" in COMPOSE
    assert "${AGENTSEC_BIND_ADDRESS:-127.0.0.1}:8000:8000" in COMPOSE
    assert "${AGENTSEC_BIND_ADDRESS:-127.0.0.1}:5001:5001" in COMPOSE
    assert "11434:11434" not in COMPOSE
    assert "AGENTSEC_BIND_ADDRESS=127.0.0.1" in LAB_UP
    assert "AGENTSEC_BIND_ADDRESS=0.0.0.0" in LAB_UP


def test_local_listeners_reject_public_learner_ports():
    access = _access()
    text = "\n".join(
        [
            "LISTEN 0 128 127.0.0.1:8000 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:5001 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:5000 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:4317 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:4318 0.0.0.0:*",
        ]
    )
    local = access.evaluate(text, "local")
    remote = access.evaluate(text, "remote")
    assert local["ok"] is True
    assert remote["ok"] is False
    assert "Academy port 8000 is not a public listener" in remote["problems"]


def test_remote_listeners_allow_only_academy_and_attack():
    access = _access()
    text = "\n".join(
        [
            "LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*",
            "LISTEN 0 128 0.0.0.0:5001 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:5000 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:4317 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:4318 0.0.0.0:*",
        ]
    )
    remote = access.evaluate(text, "remote")
    assert remote["ok"] is True
    leaked = text.replace("127.0.0.1:8088", "0.0.0.0:8088")
    hec = access.evaluate(leaked, "remote")
    assert hec["ok"] is False
    assert any("8088" in problem for problem in hec["problems"])
    ollama = access.evaluate(text + "\nLISTEN 0 128 0.0.0.0:11434 0.0.0.0:*\n", "remote")
    assert ollama["ok"] is False


def test_public_host_is_not_invented_and_docs_reject_world_open():
    access = _access()
    assert access.valid_public_host("") == ""
    assert access.valid_public_host("127.0.0.1") == ""
    assert access.valid_public_host("localhost") == ""
    assert access.valid_public_host("3.17.29.24") == "3.17.29.24"
    assert access.valid_public_host("bad host") == ""
    assert access.learner_urls("")[0].startswith("http://<your-server-public-ip>:8000/")
    assert "0.0.0.0/0" in REMOTE_DOC
    assert "NOT MEASURED" in REMOTE_DOC
    assert "Do not open" in REMOTE_DOC
