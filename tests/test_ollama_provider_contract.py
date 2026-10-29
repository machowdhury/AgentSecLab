"""Ollama provider contract: container is the default, host is a documented supported option."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_container_ollama_is_the_default_and_unpublished():
    compose = _read("docker-compose.yml")
    assert "OLLAMA_BASE_URL=${OLLAMA_BASE_URL:-http://ollama:11434}" in compose
    assert not re.search(r"11434:11434", compose)


def test_acmebank_can_reach_host_ollama():
    assert "host.docker.internal:host-gateway" in _read("docker-compose.local.yml")


def test_env_example_documents_host_option_without_enabling_it():
    env = _read(".env.example")
    assert re.search(r"(?m)^# OLLAMA_BASE_URL=http://host\.docker\.internal:11434$", env)
    assert not re.search(r"(?m)^OLLAMA_BASE_URL=", env)  # default stays container


def test_lab_ready_identifies_provider_and_checks_from_acmebank():
    ready = _read("scripts/lab-ready.sh")
    assert "OLLAMA PROVIDER:" in ready
    assert 'docker exec "$(svc_id acmebank)" curl' in ready  # same vantage point as the app, found by Compose service rather than a fixed name
    assert "ollama list" not in ready  # the container-only check caused a false DEGRADED in host mode


def test_host_option_is_documented_without_weakening_tls():
    doc = _read("docs/LOCAL_DOCKER_LAB.md")
    assert "OLLAMA_BASE_URL=http://host.docker.internal:11434" in doc
    assert "never disabled" in doc
