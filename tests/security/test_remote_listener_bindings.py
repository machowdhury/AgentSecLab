"""Remote mode publishes only the three learner ports. These tests never start a container (compose is only rendered)."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

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
    assert "${AGENTSEC_BIND_ADDRESS:-127.0.0.1}:5000:5000" in COMPOSE
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


def test_remote_listeners_allow_only_academy_attack_and_acmebank():
    access = _access()
    text = "\n".join(
        [
            "LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*",
            "LISTEN 0 128 0.0.0.0:5001 0.0.0.0:*",
            "LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*",
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


def test_remote_mode_requires_acmebank_public_and_local_mode_forbids_it():
    access = _access()
    base = [
        "LISTEN 0 128 {h}:8000 0.0.0.0:*", "LISTEN 0 128 {h}:5001 0.0.0.0:*", "LISTEN 0 128 {h}:5000 0.0.0.0:*",
        "LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*", "LISTEN 0 128 127.0.0.1:4317 0.0.0.0:*", "LISTEN 0 128 127.0.0.1:4318 0.0.0.0:*",
    ]
    public = "\n".join(line.format(h="0.0.0.0") for line in base)
    loopback = "\n".join(line.format(h="127.0.0.1") for line in base)
    assert access.evaluate(public, "remote")["ok"] is True
    assert access.evaluate(loopback, "local")["ok"] is True
    assert "AcmeBank port 5000 is public in local mode" in access.evaluate(public, "local")["problems"]
    partial = public.replace("0.0.0.0:5000", "127.0.0.1:5000")
    assert "AcmeBank port 5000 is not a public listener" in access.evaluate(partial, "remote")["problems"]
    # The Splunk management port is never published; if it ever listens publicly the check must fail.
    assert access.evaluate(public + "\nLISTEN 0 128 0.0.0.0:8089 0.0.0.0:*", "remote")["ok"] is False


def _rendered_ports(bind: str | None) -> dict[str, list[tuple[str, int, int]]]:
    env = {k: v for k, v in os.environ.items() if k != "AGENTSEC_BIND_ADDRESS"}
    if bind is not None:
        env["AGENTSEC_BIND_ADDRESS"] = bind
    out = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "--env-file", ".env.example", "--profile", "local", "config", "--format", "json"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=60, check=True,
    ).stdout
    ports: dict[str, list[tuple[str, int, int]]] = {}
    for name, svc in json.loads(out)["services"].items():
        for p in svc.get("ports") or []:
            ports.setdefault(name, []).append((p["host_ip"], int(p["published"]), int(p["target"])))
    return ports


needs_compose = pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")


@needs_compose
@pytest.mark.parametrize("bind,learner_ip", [(None, "127.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("0.0.0.0", "0.0.0.0")])
def test_rendered_compose_publishes_exactly_the_expected_host_ports(bind, learner_ip):
    published = {(ip, host) for rows in _rendered_ports(bind).values() for ip, host, _ in rows}
    assert published == {
        (learner_ip, 8000), (learner_ip, 5001), (learner_ip, 5000),
        ("127.0.0.1", 8088), ("127.0.0.1", 4317), ("127.0.0.1", 4318),
    }
    # Never published in any mode: Splunk management, Ollama, Docker, verifier.
    assert not {8089, 11434, 2375, 2376} & {host for _, host in published}
