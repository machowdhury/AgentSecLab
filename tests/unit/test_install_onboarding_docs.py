"""Learner install docs match the scripts and compose file.

These checks read documentation and source. They do not start Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")
PREREQ = (ROOT / "docs" / "AGENTSEC_PREREQUISITES.md").read_text(encoding="utf-8")
QUICK = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
TROUBLE = (ROOT / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")
OPS = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
LAB_UP = (ROOT / "scripts" / "lab-up.sh").read_text(encoding="utf-8")
PREFLIGHT = (ROOT / "scripts" / "lab-preflight.sh").read_text(encoding="utf-8")


def test_install_entry_order_and_runtime_status():
    clone_at = README.index("git clone https://github.com/machowdhury/AgentSecLab.git")
    copy_at = README.index("cp .env.example .env")
    preflight_at = README.index("./scripts/lab-preflight.sh")
    up_at = README.index("./scripts/lab-up.sh")
    assert clone_at < copy_at < preflight_at < up_at
    assert "Podman is **not validated**" in README
    assert "NOT VALIDATED" in PREREQ
    assert "podman compose up" not in PREREQ
    assert "Container Runtime Requirements" in PREREQ
    assert "NOT BENCHMARKED" in PREREQ


def test_documented_flags_and_preflight_checks_exist_in_scripts():
    for flag in ("--build", "--refresh-app", "--no-wait", "--help"):
        assert flag in LAB_UP
        assert flag in QUICK
    for token in (
        "docker info",
        "docker compose version",
        "RESULT PASS",
        "RESULT WARN",
        "RESULT FAIL",
        "llama3.2:1b",
    ):
        assert token in PREFLIGHT
        assert token in QUICK
    assert "ollama pull" in (ROOT / "scripts" / "ollama_init.sh").read_text(encoding="utf-8")
    assert "does not itself run `ollama pull`" in QUICK


def test_documented_ports_and_services_match_compose():
    for port in ("5000", "5001", "8000", "8088", "4317", "4318"):
        assert f"127.0.0.1:{port}:{port}" in COMPOSE or (
            port in ("4317", "4318") and f"127.0.0.1:{port}:{port}" in COMPOSE
        )
        assert port in QUICK
    for name in (
        "agentsec_ollama",
        "agentsec_splunk",
        "agentsec_acmebank",
        "agentsec_attack_service",
        "agentsec_otel_collector",
        "agentsec_splunk_app_init",
        "agentsec_splunk_hec_init",
    ):
        assert name in COMPOSE
        assert name in PREREQ
    assert 'image: ollama/ollama:latest' in COMPOSE
    assert "splunk/splunk:10.2" in COMPOSE
    assert "/health" in (ROOT / "src" / "agentsec" / "bank_app.py").read_text(encoding="utf-8")
    assert "/health" in (ROOT / "src" / "agentsec" / "attack_app.py").read_text(encoding="utf-8")


def test_status_words_and_host_failures_are_documented():
    for word in ("SERVICE READY", "MODEL ABSENT", "DEGRADED", "NOT READY"):
        assert word in QUICK
    assert "DEGRADED" in QUICK and "not a pass" in QUICK
    assert "mountinfo" in TROUBLE
    assert "hello-world" in TROUBLE
    assert "Dockerfile.acmebank" in TROUBLE
    assert "down -v" in OPS
    assert "lab-down.sh" in OPS
    for path in (
        ROOT / "scripts" / "lab-up.sh",
        ROOT / "scripts" / "lab-down.sh",
        ROOT / "scripts" / "lab-preflight.sh",
        ROOT / "scripts" / "lab-ready.sh",
        ROOT / "scripts" / "ollama_init.sh",
    ):
        assert path.is_file()


def test_install_doc_links_resolve():
    missing = []
    for rel in (
        "README.md",
        "docs/QUICKSTART.md",
        "docs/GETTING_STARTED.md",
        "docs/AGENTSEC_PREREQUISITES.md",
        "docs/TROUBLESHOOTING.md",
        "docs/OPERATIONS.md",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        base = (ROOT / rel).parent
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path = target.split("#", 1)[0]
            if path and not (base / path).resolve().exists():
                missing.append(f"{rel} -> {target}")
    assert missing == []
