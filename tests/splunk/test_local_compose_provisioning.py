"""Compose contracts for automated local Splunk app provisioning.

Does not start Docker. Live boot evidence belongs in docs/LOCAL_DOCKER_LAB.md.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
LOCAL = (ROOT / "docker-compose.local.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
APP_README = (ROOT / "splunk_app" / "agentsec" / "README.md").read_text(encoding="utf-8")


def test_named_volume_not_readonly_repo_bind_on_splunk_home():
    assert "splunk_app_agentsec:" in COMPOSE
    assert "splunk_app_init:" in COMPOSE
    assert "splunk_app_agentsec:/opt/splunk/etc/apps/agentsec" in COMPOSE
    assert "./splunk_app/agentsec:/opt/splunk/etc/apps" not in COMPOSE
    assert "/tmp/agentsec-app" not in COMPOSE
    assert "splunk_app_agentsec:/opt/splunk/etc/apps/agentsec:ro" not in COMPOSE
    assert "./splunk_app/agentsec:/src:ro" in COMPOSE
    assert "condition: service_completed_successfully" in COMPOSE
    assert "ws_lab_pi_001.xml" in COMPOSE
    assert "127.0.0.1:11434:11434" not in COMPOSE


def test_helpers_and_docs_describe_local_vs_external():
    assert (ROOT / "scripts" / "lab-up.sh").is_file()
    assert (ROOT / "scripts" / "lab-ready.sh").is_file()
    assert (ROOT / "docs" / "LOCAL_DOCKER_LAB.md").is_file()
    readme = README.lower()
    assert "local docker lab" in readme
    assert "external splunk" in readme
    assert "cp -a /tmp/agentsec-app" not in README
    assert "cp -a /tmp/agentsec-app" not in APP_README
    assert "./scripts/lab-up.sh" in README
