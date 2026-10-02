"""Learner navigation must follow the browser host. These tests do not start Docker."""

from __future__ import annotations

from pathlib import Path

from agentsec.search_handoff import browser_splunk_web, rewrite_learner_navigation, search_url

ROOT = Path(__file__).resolve().parents[2]
LEARNER_ROOTS = (
    ROOT / "src" / "agentsec" / "templates",
    ROOT / "src" / "agentsec" / "static",
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views",
    ROOT / "splunk_app" / "agentsec" / "appserver",
)


def test_search_handoff_follows_localhost_remote_ip_and_hostname():
    query = search_url("11111111-1111-1111-1111-111111111111", splunk_web="http://127.0.0.1:8000")
    local = rewrite_learner_navigation(query, "http://127.0.0.1:8000")
    remote = rewrite_learner_navigation(query, "http://203.0.113.10:5001")
    named = rewrite_learner_navigation(query, "http://agentsec.example.test:8000")
    assert local.startswith("http://127.0.0.1:8000/en-US/app/search/search?")
    assert remote.startswith("http://203.0.113.10:8000/en-US/app/search/search?")
    assert named.startswith("http://agentsec.example.test:8000/en-US/app/search/search?")
    assert "11111111-1111-1111-1111-111111111111" in remote
    relative = rewrite_learner_navigation("/en-US/app/search/search", "http://agentsec.example.test:8000")
    assert relative == "/en-US/app/search/search"
    from_attack = rewrite_learner_navigation("/en-US/app/search/search", "http://agentsec.example.test:5001")
    assert from_attack == "http://agentsec.example.test:8000/en-US/app/search/search"


def test_browser_splunk_web_uses_request_hostname_not_a_fixed_address():
    assert browser_splunk_web("agentsec.example.test:5001", "http") == "http://agentsec.example.test:8000"
    assert browser_splunk_web("203.0.113.10:5001", "https") == "https://203.0.113.10:8000"
    assert browser_splunk_web("127.0.0.1:5001", "http") == "http://127.0.0.1:8000"


def test_learner_facing_files_do_not_hardcode_splunk_loopback():
    offenders = []
    for folder in LEARNER_ROOTS:
        for path in folder.rglob("*"):
            if path.suffix not in {".html", ".js", ".xml"}:
                continue
            text = path.read_text(encoding="utf-8")
            if "http://127.0.0.1:8000" in text or "http://localhost:8000" in text:
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
