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
    academy = rewrite_learner_navigation(
        "/en-US/app/agentsec/ws_agentsec_home",
        "http://203.0.113.10:5001",
    )
    assert academy == "http://203.0.113.10:8000/en-US/app/agentsec/ws_agentsec_home"
    local_academy = rewrite_learner_navigation(
        "/en-US/app/agentsec/ws_lab_pi_001",
        "http://127.0.0.1:5001",
    )
    assert local_academy == "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
    assert rewrite_learner_navigation("/labs/LAB-MCP-001", "http://203.0.113.10:5001") == "/labs/LAB-MCP-001"
    assert rewrite_learner_navigation("/", "http://agentsec.example.test:5001") == "/"
    assert rewrite_learner_navigation("/labs/LAB-PI-001", "http://127.0.0.1:5001") == "/labs/LAB-PI-001"
    assert "3.17.29.24" not in academy
    assert "localhost" not in academy


def test_browser_script_keeps_attack_routes_and_moves_academy_routes():
    import shutil
    import subprocess

    node = shutil.which("node")
    assert node
    program = r"""
const fs = require("fs");
const vm = require("vm");
const window = {};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {window, URL});
const href = window.AgentSecUI.learnerHref;
const remote = {protocol: "http:", hostname: "203.0.113.10", port: "5001", origin: "http://203.0.113.10:5001"};
const local = {protocol: "http:", hostname: "127.0.0.1", port: "5001", origin: "http://127.0.0.1:5001"};
const named = {protocol: "http:", hostname: "agentsec.example.test", port: "5001", origin: "http://agentsec.example.test:5001"};
const academy = {protocol: "http:", hostname: "agentsec.example.test", port: "8000", origin: "http://agentsec.example.test:8000"};
if (href("/labs/LAB-MCP-001", remote) !== "/labs/LAB-MCP-001") throw new Error("switcher");
if (href("/", named) !== "/") throw new Error("next root");
if (href("/en-US/app/agentsec/ws_agentsec_home", remote) !== "http://203.0.113.10:8000/en-US/app/agentsec/ws_agentsec_home") throw new Error("academy");
if (href("/en-US/app/search/search", local) !== "http://127.0.0.1:8000/en-US/app/search/search") throw new Error("search");
if (href("/en-US/app/agentsec/ws_agentsec_arena", academy) !== "/en-US/app/agentsec/ws_agentsec_arena") throw new Error("already splunk");
if (href("http://127.0.0.1:8000/en-US/app/search/search?q=1", named) !== "http://agentsec.example.test:8000/en-US/app/search/search?q=1") throw new Error("absolute search");
const moved = href("/en-US/app/agentsec/learner_path", remote);
if (moved.includes("3.17.29.24") || moved.includes("localhost")) throw new Error(moved);
"""
    script = ROOT / "src/agentsec/static/agentsec-ui.js"
    completed = subprocess.run([node, "-e", program, str(script)], check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


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
