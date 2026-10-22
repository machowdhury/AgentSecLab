"""Batch 6 learner-experience contracts that need no browser."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec import mission_loan_desk as mld
from agentsec.loan_desk.model import OllamaChat

ROOT = Path(__file__).resolve().parents[1]
WS = json.loads((ROOT / "learning/level_1/LAB-LOANDESK-001/workshop.json").read_text())


def test_page_objectives_prerequisites_and_duration_equal_the_workshop_definition():
    assert list(mld.OBJECTIVES) == WS["objectives"]
    assert list(mld.PREREQUISITES) == WS["prerequisites"]
    assert mld.DURATION_MINUTES == f'{WS["duration_minutes"]["min"]} to {WS["duration_minutes"]["max"]}'


@pytest.fixture
def page_html(settings):
    from agentsec.attack_app import AcmeBankClient, create_app
    c = create_app(AcmeBankClient("http://127.0.0.1:1")).test_client()
    return c.get("/academy/missions/loan-desk").get_data(as_text=True)


def test_mission_page_states_objectives_prerequisites_time_and_defines_every_required_term(page_html):
    for o in mld.OBJECTIVES:
        assert o.replace("'", "&#39;") in page_html or o in page_html
    assert "By the end you will be able to" in page_html and "What you need" in page_html and "25 to 40 minutes" in page_html
    for term in ("posture", "scope", "pdp", "proposal", "handler", "allow", "verification", "runid"):
        assert f'id="term-{term}"' in page_html, term
    for link in re.findall(r'data-term="([a-z]+)"', page_html):
        assert f'id="term-{link}"' in page_html, link  # no dangling contextual link
    assert page_html.count('class="term"') >= 3


def test_every_heading_level_in_the_page_is_sequential_without_skips(page_html):
    levels = [int(m) for m in re.findall(r"<h([1-6])[ >]", page_html)]
    assert levels[0] == 1 and all(b - a <= 1 for a, b in zip(levels, levels[1:])), levels


def test_script_creates_no_heading_that_skips_a_level():
    js = (ROOT / "src/agentsec/static/academy.js").read_text()
    assert 'el("h4", {text: "Underwriter queue' not in js and 'el("h4", {text: s[0]}' not in js


class _R:
    def __init__(self, code=200, names=()):
        self.status_code = code
        self._n = names

    def json(self):
        return {"models": [{"name": n} for n in self._n]}


def _chat(monkeypatch, result):
    import requests
    calls = []

    def get(url, **k):
        calls.append(("GET", url))
        if isinstance(result, Exception):
            raise result
        return result

    def post(url, **k):  # anything that tries to pull or generate must fail the test
        calls.append(("POST", url))
        raise AssertionError("readiness must never POST (no downloads)")
    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr(requests, "post", post)
    return OllamaChat("http://ollama.invalid:11434", "llama3.2:latest"), calls


def test_readiness_when_ollama_is_down_gives_a_manual_fix_and_downloads_nothing(monkeypatch):
    import requests
    c, calls = _chat(monkeypatch, requests.ConnectionError("x"))
    rd = c.readiness()
    assert not rd["ollama_reachable"] and rd["fix"]["kind"] == "start_ollama" and c.available() == (False, "Ollama is not reachable from AcmeBank.")
    assert all(m == "GET" for m, _ in calls)


def test_readiness_when_the_model_is_missing_names_the_exact_command_and_never_pulls(monkeypatch):
    c, calls = _chat(monkeypatch, _R(names=["llama3.2:1b"]))
    rd = c.readiness()
    assert rd["ollama_reachable"] and not rd["model_installed"] and rd["installed_models"] == ["llama3.2:1b"]
    assert rd["fix"]["command"] == "ollama pull llama3.2:latest" and "never downloads" in rd["fix"]["note"]
    assert "do not disable TLS verification" in rd["fix"]["note"]
    assert c.available()[0] is False and all(m == "GET" for m, _ in calls)


def test_readiness_when_ready_has_no_fix(monkeypatch):
    c, _ = _chat(monkeypatch, _R(names=["llama3.2:latest"]))
    assert c.readiness()["fix"] is None and c.available() == (True, None)


def test_no_loan_desk_code_can_download_a_model_or_relax_tls():
    for p in (ROOT / "src/agentsec/loan_desk").glob("*.py"):
        t = p.read_text()
        assert "/api/pull" not in t and "verify=False" not in t and "ollama pull" not in t.replace('f"ollama pull {want}"', ""), p.name


def test_legacy_phase14b_validator_sends_only_fields_the_launch_contract_accepts(monkeypatch):
    import importlib.util
    from agentsec.launch_contract import ALLOWED_LAUNCH_FIELDS, parse_launch_body
    spec = importlib.util.spec_from_file_location("v14b", ROOT / "scripts/validate_phase14b_live_launch.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sent = {}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b"{}"

    def fake(req, timeout=0):
        sent.update(json.loads(req.data))
        return Resp()
    monkeypatch.setattr(mod.urllib.request, "urlopen", fake)
    mod.post_launch("ATK-002", "ATTACK", "vulnerable")
    assert set(sent) <= ALLOWED_LAUNCH_FIELDS and parse_launch_body(sent).ok
