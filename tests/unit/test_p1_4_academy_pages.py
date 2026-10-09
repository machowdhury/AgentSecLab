"""P1.4: Academy page structure, curriculum fidelity and accessibility primitives (offline)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentsec.academy import load_curriculum
from agentsec.attack_app import AcmeBankClient, create_app

ROOT = Path(__file__).resolve().parents[2]
CSS = ROOT / "src" / "agentsec" / "static" / "academy.css"
STEPS = ["start", "baseline", "predict", "attack", "investigate", "defend", "retest", "compare", "explain"]
BRIEF = ["What you are doing", "Why it matters", "What to do", "Evidence to inspect", "What you will learn"]


@pytest.fixture(scope="module")
def client():
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda _p: (200, {"status": "healthy"})))
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(scope="module")
def workshop(client) -> str:
    return client.get("/academy/labs/LAB-MCP-001").get_data(as_text=True)


def test_workshop_has_the_nine_steps_in_order(workshop):
    assert re.findall(r'data-step="(\w+)"', workshop) == STEPS
    assert re.findall(r'data-step-link="(\w+)"', workshop) == STEPS


@pytest.mark.parametrize("step", STEPS)
def test_each_step_explains_doing_why_action_evidence_and_learning(workshop, step):
    section = workshop.split(f'id="step-{step}"')[1].split("<!--")[0]
    assert re.findall(r"<dt>([^<]+)</dt>", section)[:5] == BRIEF
    assert f'id="h-{step}" tabindex="-1"' in section


def test_unknown_academy_lab_is_not_served(client):
    assert client.get("/academy/labs/LAB-PI-001").status_code != 200


def test_path_lists_every_curriculum_lab(client):
    html = client.get("/academy/path").get_data(as_text=True)
    for level in load_curriculum()["levels"]:
        for lab in level.get("labs") or []:
            assert lab["lab_id"] in html
    assert html.count("Not tracked here") >= 10
    assert "/academy/labs/LAB-MCP-001" in html


@pytest.mark.parametrize("path,label", [("/academy", "Home"), ("/academy/path", "Your Learning Path"), ("/academy/status", "System Status")])
def test_current_page_is_marked_in_navigation(client, path, label):
    html = client.get(path).get_data(as_text=True)
    assert re.search(rf'<a href="{re.escape(path)}" aria-current="page">{re.escape(label)}</a>', html)


@pytest.mark.parametrize("path", ["/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001"])
def test_pages_have_landmarks_skip_link_and_one_h1(client, path):
    html = client.get(path).get_data(as_text=True)
    assert '<html lang="en">' in html
    assert 'class="skip-link" href="#main"' in html
    assert '<main id="main"' in html
    assert html.count("<h1") == 1
    assert 'aria-label="Academy"' in html and 'aria-label="Breadcrumb"' in html


def test_menu_toggle_is_a_labelled_disclosure(client):
    html = client.get("/academy").get_data(as_text=True)
    assert re.search(r'<button class="menu-toggle" type="button" aria-expanded="false" aria-controls="primary-nav"', html)


def test_css_has_no_text_under_14px_and_keeps_focus_rings():
    css = CSS.read_text(encoding="utf-8")
    for value in re.findall(r"font-size:\s*([\d.]+)px", css):
        assert float(value) >= 14
    for value in re.findall(r"font-size:\s*([\d.]+)rem", css):
        assert float(value) >= 0.875
    assert ":focus-visible { outline: 3px solid var(--focus)" in css
    assert "outline: none" not in css.replace("main:focus { outline: none; }", "").replace('[tabindex="-1"]:focus { outline: none; }', "")


def test_css_breakpoints_use_em_so_zoom_reflows():
    css = CSS.read_text(encoding="utf-8")
    queries = re.findall(r"@media \(([^)]*width[^)]*)\)", css)
    assert queries and all(q.strip().endswith("em") for q in queries)


def test_dockerfile_ships_the_replay_packs_the_notebook_reads():
    dockerfile = (ROOT / "docker" / "Dockerfile.attack").read_text(encoding="utf-8")
    assert "COPY learning/level_1/LAB-MCP-001/specimens/ ./learning/level_1/LAB-MCP-001/specimens/" in dockerfile


def test_existing_learner_pages_link_to_the_academy(client):
    assert 'href="/academy"' in client.get("/").get_data(as_text=True)
    assert 'href="/academy/labs/LAB-MCP-001"' in client.get("/labs/LAB-MCP-001").get_data(as_text=True)
