"""Phase 12D in a real browser: the Governance Center. Headless Chromium on the local build only; the deployed app has not been browser-tested."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import watch  # noqa: E402
from tests.ui.test_study_browser import root as lab_root  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[2]
G = json.loads((ROOT / "academy-ui/src/content/governance/index.json").read_text(encoding="utf-8"))
VIEWS = ["", "/frameworks", "/threats", "/export"]


@pytest.fixture
def base(lab_root):
    return lab_root.replace("/lab/", "/governance")


def go(pg, base, path=""):
    pg.goto(base + path)
    pg.get_by_role("navigation", name="Governance Center").wait_for()
    pg.locator("h2").first.wait_for()


def text(pg):
    return pg.locator("main").inner_text()


def test_overview_states_what_is_not_shown_and_gives_denominators(page, base):
    seen = watch(page); go(page, base)
    t = text(page)
    assert "This is not a compliance assessment." in t and len(G["distinctions"]) == 8
    for d in G["distinctions"]:
        assert d["name"].lower() in t.lower()
    assert "2 of 9" in t and "0 of 14" in t and "linked evaluation evidence" in t
    for tid in G["gaps"]["unmapped_threats"]:
        assert tid in t
    assert "NIST AI RMF" in " ".join(G["gaps"]["frameworks_not_mapped"]) and not re.search(r"\d\s*%", t)
    assert seen == []


def test_tabs_navigate_and_mark_the_current_view(page, base):
    go(page, base)
    nav = page.get_by_role("navigation", name="Governance Center")
    for name, suffix in (("Frameworks", "/frameworks"), ("Threats and controls", "/threats"), ("Export", "/export"), ("Overview", "")):
        nav.get_by_role("link", name=name).click(); page.wait_for_url(re.compile(re.escape("/learn/governance" + suffix) + r"$"))
        assert nav.get_by_role("link", name=name).get_attribute("aria-current") == "page"
    assert page.get_by_role("navigation", name="Primary navigation").get_by_role("link", name="Governance Center").get_attribute("aria-current") == "page"
    page.goto(base + "/nope"); page.wait_for_selector("h1"); assert "That page does not exist" in text(page)


def test_frameworks_list_references_and_label_unverified_nist(page, base):
    go(page, base, "/frameworks")
    for f in G["frameworks"]:
        assert page.get_by_role("link", name=re.compile("^" + re.escape(f["name"]))).count() == 1
    page.get_by_role("link", name=re.compile("^MITRE ATLAS")).click()
    tbl = page.get_by_role("region", name=re.compile("^MITRE ATLAS references"))
    f = next(x for x in G["frameworks"] if x["name"] == "MITRE ATLAS")
    assert tbl.locator("tbody tr").count() == len(f["items"]) and "AML.T0053" in tbl.inner_text()
    assert "PROPOSED: TM-T04" in tbl.inner_text() and "None recorded" in tbl.inner_text()
    page.get_by_role("link", name=re.compile("^NIST AI RMF")).click()
    t = text(page)
    assert "No identifier is verified in this repository." in t and page.get_by_role("region", name=re.compile("references")).count() == 0
    assert "A reference being listed does not mean any control meets it." in t


def test_threats_filter_cards_links_and_control_register(page, base):
    go(page, base, "/threats")
    assert "Showing 9 of 9 threats." in text(page)
    page.get_by_label("With a framework relationship").check(); assert "Showing 2 of 9 threats." in text(page)
    page.get_by_label("With none recorded").check(); assert "Showing 7 of 9 threats." in text(page) and "NO FRAMEWORK RELATIONSHIP RECORDED" in text(page)
    page.get_by_label("All", exact=True).check()
    card = page.get_by_role("article").filter(has_text="TM-T04"); t = card.inner_text()
    assert "AI Agent Tool Invocation" in t and "PROPOSED" in t and "CTRL-MCP-001" in t and "recorded decision(s)" in t and "owner NOT ASSIGNED" in t
    assert card.get_by_role("link", name="Open TM-T04 in the Risk Center").get_attribute("href").endswith("/learn/risk/TM-T04")
    assert card.get_by_role("link").filter(has_text="MCP-").count() >= 1
    card.locator("summary", has_text="Gaps for this threat").click()
    reg = page.get_by_role("region", name=re.compile("^Control register"))
    assert reg.locator("tbody tr").count() == len(G["controls"]) == 14
    for c in reg.locator("tbody tr").all():
        r = c.inner_text()
        assert "NOT ASSIGNED" in r and "NOT REVIEWED" in r and "NONE RECORDED" in r and "NO ASSERTION" in r
    page.get_by_role("link", name="Open TM-T04 in the Risk Center").click(); page.wait_for_url(re.compile(r"/learn/risk/TM-T04$"))


def test_export_is_deterministic_and_asserts_nothing(page, base):
    go(page, base, "/export")
    def dl():
        with page.expect_download() as d: page.get_by_role("button", name="Download the export").click()
        return d.value.suggested_filename, Path(d.value.path()).read_text(encoding="utf-8")
    n1, md1 = dl(); n2, md2 = dl()
    assert n1 == "governance-export.md" and md1 == md2
    for h in ("## Framework relationships", "## Threats", "## Controls", "## Gaps", "## Sources"):
        assert h in md1
    assert "asserts no compliance" in md1 and "NO framework relationship recorded" in md1 and "attestation NONE RECORDED" in md1 and not re.search(r"\d\s*%", md1)
    for s in G["sources"]:
        assert s["sha256"] in md1
    page.get_by_label("JSON (structured)").check()
    n, js = dl(); j = json.loads(js)
    assert n == "governance-export.json" and j["schema"] == "agentsec.governance_export.v1" and len(j["relationships"]) == len(G["relationships"]) == 5 and len(j["controls"]) == 14
    assert [t["id"] for t in j["threats"] if not t["mapped"]] == G["gaps"]["unmapped_threats"] and all(c["owner"] == "NOT ASSIGNED" and c["compliance"] == "NO ASSERTION" for c in j["controls"])
    assert j["frameworks_not_verified"][0]["name"] == "NIST AI RMF" and not re.search(r"score|percent", js, re.I)


def test_loading_failed_chunk_keyboard_and_no_backend(page, base):
    reqs = []
    page.on("request", lambda r: reqs.append((r.method, r.url)))
    page.goto(base.replace("/governance", "")); page.wait_for_selector("h1")
    assert not any("Governance" in u for _, u in reqs)
    seen = watch(page)
    for p in VIEWS: go(page, base, p)
    assert all(m == "GET" for m, _ in reqs) and seen == []
    nav = page.get_by_role("navigation", name="Governance Center")
    nav.get_by_role("link", name="Threats and controls").focus(); page.keyboard.press("Enter"); page.wait_for_url(re.compile(r"/threats$"))
    r = page.get_by_label("With none recorded"); r.focus(); page.keyboard.press("Space"); assert r.is_checked()


@pytest.mark.parametrize("path", VIEWS + ["/frameworks#x"])
def test_390px_layout_has_no_sideways_page_scroll(browser, base, path):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    go(pg, base, path.replace("#x", ""))
    for sm in pg.locator("main summary").all()[:6]: sm.click()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), path
    for r in pg.locator("main [role=region][tabindex='0']").all()[:2]:
        r.focus(); assert r.evaluate("e => e === document.activeElement")
    ctx.close()


def test_existing_navigation_is_unchanged(page, base):
    page.goto(base.replace("/governance", "")); page.wait_for_selector("h1")
    nav = page.get_by_role("navigation", name="Primary navigation")
    for n in ("Home", "Your Path", "Curriculum Explorer", "AI & Agent Foundations", "Loan Desk Mission", "MCP Tool Authorization", "Mastery", "Security Assurance", "EVAL Center", "Risk Center", "Governance Center"):
        assert nav.get_by_role("link", name=n).count() == 1, n
