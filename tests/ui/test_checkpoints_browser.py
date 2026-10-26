"""Increment 11D in a real browser: the nine simulated or documented checkpoints, each exercised on its own.

The packet loads on demand, nothing is launched and no lab API is called. SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402
from tests.test_checkpoints import ALL, DIFFS, EXPECTED, INVENTORY, INVENTORY_ANSWERS, MODES  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import tab, watch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "academy-ui/src/content/recorded"
MODE_LABS = [f"LAB-{m}" for m in MODES]
ORDER = ("BASELINE", "ATTACK", "RETEST")
LEARN_HEADINGS = ("the legitimate workflow", "the threat", "the trust boundary", "the security control", "what the evidence can and cannot show")


def data(lab):
    return json.loads((FILES / f"{lab}.json").read_text(encoding="utf-8"))


@pytest.fixture
def root(settings):
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{attack.server_port}/learn/lab/"
    for s in (bank, attack):
        s.shutdown()


def case(pg, mode):
    pg.locator(".rec-runs .rec-run", has_text=re.compile(f"^{mode}")).click()


def wrong(options, right):
    return next(o for o in options if o != right)


@pytest.mark.parametrize("lab", ALL)
def test_learn_covers_workflow_threat_boundary_control_and_limits_and_loads_no_packet(page, root, lab):
    seen, loaded = watch(page), []
    page.on("request", lambda r: loaded.append(r.url) if "/assets/LAB-" in r.url else None)
    page.goto(root + lab)
    text = page.locator("main, .page").first.inner_text().lower()
    for h in LEARN_HEADINGS:
        assert h in text, (lab, h)
    assert page.get_by_text("Full guided lesson not yet available").count() == 0
    assert "replay" in text or "content only" in text
    assert loaded == [] and seen == []
    tab(page, "Practice")
    page.get_by_test_id("checkpoint-workbench").wait_for()
    assert any(lab in u for u in loaded), "the packet loads when Practice opens"
    assert seen == []


@pytest.mark.parametrize("lab", MODE_LABS)
def test_predict_reveal_diff_compare_and_prove_use_only_the_packet(page, root, lab):
    d = data(lab); spec = d["spec"]; packet = d["packet"]; seen = watch(page)
    page.goto(root + lab); tab(page, "Practice")
    wb = page.get_by_test_id("checkpoint-workbench")
    assert "NOT A LIVE RUN" in wb.inner_text() and packet["evidence_classification"] in wb.inner_text()
    by = {m["mode"]: m for m in packet["modes"]}
    for mode in ORDER:                                               # a fresh page per case: nothing the packet reveals later may be on screen before the reveal
        page.goto(root + lab); tab(page, "Practice")
        case(page, mode)
        before = wb.inner_text()
        for f in spec["outcome"]:
            v = by[mode].get(f["field"])
            if isinstance(v, str) and len(v) > 12 and v not in [by[mode].get(s["field"]) for s in spec["setup"]] + [packet.get(k) for k in packet if isinstance(packet.get(k), str)] + [o for pr in spec["predictions"] for o in pr["options"]]:
                assert v not in before, (lab, mode, f["field"])
    page.goto(root + lab); tab(page, "Practice")
    for mode in ORDER:
        case(page, mode)
        for p in spec["predictions"]:
            right = EXPECTED[lab][p["id"]][mode]
            page.locator(f"input[name='{mode}-{p['id']}'][value='{wrong(p['options'], right)}']").check()
        page.get_by_role("button", name="Reveal the packet's record").click()
        r = wb.locator(".rec-predict .rec-reveal").text_content()
        assert r.count("did not match") == len(spec["predictions"]) and "your prediction matched" not in r
        for f in spec["outcome"]:
            v = by[mode].get(f["field"])
            assert (str(v) in r) if v is not None else ("not recorded in this record" in r), (lab, mode, f["field"])
    for i, (a, b) in enumerate((("BASELINE", "ATTACK"), ("ATTACK", "RETEST"))):
        fs = wb.locator("fieldset", has_text=f"{a} compared with {b}")
        if i == 0:
            for f in spec["diff"]:
                if f["field"] in DIFFS[lab]:
                    fs.get_by_label(f["label"], exact=True).check()
        fs.get_by_role("button", name="Check against the packet").click()
        out = fs.locator(".rec-reveal").inner_text()
        assert "that matches" in out
        assert ("no difference" in out) == (i == 1)
    t = wb.get_by_role("region", name=re.compile("^Comparison of the revealed cases"))
    assert "(differs)" in t.text_content() and all(m in t.text_content() for m in ORDER)
    assert seen == [], "no launch and no lab API call"


@pytest.mark.parametrize("lab", MODE_LABS)
def test_prove_shows_decisive_fields_provenance_and_no_live_or_verified_claim(page, root, lab):
    d = data(lab); packet = d["packet"]
    page.goto(root + lab); tab(page, "Prove")
    p = page.get_by_test_id("checkpoint-prove"); text = p.text_content()
    assert "NOT A LIVE RUN" in text and "Verification status: not verified here" in text and "makes no claim" in text
    assert "SPLUNK-VERIFIED" not in text
    rows = p.get_by_role("region", name=re.compile("^Decisive fields")).locator("tbody tr")
    assert rows.count() == 3
    for m in packet["modes"]:
        row = [r for r in rows.all() if r.locator("th").text_content() == m["mode"]][0]
        for dcs in d["spec"]["decisive"]:
            assert str(m.get(dcs["field"], "not recorded in this record")) in row.text_content(), (lab, m["mode"], dcs["field"])
    for f in d["spec"]["packet_facts"]:
        v = packet
        for k in f["path"].split("."):
            v = v[k]
        assert (json.dumps(v) if not isinstance(v, str) else v) in text
    p.locator("summary", has_text="Provenance of the packet").click()
    assert d["sha256"] in p.text_content() and packet["packet_id"] in p.text_content() and d["packet_file"] in p.text_content()
    for q in d["spl"]:
        assert p.locator("summary code", has_text=q["name"]).count() == 1
    assert page.get_by_text("cannot", exact=False).count() >= 1


def test_asset_inventory_questions_are_computed_from_the_documented_list(page, root):
    d = data(INVENTORY); seen = watch(page)
    page.goto(root + INVENTORY); tab(page, "Practice")
    wb = page.get_by_test_id("checkpoint-workbench")
    assert "DOCUMENTED — NOT A LIVE RUN" in wb.inner_text()
    assert wb.locator("tbody tr").count() == len(d["packet"]["components"])
    for q in d["spec"]["questions"]:
        li = wb.locator(".rec-q", has_text=q["prompt"])
        want = INVENTORY_ANSWERS[q["id"]]
        names = [c["name"] for c in d["packet"]["components"]]
        if q["id"] == "i1":
            for n in names:
                if n in want:
                    li.get_by_label(n, exact=True).check()
            li.get_by_role("button", name="Check against the packet").click()
            assert "that matches" in li.locator(".rec-reveal").inner_text()
        else:
            li.get_by_label(next(n for n in names if n not in want), exact=True).check()
            li.get_by_role("button", name="Check against the packet").click()
            r = li.locator(".rec-reveal").inner_text()
            assert "does not match" in r and all(w in r for w in want) and q["quote"]["text"] in r
    assert seen == []
    tab(page, "Prove")
    p = page.get_by_test_id("checkpoint-prove"); text = p.text_content()
    assert "documented component list" in text.lower() and "AI-BOM" in text and d["packet"]["cisco_aibom_compatibility"] in text
    for q in d["spec"]["questions"]:
        assert all(w in text for w in INVENTORY_ANSWERS[q["id"]])


def test_neighbouring_experiences_are_unchanged(page, root):
    page.goto(root + "LAB-MCP-004"); tab(page, "Practice")
    assert page.get_by_test_id("recorded-workbench").count() == 1
    page.goto(root + "LAB-BLUE-TEAM-INCIDENT-001"); tab(page, "Practice")
    page.get_by_test_id("investigation-workbench").wait_for()


@pytest.mark.parametrize("lab", ALL)
def test_keyboard_and_390px_layout(browser, root, lab):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    ok = "document.documentElement.scrollWidth <= window.innerWidth + 1"
    pg.goto(root + lab); assert pg.evaluate(ok), "learn"
    tab(pg, "Practice"); wb = pg.get_by_test_id("checkpoint-workbench"); wb.wait_for()
    assert pg.evaluate(ok), "practice"
    if lab == INVENTORY:
        region = wb.get_by_role("region", name=re.compile("^The documented components"))
        first = wb.locator(".rec-q").first
        first.locator("input[type=checkbox]").first.focus(); pg.keyboard.press("Space")
        assert first.locator("input[type=checkbox]").first.is_checked()
        first.get_by_role("button", name="Check against the packet").focus(); pg.keyboard.press("Enter")
        assert first.locator(".rec-reveal").count() == 1
    else:
        wb.get_by_role("button", name="Skip the predictions and show the record").click()
        case(pg, "ATTACK"); wb.get_by_role("button", name="Skip the predictions and show the record").click()
        region = wb.get_by_role("region", name=re.compile("^Comparison of the revealed cases"))
        radios = wb.locator("fieldset input[type=radio]")
        case(pg, "RETEST")
        radios.first.focus(); pg.keyboard.press("Space"); assert radios.first.is_checked(), "radios work from the keyboard"
        btn = wb.get_by_role("button", name="Check against the packet").first
        btn.focus(); pg.keyboard.press("Enter")
        assert wb.locator(".rec-reveal").count() >= 1
    assert pg.evaluate(ok), "after interaction"
    region.focus(); assert region.evaluate("e => e === document.activeElement"), "sideways-scrolling regions are keyboard-focusable"
    tab(pg, "Prove"); pg.get_by_test_id("checkpoint-prove").locator("summary").first.click()
    assert pg.evaluate(ok), "prove"
    ctx.close()
