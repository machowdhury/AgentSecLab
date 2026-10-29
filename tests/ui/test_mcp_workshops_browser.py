"""LAB-MCP-003/004/005/006/CATALOG launched from the Academy in a real browser: gating, BASELINE / ATTACK / RETEST read from real records, the finish guide,
and the CTF Challenges page. AcmeBank and the Attack Service run in this process; no model is involved. SKIPPED without Playwright and a Chromium (AGENTSEC_CHROMIUM)."""
from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_rag_workbench_browser import launches, tab  # noqa: E402
from tests.ui.test_scenario_workbench_browser import main, url  # noqa: E402,F401

CASES = {
    "LAB-MCP-003": dict(baseline="GRANTED REQUEST RAN", rows={"Decision (CTRL-MCP-001)": ("ALLOW", "DENY"), "Reason": ("vulnerable_profile_fail_open", "scope_not_granted"), "Handler ran": ("true", "false")}),
    "LAB-MCP-004": dict(baseline="GRANTED REQUEST RAN", rows={"Decision (CTRL-MCP-001)": ("ALLOW", "DENY"), "Reason": ("vulnerable_profile_fail_open", "resource_not_granted"), "Handler ran": ("true", "false")}),
    "LAB-MCP-005": dict(baseline="GRANTED REQUEST RAN, NO FOLLOW-ON", rows={"Decisive tool": ("lookup_customer_tier", "lookup_customer_tier"), "Decision (CTRL-MCP-001)": ("ALLOW", "DENY"), "Reason": ("result_derived_grant", "tool_not_granted"), "Handler ran": ("true", "false")}),
    "LAB-MCP-CATALOG": dict(baseline="GRANTED REQUEST RAN, NO FOLLOW-ON", rows={"Decisive tool": ("lookup_customer_tier", "lookup_customer_tier"), "Decision (CTRL-MCP-001)": ("ALLOW", "DENY"), "Reason": ("metadata_derived_authority", "tool_not_granted"), "Handler ran": ("true", "false")}),
    "LAB-MCP-006": dict(baseline="GRANTED REQUEST RAN", rows={"Decisive tool": ("lookup_customer_tier", "lookup_customer_tier"), "Decision (CTRL-DELEGATION-001)": ("ALLOW", "DENY"), "Reason": ("ambient_deputy_authority", "delegated_authority_not_granted"), "Handler ran": ("true", "false")}),
}
ATTACK, RETEST = "ALLOWED BY THE LABELLED FAIL-OPEN SETTING", "DENIED, HANDLER DID NOT RUN"


def lock(pg, lab):
    for key, opt in (("decision", "ALLOW"), ("handler", "will run")):
        pg.locator(f"input[name='{lab}-{key}']").locator("xpath=following-sibling::span").filter(has_text=re.compile(f"^{opt}")).click()
    pg.get_by_role("button", name="Lock prediction").click()


@pytest.mark.parametrize("lab", sorted(CASES))
def test_baseline_attack_retest_read_the_real_records(page, url, lab):
    c, sent = CASES[lab], launches(page)
    page.goto(url(lab)); tab(page, "Practice")
    attack, retest = page.get_by_role("button", name=re.compile("Launch ATTACK")), page.get_by_role("button", name=re.compile("Run RETEST"))
    assert attack.is_disabled() and retest.is_disabled() and sent == [], "opening the page launches nothing and the attack needs a locked prediction"
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector(f"text={c['baseline']}")
    assert attack.is_disabled(), "a baseline does not unlock the attack"
    lock(page, lab)
    attack.dblclick()
    page.wait_for_selector(f"text={ATTACK}")
    assert len([s for s in sent if "ATTACK" in s]) == 1, "a double click sends one launch"
    retest.click()
    page.wait_for_selector(f"text={RETEST}")
    assert len(sent) == 3
    cmp_ = page.locator("table", has_text="ATTACK (live)")
    for fact, (x, y) in c["rows"].items():
        cells = cmp_.locator("tr", has_text=fact).first.locator("td").all_inner_texts()
        assert x in cells[1] and y in cells[2], (fact, cells)
    body = main(page)
    assert "no signed verifier" in body and not re.search(r"SPLUNK[- ]VERIFIED|independently verified: yes", body, re.I)
    assert "no model was involved" in body.lower() or "calls no language model" in body.lower()


@pytest.mark.parametrize("lab", sorted(CASES))
def test_the_finish_guide_is_on_the_learn_tab(page, url, lab):
    page.goto(url(lab))
    text = main(page)
    for needle in ("What you should see", "What the defense teaches", "You are done when", "If something does not look right"):
        assert needle in text, needle
    assert "VERIFICATION UNAVAILABLE" in text and "WAITING_FOR_EVIDENCE" in text


def test_the_ctf_challenges_page_lists_the_three_challenges_from_the_service(page, url):
    page.goto(url("LAB-MCP-003").replace("/learn/lab/LAB-MCP-003", "/learn/challenges"))
    page.wait_for_selector("text=Loan Desk Note Smuggler")
    text = main(page)
    for title in ("Loan Desk Note Smuggler", "Poisoned Catalog", "Confused Deputy Relay"):
        assert title in text
    assert "not multi-user" in text.lower() and "SIMULATED" in text
    assert page.locator("a", has_text="Open this challenge").count() == 3, "the page is on a loopback host, so the CTF answers and links resolve"
