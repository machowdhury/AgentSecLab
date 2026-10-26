"""Workshop path bar in a real browser (headless Chromium, local build only; the deployed app has not been browser-tested)."""
from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_study_browser import root as lab_root  # noqa: E402,F401

ORDER = ["Learn", "Attack", "Investigate", "EVAL", "Risk", "Governance"]


@pytest.fixture
def base(lab_root):
    return lab_root.replace("/lab/", "")


@pytest.mark.parametrize("path,current", [("/governance", "Governance"), ("/risk", "Risk"), ("/evals", "EVAL"),
                                           ("/loan-desk/attack", "Attack"), ("/loan-desk/investigate", "Investigate"),
                                           ("/lab/LAB-MCP-003", "Learn")])
def test_path_bar_lists_the_steps_in_order_and_marks_the_current_one(page, base, path, current):
    page.goto(base + path)
    nav = page.get_by_role("navigation", name="Workshop path")
    nav.wait_for()
    assert nav.get_by_role("link").all_inner_texts() == ORDER
    if "/loan-desk" in page.url:  # the mission gates later stages and may redirect; judge by the stage actually shown
        stage = page.url.rstrip("/").rsplit("/", 1)[-1]
        current = {"attack": "Attack", "investigate": "Investigate", "defend": "Investigate", "retest": "Investigate", "explain": "Investigate"}.get(stage, "Learn")
    assert [t for t in ORDER if nav.get_by_role("link", name=t).get_attribute("aria-current") == "step"] == [current]


def test_path_bar_links_navigate_without_a_reload(page, base):
    page.goto(base + "/governance")
    page.get_by_role("navigation", name="Workshop path").get_by_role("link", name="Risk").click()
    page.wait_for_url("**/learn/risk")
    assert page.get_by_role("navigation", name="Workshop path").get_by_role("link", name="Risk").get_attribute("aria-current") == "step"


def test_path_bar_is_absent_on_home(page, base):
    page.goto(base)
    page.locator("h1").first.wait_for()
    assert page.get_by_role("navigation", name="Workshop path").count() == 0
