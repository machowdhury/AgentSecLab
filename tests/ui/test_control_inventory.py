"""Structural control inventory: no decorative controls, no dead links, every visible control named.

Runs the crawler against the Attack Service with an unreachable AcmeBank (nothing can launch a LIVE run).
SKIPPED, not passed, when Playwright or a Chromium is unavailable. Set AGENTSEC_CHROMIUM to a Chrome path.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _chromium() -> str | None:
    env = os.environ.get("AGENTSEC_CHROMIUM")
    if env and Path(env).is_file():
        return env
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            default = pw.chromium.executable_path
        return default if Path(default).is_file() else None
    except Exception:  # noqa: BLE001
        return None


@pytest.fixture(scope="module")
def rows():
    chromium = _chromium()
    if not chromium:
        pytest.skip("Playwright/Chromium not available (set AGENTSEC_CHROMIUM)")
    spec = importlib.util.spec_from_file_location("ui_control_inventory", ROOT / "scripts/ui_control_inventory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.collect(chromium), mod.PAGES


def test_inventory_covers_every_page_and_finds_controls(rows):
    data, pages = rows
    assert {r["page"] for r in data} == set(pages)
    assert len(data) >= 300  # 396 when this guard was added


def test_no_decorative_buttons_or_dead_links(rows):
    data, _ = rows
    bad = [(r["page"], r["tag"], r["id"] or r["href"] or r["name"], r["class"], r["why"])
           for r in data if r["class"] in ("NO_HANDLER", "BROKEN_LINK")]
    assert not bad, bad


def test_every_visible_control_has_an_accessible_name(rows):
    data, _ = rows
    assert not [(r["page"], r["tag"], r["id"], r["href"]) for r in data if r["visible"] and r["unnamed"]]


def test_the_shared_shell_is_on_every_page(rows):
    data, pages = rows
    for page in pages:
        names = {r["name"] for r in data if r["page"] == page}
        assert {"Academy", "Attack Service"} <= names, page
