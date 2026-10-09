"""P1.5 genuine Chrome zoom via chrome.tabs.setZoom. Viewport resize is not this test.

If the MV3 helper cannot apply chrome.tabs.setZoom, the tests skip. That is
UNTESTED, not PASS.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "tests" / "support" / "chrome_zoom_extension"
PAGES = (
    "/academy",
    "/academy/foundations",
    "/academy/path",
    "/academy/status",
    "/academy/labs/LAB-MCP-001",
)
FACTORS = (1.0, 2.0, 4.0)


def _healthy(_path):
    return 200, {"status": "healthy", "security.profile": "defended", "ollama_reachable": False, "ollama_model": "llama3.2:1b"}


@pytest.fixture(scope="module")
def base_url(tmp_path_factory):
    app = create_app(
        AcmeBankClient("http://acmebank.example:5000", get_fn=_healthy),
        launch_kwargs={"artifacts_dir": tmp_path_factory.mktemp("artifacts")},
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def zoom_context(tmp_path_factory):
    user_data = tmp_path_factory.mktemp("chrome-zoom-profile")
    with sync_api.sync_playwright() as pw:
        try:
            context = pw.chromium.launch_persistent_context(
                str(user_data),
                headless=False,
                args=[
                    f"--disable-extensions-except={EXT}",
                    f"--load-extension={EXT}",
                    "--no-first-run",
                ],
                viewport={"width": 1440, "height": 900},
            )
        except Exception as exc:
            pytest.skip(f"Chromium with extension unavailable: {exc}")
        yield context
        context.close()


def _set_zoom(context, page, factor: float) -> float:
    workers = [w for w in context.service_workers if "chrome-extension://" in w.url]
    if not workers:
        pytest.skip("chrome.tabs.setZoom helper did not register a service worker (genuine zoom UNTESTED)")
    worker = workers[0]
    page.bring_to_front()
    result = worker.evaluate(
        """async (factor) => {
          const tabs = await chrome.tabs.query({ lastFocusedWindow: true });
          const tab = tabs.find((row) => row.active) || tabs[0];
          if (!tab || tab.id == null) return { ok: false, error: "no_tab" };
          await chrome.tabs.setZoom(tab.id, factor);
          const actual = await chrome.tabs.getZoom(tab.id);
          return { ok: true, factor: actual };
        }""",
        factor,
    )
    if not result or not result.get("ok"):
        pytest.skip(f"chrome.tabs.setZoom failed: {result} (genuine zoom UNTESTED)")
    actual = float(result["factor"])
    if abs(actual - factor) > 0.05:
        pytest.skip(f"chrome.tabs.setZoom reported {actual}, not {factor} (genuine zoom UNTESTED)")
    return actual


def _overflow(page) -> int:
    return page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize("factor", FACTORS)
def test_genuine_chrome_zoom_keeps_pages_usable(zoom_context, base_url, path, factor):
    page = zoom_context.pages[0] if zoom_context.pages else zoom_context.new_page()
    page.goto(base_url + path, wait_until="networkidle")
    actual = _set_zoom(zoom_context, page, factor)
    page.wait_for_timeout(250)
    assert page.locator("h1").count() == 1
    assert page.locator("main#main").count() == 1
    assert page.locator("a.skip-link").count() == 1
    heading = page.locator("h1")
    assert heading.is_visible()
    overflow = _overflow(page)
    # Ordinary content must not require horizontal scrolling. Two-dimensional
    # tables may; they live inside .table-wrap with an accessible alternative.
    if path != "/academy/labs/LAB-MCP-001":
        assert overflow <= 24, f"{path} at {actual:.0%} overflow={overflow}"
    page.keyboard.press("Tab")
    focused = page.evaluate("document.activeElement && document.activeElement.tagName")
    assert focused


def test_workshop_zoom_keeps_stepper_and_notebook_reachable(zoom_context, base_url):
    page = zoom_context.pages[0] if zoom_context.pages else zoom_context.new_page()
    page.goto(base_url + "/academy/labs/LAB-MCP-001", wait_until="networkidle")
    page.wait_for_timeout(400)
    actual = _set_zoom(zoom_context, page, 4.0)
    assert actual == pytest.approx(4.0, abs=0.05)
    assert page.locator("[data-step-link]").count() == 9
    page.locator('[data-step-link="start"]').click()
    assert page.locator('#h-start').is_visible()
    page.locator('[data-step-link="predict"]').click()
    page.locator('input[name="predict-control"][value="UNSURE"]').click(force=True)
    page.locator('input[name="predict-execution"][value="UNSURE"]').click(force=True)
    page.locator("[data-lock-prediction]").click()
    page.locator('[data-use-replay="ATTACK"]').click()
    page.wait_for_timeout(500)
    assert page.locator('[data-run-card="ATTACK"]').is_visible()
    page.locator('[data-step-link="investigate"]').click()
    assert page.locator("[data-notebook-body], [data-notebook-empty]").count() >= 1
