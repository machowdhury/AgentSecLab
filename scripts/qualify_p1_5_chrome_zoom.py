#!/usr/bin/env python3
"""Record genuine Chrome zoom evidence against the live Academy.

Uses chrome.tabs.setZoom via tests/support/chrome_zoom_extension. A resized
viewport is not recorded as zoom. If the helper cannot set zoom, this script
exits 2 (UNTESTED) rather than reporting PASS.
"""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "tests" / "support" / "chrome_zoom_extension"
OUT = ROOT / "docs" / "reviews" / "p1.5-academy-closeout-evidence" / "chrome-zoom"
ACADEMY = "http://127.0.0.1:5001"
PAGES = (
    ("home", "/academy"),
    ("foundations", "/academy/foundations"),
    ("path", "/academy/path"),
    ("status", "/academy/status"),
    ("workshop", "/academy/labs/LAB-MCP-001"),
)
FACTORS = (("100", 1.0), ("200", 2.0), ("400", 4.0))


def set_zoom(context, page, factor: float) -> dict:
    workers = [w for w in context.service_workers if "chrome-extension://" in w.url]
    if not workers:
        return {"ok": False, "error": "no_service_worker"}
    page.bring_to_front()
    return workers[0].evaluate(
        """async (factor) => {
          const tabs = await chrome.tabs.query({ lastFocusedWindow: true });
          const tab = tabs.find((row) => row.active) || tabs[0];
          if (!tab || tab.id == null) return { ok: false, error: "no_tab" };
          await chrome.tabs.setZoom(tab.id, factor);
          const actual = await chrome.tabs.getZoom(tab.id);
          return { ok: true, factor: actual, tabId: tab.id };
        }""",
        factor,
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    results = {
        "queried_at_utc": datetime.now(timezone.utc).isoformat(),
        "os": f"{platform.system()} {platform.release()}",
        "method": "chrome.tabs.setZoom",
        "academy": ACADEMY,
        "pages": [],
        "verdict": "UNTESTED",
    }
    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            str(Path("/tmp/agentsec-p15-chrome-zoom-profile")),
            headless=False,
            args=[
                f"--disable-extensions-except={EXT}",
                f"--load-extension={EXT}",
                "--no-first-run",
            ],
            viewport={"width": 1440, "height": 900},
        )
        page = context.pages[0] if context.pages else context.new_page()
        version = context.browser.version if context.browser else "unknown"
        results["browser"] = f"Chromium {version}"
        results["viewport"] = {"width": 1440, "height": 900}
        for key, path in PAGES:
            page.goto(ACADEMY + path, wait_until="networkidle", timeout=30000)
            for label, factor in FACTORS:
                applied = set_zoom(context, page, factor)
                if not applied.get("ok"):
                    results["verdict"] = "UNTESTED"
                    results["error"] = applied
                    (OUT / "zoom_results.json").write_text(json.dumps(results, indent=2) + "\n")
                    context.close()
                    print(json.dumps(results, indent=2))
                    return 2
                page.wait_for_timeout(300)
                overflow = page.evaluate(
                    "document.documentElement.scrollWidth - document.documentElement.clientWidth"
                )
                h1 = page.locator("h1").inner_text()
                shot = OUT / f"{key}_{label}.png"
                page.screenshot(path=str(shot), full_page=True)
                results["pages"].append(
                    {
                        "page": key,
                        "path": path,
                        "requested_zoom": factor,
                        "actual_zoom": applied.get("factor"),
                        "h1": h1,
                        "horizontal_overflow_px": overflow,
                        "screenshot": str(shot.relative_to(ROOT)),
                    }
                )
        context.close()
    results["verdict"] = "MEASURED"
    (OUT / "zoom_results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"verdict": results["verdict"], "n": len(results["pages"]), "browser": results.get("browser")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
