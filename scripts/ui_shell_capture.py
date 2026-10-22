#!/usr/bin/env python3
"""Screenshot and axe-core scan of the learner pages at desktop and phone widths.

Serves the Attack Service in-process against an UNREACHABLE AcmeBank. Viewport widths emulate a
narrow screen; they are NOT genuine browser zoom or a real device. Needs playwright,
axe-playwright-python and a Chromium executable.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from ui_control_inventory import PAGES  # noqa: E402

VIEWPORTS = {"desktop": (1280, 900), "phone": (390, 844)}


def capture(chromium: str, out: Path, pages: list[str]) -> list[dict]:
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import sync_playwright

    out.mkdir(parents=True, exist_ok=True)
    app = create_app(AcmeBankClient("http://127.0.0.1:9"))
    app.config["TESTING"] = True
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    report = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium, headless=True)
        for vp, (w, h) in VIEWPORTS.items():
            ctx = browser.new_context(viewport={"width": w, "height": h})
            for path in pages:
                page = ctx.new_page()
                page.goto(origin + path, wait_until="load")
                page.wait_for_timeout(500)
                slug = (path.strip("/") or "attack-home").replace("/", "_")
                page.screenshot(path=str(out / f"{slug}__{vp}.png"), full_page=False)
                res = Axe().run(page)
                violations = [{"id": v["id"], "impact": v["impact"], "nodes": len(v["nodes"]), "help": v["help"]}
                              for v in res.response["violations"]]
                overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
                report.append({"page": path, "viewport": vp, "size": [w, h], "violations": violations, "horizontal_overflow": overflow})
                page.close()
            ctx.close()
        browser.close()
    server.shutdown()
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chromium", required=True)
    ap.add_argument("--out", required=True, help="directory for PNGs and axe.json")
    ap.add_argument("--pages", nargs="*", default=PAGES)
    args = ap.parse_args()
    out = Path(args.out)
    report = capture(args.chromium, out, args.pages)
    (out / "axe.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    serious = [r for r in report for v in r["violations"] if v["impact"] in ("serious", "critical")]
    print(f"pages x viewports: {len(report)}; with serious/critical violations: {len(serious)}; horizontal overflow: {sum(r['horizontal_overflow'] for r in report)}")
    for r in report:
        for v in r["violations"]:
            print(f"  {r['viewport']:7} {r['page']:38} {v['impact']:9} {v['id']} x{v['nodes']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
