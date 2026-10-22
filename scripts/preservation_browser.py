#!/usr/bin/env python3
"""Drive the original learner surfaces in a real browser against one served tree and record what happens.
  attack-ui --base URL --out FILE    Attack UI, Academy and workshop pages: structure, console, a11y, and every launch button
  splunk-views --splunk URL --out F  every Studio view named in lab_registry_data.json, rendered in Splunk Web (needs the lab admin password from the Splunk container's env; never printed)
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
MASK = [(re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"), (re.compile(r"\b[0-9a-f]{16,64}\b"), "<id>"),
        (re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?"), "<ts>"), (re.compile(r"\b\d+(\.\d+)?\s?(ms|s)\b"), "<dur>"), (re.compile(r"Version \d+\.\d+\.\d+"), "Version X"), (re.compile(r"127\.0\.0\.1:1[0-9]{4}"), "HOST:PORT")]
LIVE = ["LAB-PI-001", "LAB-MCP-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-AGENTSEC-CAPSTONE-001"]


def norm(t: str) -> str:
    t = " ".join(t.split())
    for rx, rep in MASK:
        t = rx.sub(rep, t)
    return t


def axe(page):
    try:
        from axe_playwright_python.sync_playwright import Axe
        return sorted((v["id"], v["impact"], len(v["nodes"])) for v in Axe().run(page).response["violations"])
    except ImportError:
        return "axe unavailable"


def visit(page, url, log):
    log["console"].clear(); log["bad"].clear()
    resp = page.goto(url, wait_until="load")
    page.wait_for_timeout(600)
    rec = {"status": resp.status if resp else None, "title": page.title(),
           "headings": page.eval_on_selector_all("h1,h2,h3", "els => els.map(e => e.tagName + ':' + e.textContent.trim().replace(/\\s+/g,' '))"),
           "controls": page.evaluate("() => ({buttons: document.querySelectorAll('button').length, inputs: document.querySelectorAll('input,select,textarea').length, links: document.querySelectorAll('a[href]').length})"),
           "axe": axe(page)}
    rec["console_errors"], rec["bad_responses"] = list(log["console"]), list(log["bad"])
    return rec


def attack_ui(base, out):
    res = {"base": base, "pages": {}, "launch_ui": {}}
    exe = os.environ.get("AGENTSEC_CHROMIUM")
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=exe)
        page = b.new_page(viewport={"width": 1280, "height": 900})
        log = {"console": [], "bad": []}
        page.on("console", lambda m: log["console"].append(m.text[:160]) if m.type == "error" else None)
        page.on("response", lambda r: log["bad"].append(f"{r.status} {r.url.split('?')[0][-60:]}") if r.status >= 400 else None)
        urls = ["/", "/acmebank", "/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001"] + [f"/labs/{l}" for l in LIVE]
        for u in urls:
            res["pages"][u] = visit(page, base + u, log)
        # exercise the launch controls of every LIVE lab exactly as a learner would, recording what each click leads to
        def click(page, sel, label, steps, wait=2500):
            loc = page.locator(sel).first
            if loc.count() == 0:
                steps.append({"step": label, "present": False}); return False
            if not loc.is_enabled() or not loc.is_visible():
                steps.append({"step": label, "present": True, "enabled": False}); return False
            try:
                loc.click(timeout=3000)
            except Exception as exc:  # noqa: BLE001 - recorded, and compared across trees
                steps.append({"step": label, "present": True, "enabled": True, "click_failed": type(exc).__name__}); return False
            page.wait_for_timeout(wait)
            steps.append({"step": label, "present": True, "enabled": True, "after": norm(page.inner_text("body"))[:5000]})
            return True

        def pick_prediction(page):
            # answer every visible radio group by clicking the first option's label (inputs are visually hidden)
            for grp in page.eval_on_selector_all("input[type=radio]", "els => [...new Set(els.filter(e => e.closest('label') && e.closest('label').offsetParent !== null).map(e => e.name))]"):
                try:
                    page.locator(f"label:has(input[name='{grp}'])").first.click(timeout=2000)
                except Exception:  # noqa: BLE001 - a group that is not on this step is not part of it
                    pass

        flows = {
            "/": [("BASELINE", "#fire-baseline"), ("ATTACK", "#fire-attack"), ("RETEST", "#fire-retest")],
            "/labs/LAB-PI-001": [("BASELINE", "#fire-baseline"), ("ATTACK", "#fire-attack"), ("RETEST", "#fire-retest")],
            "/labs/LAB-MCP-001": [("start", "#start-lab"), ("explore baseline", "#explore-baseline"), ("continue", "#baseline-continue"),
                                  ("PREDICT", "#record-prediction"), ("ATTACK", "#fire-attack"), ("continue", "#investigate-continue"), ("goto retest", "#goto-retest"), ("RETEST", "#fire-retest"),
                                  ("compare", "#goto-compare"), ("explain", "#goto-explain")],
        }
        for lab in ("LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-AGENTSEC-CAPSTONE-001"):
            flows[f"/labs/{lab}"] = [("ATTACK", "#attack-button"), ("RETEST", "#retest-button")]
        flows["/academy/labs/LAB-MCP-001"] = [("to baseline", "button:has-text('Continue to Baseline')"), ("recorded baseline", "button:has-text('Load the recorded baseline')"),
                                              ("to predict", "button:has-text('Continue to Predict')"), ("PREDICT", "button:has-text('Lock prediction and continue')"),
                                              ("LIVE ATTACK", "button[data-mode='ATTACK']"), ("to investigate", "button:has-text('Continue to Investigate')"),
                                              ("to defend", "button:has-text('Continue to Defend')"), ("to retest", "button:has-text('Continue to Retest')"),
                                              ("LIVE RETEST", "button[data-mode='RETEST']"), ("to compare", "button:has-text('Continue to Compare')"),
                                              ("to explain", "button:has-text('Continue to Explain')"), ("complete", "button:has-text('Mark workflow complete')")]
        for u, flow in flows.items():
            page.goto(base + u, wait_until="load")
            page.wait_for_timeout(500)
            steps = []
            for label, sel in flow:
                if label == "PREDICT":
                    pick_prediction(page)
                click(page, sel, label, steps)
            res["launch_ui"][u] = steps
        b.close()
    Path(out).write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    print("attack-ui walked", len(res["pages"]), "pages,", len(res["launch_ui"]), "launch surfaces ->", out)


def splunk_views(splunk, out):
    reg = json.loads((ROOT / "learning/academy/lab_registry_data.json").read_text())["entries"]
    views = {}
    for e in reg:
        v = "ws_" + e["lab_id"].lower().replace("-", "_")
        views[e["lab_id"]] = v
    # the registry's own view names where they differ from the pattern
    cur = json.loads((ROOT / "learning/academy/curriculum.json").read_text())

    def walk(x):
        if isinstance(x, dict):
            if x.get("lab_id") and x.get("view"):
                views[x["lab_id"]] = x["view"]
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(cur)
    on_disk = {p.stem for p in (ROOT / "splunk_app/agentsec/default/data/ui/views").glob("*.xml")}
    pw_ = subprocess.run(["docker", "exec", "agentsec_splunk", "printenv", "SPLUNK_PASSWORD"], capture_output=True, text=True).stdout.strip()
    res = {}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=os.environ.get("AGENTSEC_CHROMIUM"))
        page = b.new_page(viewport={"width": 1440, "height": 1000})
        page.goto(f"{splunk}/en-US/account/login")
        page.fill("input[name=username]", "admin")
        page.fill("input[name=password]", pw_)
        page.keyboard.press("Enter")
        page.wait_for_url("**/app/**", timeout=120000)
        for lab, view in sorted(views.items()):
            if view not in on_disk:
                res[lab] = {"view": view, "exists_in_app": False}
                continue
            errs = []
            page.on("pageerror", lambda e: errs.append(str(e)[:120]))
            r = page.goto(f"{splunk}/en-US/app/agentsec/{view}", wait_until="domcontentloaded")
            page.wait_for_timeout(9000)
            text = page.inner_text("body")
            shots = ROOT / "docs/reviews/batch7/splunk_views"
            shots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(shots / f"{view}.png"))
            res[lab] = {"view": view, "exists_in_app": True, "http": r.status if r.ok is not None and r else None,
                        "panels_rendered": page.locator("[data-test*='viz']").count(), "markdown_blocks": page.locator("[data-test*='markdown']").count(),
                        "tabs": page.locator("[data-test='tab-bar'] [role='tab']").count(),
                        "has_error_banner": bool(re.search(r"Error in 'search'|Search is waiting|Unknown search command|could not be loaded|view not found|404", text)),
                        "headings": page.eval_on_selector_all("h1,h2,h3", "els => els.slice(0,6).map(e => e.textContent.trim().slice(0,70))"), "page_errors": errs[:3]}
        b.close()
    Path(out).write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    print("splunk views checked:", len(res))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("attack-ui"); a1.add_argument("--base", required=True); a1.add_argument("--out", required=True)
    a2 = sub.add_parser("splunk-views"); a2.add_argument("--splunk", default="http://127.0.0.1:8000"); a2.add_argument("--out", required=True)
    a = ap.parse_args()
    attack_ui(a.base, a.out) if a.cmd == "attack-ui" else splunk_views(a.splunk, a.out)
