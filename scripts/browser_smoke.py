"""Read-only real-browser smoke test for a running Academy (local or reached over a private tunnel).

    AGENTSEC_BASE_URL=http://127.0.0.1:15001 AGENTSEC_CHROMIUM=<path> python scripts/browser_smoke.py [--shots DIR]

Navigates, never launches an attack or submits a form. Fails on any console error, page error,
failed request or HTTP status >= 400 other than the one deliberate probe. Exit 0 only if every check passes.
"""
from __future__ import annotations

import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("AGENTSEC_BASE_URL", "http://127.0.0.1:5001").rstrip("/")
SHOTS = sys.argv[sys.argv.index("--shots") + 1] if "--shots" in sys.argv else None
results: list[tuple[bool, str]] = []
problems: list[str] = []
assets: dict[str, int] = {}


def check(ok: bool, what: str) -> None:
    results.append((bool(ok), what))
    print(("PASS " if ok else "FAIL ") + what)


def path_bar(pg):
    return pg.get_by_role("navigation", name="Workshop path")


def current(pg) -> list[str]:
    return [t for t in path_bar(pg).get_by_role("link").all_inner_texts() if path_bar(pg).get_by_role("link", name=t).get_attribute("aria-current") == "step"]


with sync_playwright() as p:
    b = p.chromium.launch(**({"executable_path": os.environ["AGENTSEC_CHROMIUM"]} if os.environ.get("AGENTSEC_CHROMIUM") else {}))
    for w, h in ((1280, 900), (390, 800)):
        pg = b.new_context(viewport={"width": w, "height": h}).new_page()
        pg.on("console", lambda m, w=w: problems.append(f"console.{m.type}@{w}: {m.text[:160]}") if m.type in ("error", "warning") else None)
        pg.on("pageerror", lambda e, w=w: problems.append(f"pageerror@{w}: {str(e)[:160]}"))
        pg.on("requestfailed", lambda r, w=w: problems.append(f"requestfailed@{w}: {r.url}"))
        def on_resp(r, w=w):
            if "/static/learn/assets/" in r.url: assets[r.url.rsplit("/", 1)[-1]] = r.status
            if r.status >= 400: problems.append(f"http {r.status}@{w}: {r.url}")
        pg.on("response", on_resp)

        def go(path, ready):
            pg.goto(BASE + path); pg.locator(ready).first.wait_for(timeout=20000)
            if SHOTS: os.makedirs(SHOTS, exist_ok=True); pg.screenshot(path=f"{SHOTS}/{w}{path.replace('/', '_')}.png")

        # Navigation and lazy-loaded Centers through the real sidebar.
        go("/learn", "main h1, main h2")
        side = pg.get_by_role("navigation", name="Primary navigation")
        for label, heading in (("Governance Center", "Governance"), ("Risk Center", "Risk"), ("EVAL Center", "EVAL"), ("Security Assurance", "Assurance")):
            if w == 390:  # the sidebar is a drawer at phone width; navigate by URL there
                continue
            side.get_by_role("link", name=label).click(); pg.locator("main h1, main h2").first.wait_for(timeout=20000)
            check(heading.lower() in pg.locator("main").inner_text().lower(), f"@{w} sidebar opens {label}")
        for path in ("/learn/governance", "/learn/governance/frameworks", "/learn/governance/threats", "/learn/governance/export",
                     "/learn/risk", "/learn/risk/register", "/learn/risk/method", "/learn/evals", "/learn/evals/catalog",
                     "/learn/evals/findings", "/learn/assurance", "/learn/assurance/mcp-unauthorized-scope"):
            go(path, "main h1, main h2"); check(pg.locator("main").inner_text().strip() != "", f"@{w} {path} renders")

        # Representative evidence: lab Prove tab shows hashes; governance links into labs and the EVAL findings.
        go("/learn/lab/LAB-MCP-003", "main h1")
        pg.get_by_role("tab", name="Prove").click()
        check(len(__import__("re").findall(r"\b[0-9a-f]{12,64}\b", pg.locator("main").inner_text())) >= 1, f"@{w} LAB-MCP-003 Prove tab shows evidence hash digests")
        go("/learn/governance/threats", "main h2")
        check(pg.locator("main a[href*='/learn/evals'], main a[href*='/learn/risk/']").count() >= 1, f"@{w} governance threats link to EVAL or Risk evidence")
        go("/learn/evals/findings", "main h2")
        check("not_verified" in pg.locator("main").inner_text().lower().replace(" ", "_") or "not verified" in pg.locator("main").inner_text().lower(), f"@{w} EVAL findings state NOT_VERIFIED")
        go("/learn/risk", "main h2")
        check("LOCAL_DRAFT_NOT_APPROVED" in pg.locator("main").inner_text() or "not approved" in pg.locator("main").inner_text().lower(), f"@{w} Risk Center labels drafts as not approved")

        # Workshop stage transitions via the path bar (browser history intact).
        go("/learn/governance", "main h2")
        order = ["Learn", "Attack", "Investigate", "EVAL", "Risk", "Governance"]
        check(path_bar(pg).get_by_role("link").all_inner_texts() == order, f"@{w} workshop path lists the six steps in order")
        check(current(pg) == ["Governance"], f"@{w} path bar marks Governance current")
        for step, want in (("Risk", "/learn/risk"), ("EVAL", "/learn/evals"), ("Learn", "/learn/curriculum")):
            path_bar(pg).get_by_role("link", name=step).click(); pg.wait_for_url(f"**{want}"); pg.locator("main h1, main h2").first.wait_for()
            check(current(pg) == [step], f"@{w} path bar to {step} lands on {want} and marks it current")
        pg.go_back(); pg.wait_for_url("**/learn/evals"); check(current(pg) == ["EVAL"], f"@{w} browser Back restores the previous step")
        go("/learn/loan-desk", "main h1, main h2"); check(len(current(pg)) <= 1 and "/loan-desk" in pg.url, f"@{w} Loan Desk mission opens a stage ({pg.url.rsplit('/', 1)[-1]})")
        check(not pg.evaluate("document.documentElement.scrollWidth>document.documentElement.clientWidth"), f"@{w} no horizontal overflow")
    b.close()

lazy = {k: v for k, v in assets.items() if k.split("-")[0] in ("Governance", "RiskCenter", "EvalCenter", "seed", "parts", "evals") or k.startswith(("exp-", "LAB-"))}
check(len(lazy) >= 6 and all(v in (200, 304) for v in lazy.values()), f"{len(lazy)} lazy-loaded chunks all served 200/304")
check(all(v in (200, 304) for v in assets.values()), f"all {len(assets)} requested static assets served 200/304")
check(not problems, "no console errors/warnings, page errors, failed requests or HTTP >= 400")
for pr in problems[:15]: print("  ", pr)
bad = [w for ok, w in results if not ok]
print(f"SUMMARY pass={len(results) - len(bad)} fail={len(bad)}")
print("NOTE: this proves behavior of the origin you pointed it at; it does not change any acceptance status by itself.")
sys.exit(1 if bad else 0)
