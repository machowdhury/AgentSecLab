#!/usr/bin/env python3
"""AUTOMATED first-time-learner walkthrough of the Loan Desk mission against the RUNNING Docker stack.

This is a repeatable browser script. It is NOT a usability study: machine timings are not human timings, and it
cannot measure comprehension, confusion or perceived difficulty. Those need the pilot in docs/reviews/batch5/.
It measures what a script can: discoverability, click counts, per-step reading load, navigation gates, state
survival across reload/back, console and network errors, keyboard operability, axe violations, machine time.
"""
from __future__ import annotations
import argparse, json, os, re, sys, time
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
STEPS = ["understand", "explore", "predict", "attack", "observe", "investigate", "defend", "retest", "compare", "explain"]
JARGON = ["PDP", "posture", "scope", "handler", "ALLOW", "DENY", "run.id", "SPL", "sequence", "untrusted", "proposal", "HEC", "decision point", "reconcile"]
WPM = 200


def wait_run(pg, slot, timeout=300000):
    pg.wait_for_function("(s) => { const p = document.querySelector(`[data-run-panel='${s}']`); return p && p.getAttribute('aria-busy') === 'false' && p.querySelector('.outcomes, .callout--warn'); }", arg=slot, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="http://127.0.0.1:5001")
    ap.add_argument("--chromium", default=os.environ.get("AGENTSEC_CHROMIUM"))
    ap.add_argument("--out", default="docs/reviews/batch5/learner_walkthrough.json")
    ap.add_argument("--skip-live-runs", action="store_true")
    a = ap.parse_args()
    res: dict = {"kind": "AUTOMATED_BROWSER_SCRIPT_NOT_A_HUMAN_STUDY", "target": a.attack, "findings": []}
    log = {"console_errors": [], "page_errors": [], "bad_responses": []}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=a.chromium)
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        pg.on("console", lambda m: log["console_errors"].append(m.text[:200]) if m.type == "error" else None)
        pg.on("pageerror", lambda e: log["page_errors"].append(str(e)[:200]))
        pg.on("response", lambda r: log["bad_responses"].append(f"{r.status} {r.request.method} {r.url.split('?')[0][-70:]}") if r.status >= 400 else None)
        # 1. discoverability
        pg.goto(f"{a.attack}/academy")
        home = pg.inner_text("body")
        res["discovery"] = {"clicks_home_to_mission": 1, "start_button_text_present": "Start the mission" in home,
                            "mission_in_nav": pg.locator("a:has-text('Loan Desk Mission')").count() > 0,
                            "home_states_duration_or_difficulty": bool(re.search(r"\d+\s*(–|-|to)?\s*\d*\s*min", home, re.I)),
                            "home_has_objectives": "What you will be able to do" in home}
        pg.click("text=Start the mission")
        pg.wait_for_selector("[data-mission='loan-desk']")
        body = pg.inner_text("body")
        res["mission_page"] = {"states_duration": bool(re.search(r"\d+\s*(–|-|to)?\s*\d*\s*min", body, re.I)),
                               "lists_prerequisites": bool(re.search(r"prerequisite|before you start|you will need", body, re.I)),
                               "lists_objectives": bool(re.search(r"objective|by the end|you will be able", body, re.I)),
                               "has_what_you_will_learn": "What you will learn" in body}
        # 2. per-step load and structure
        steps = {}
        for s in STEPS:
            sec = pg.locator(f"#step-{s}")
            txt = sec.evaluate("e => e.textContent").strip()
            words = len(txt.split())
            steps[s] = {"words": words, "read_min_at_200wpm": round(words / WPM, 1),
                        "has_what_to_do": "What to do" in txt, "has_why_it_matters": "Why it matters" in txt,
                        "interactive_controls": sec.evaluate("e => e.querySelectorAll('button, input, select, textarea, a[href]').length")}
        res["steps_static"] = steps
        res["reading_total_min"] = round(sum(v["read_min_at_200wpm"] for v in steps.values()), 1)
        html = pg.content()
        res["jargon"] = {t: {"occurrences": len(re.findall(re.escape(t), re.sub(r"<[^>]+>", " ", html))),
                             "marked_up_definition": bool(re.search(rf"<(abbr|dfn)[^>]*>\s*{re.escape(t)}", html))} for t in JARGON}
        # 3. gating, reload and back
        gates = {}
        for s in ("attack", "observe", "retest", "compare"):
            pg.click(f"[data-step-link='{s}']", force=True)
            gates[s] = {"stayed_locked": pg.locator(f"#step-{s}").is_hidden(), "message": pg.locator("[data-gate-message]").inner_text()[:90]}
        res["gates"] = gates
        # 4. keyboard only: Tab to the Continue control on step 1 and press Enter
        pg.goto(f"{a.attack}/academy/missions/loan-desk")
        reached = False
        for _ in range(60):
            pg.keyboard.press("Tab")
            if pg.evaluate("(document.activeElement.textContent||'').trim().startsWith('Continue to Explore')"):
                reached = True; pg.keyboard.press("Enter"); break
        pg.wait_for_timeout(300)
        res["keyboard"] = {"reached_continue_by_tab": reached, "explore_opened": pg.locator("#step-explore").is_visible(),
                           "focus_moves_to_new_step": pg.evaluate("!!document.activeElement && !!document.activeElement.closest('#step-explore, [data-mission]')")}
        if not a.skip_live_runs:
            t0 = time.time(); timings = {}
            def mark(k): timings[k] = round(time.time() - t0, 1)
            pg.click("[data-step-link='explore']"); pg.fill("#f-full_name", "Amara Nwosu"); pg.click("[data-launch='explore']"); wait_run(pg, "explore"); mark("explore_run_done_s")
            pg.click("[data-step-link='predict']")
            pg.check("input[name=follow][value=yes]"); pg.check("input[name=decision][value=ALLOW]"); pg.check("input[name=queue][value=planted]"); pg.click("[data-lock-prediction]")
            pg.reload(); pg.wait_for_selector("[data-mission='loan-desk']")
            pg.click("[data-step-link='attack']", force=True)
            res["state_survives_reload"] = {"attack_unlocked_after_reload": pg.locator("#step-attack").is_visible(),
                                            "prediction_still_locked": "locked" in pg.evaluate("localStorage.getItem('agentsec.academy.progress.v1')||''").lower() or pg.locator("[data-prediction-locked]").count() > 0}
            pg.click("[data-launch='attack']"); wait_run(pg, "attack"); mark("attack_run_done_s")
            atk_panel = pg.locator("[data-run-panel='attack']").inner_text()
            res["attack_outcome_visible_to_learner"] = {"model_proposals_listed": "proposed" in atk_panel.lower(), "policy_decision_shown": "ALLOW" in atk_panel or "DENY" in atk_panel,
                                                       "handler_outcome_shown": "handler" in atk_panel.lower(), "planted_text_reached_queue": "PRE-APPROVED" in atk_panel}
            pg.click("[data-step-link='defend']"); pg.check("input[name=posture][value=hardened]"); pg.click("[data-apply-defense]")
            pg.click("[data-step-link='retest']"); pg.click("[data-launch='retest']"); wait_run(pg, "retest"); mark("retest_run_done_s")
            ret = pg.locator("[data-run-panel='retest']").inner_text()
            res["retest_outcome_visible_to_learner"] = {"says_blocked": "BLOCKED" in ret, "business_outcome_separate": bool(re.search(r"COMPLETE|INCOMPLETE|FAILED", ret)),
                                                       "policy_reason_shown": "argument_not_allowed" in ret}
            pg.click("[data-step-link='compare']"); res["compare_has_table"] = pg.locator("[data-compare-table]").is_visible()
            res["machine_timings_s"] = timings
            res["back_button"] = {}
            pg.go_back(); pg.wait_for_timeout(500)
            res["back_button"]["url_after_back"] = pg.url.replace(a.attack, "")
        # 5. axe on each step
        try:
            from axe_playwright_python.sync_playwright import Axe
            pg.goto(f"{a.attack}/academy/missions/loan-desk"); ax = {}
            for s in STEPS:
                pg.click(f"[data-step-link='{s}']", force=True)
                if pg.locator(f"#step-{s}").is_hidden():
                    ax[s] = "LOCKED_NOT_SCANNED"; continue
                v = Axe().run(pg).response["violations"]
                ax[s] = [{"id": x["id"], "impact": x["impact"], "n": len(x["nodes"])} for x in v]
            res["axe"] = ax
        except ImportError:
            res["axe"] = "axe_playwright_python not installed"
        b.close()
    res["browser_log"] = {k: v[:10] for k, v in log.items()}
    Path(ROOT / a.out).parent.mkdir(parents=True, exist_ok=True)
    (ROOT / a.out).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: res[k] for k in res if k not in ("steps_static", "jargon", "axe")}, indent=1)[:3500])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
