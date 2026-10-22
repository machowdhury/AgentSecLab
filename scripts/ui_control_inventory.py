#!/usr/bin/env python3
"""Enumerate every interactive control on the learner-facing pages and classify it structurally.

Serves the Attack Service in-process against an UNREACHABLE AcmeBank (127.0.0.1:9), so nothing
here can start a LIVE run or touch Splunk. Classes are STRUCTURAL, from the rendered DOM:

  NAVIGATES       same-origin link that returned a non-error status when fetched
  FRAGMENT_OK     in-page link whose target id exists
  EXTERNAL        link to another origin (Splunk Web etc.); not fetched, not claimed working
  HANDLER         button/summary/input with an event listener attached by page script
  FORM_SUBMIT     submit control inside a form that has an action or a submit listener
  NO_HANDLER      button with no listener and no form: a candidate decorative control (needs review)
  BROKEN_LINK     same-origin link that returned an error status, or a fragment with no target
  NATIVE          native widget with built-in behaviour (details summary, text field, radio, checkbox)

A structural class is not proof of behaviour. Behaviour is covered by browser tests; this report
shows which controls have no test-visible wiring at all. Needs: playwright and a Chromium.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections import Counter
from pathlib import Path

from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402

LIVE_LABS = ["LAB-PI-001", "LAB-MCP-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001",
             "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-AGENTSEC-CAPSTONE-001"]
PAGES = ["/", "/acmebank", "/academy", "/academy/foundations", "/academy/path", "/academy/status",
         "/academy/labs/LAB-MCP-001", *[f"/labs/{lab}" for lab in LIVE_LABS]]

TRACK = """
(() => {
  window.__listeners = [];
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    try { window.__listeners.push({node: this, type}); } catch (e) {}
    return add.call(this, type, fn, opts);
  };
})();
"""

COLLECT = """
() => {
  const sel = 'a[href], button, input, select, textarea, summary, [role="button"], [role="tab"], [role="link"], [onclick]';
  const listeners = window.__listeners || [];
  const has = (el, types) => listeners.some(l => types.includes(l.type) &&
      (l.node === el || (l.node instanceof Node && l.node !== document && l.node !== window && l.node.contains && l.node.contains(el) && l.node !== document.body)));
  const delegated = (types) => listeners.some(l => types.includes(l.type) && (l.node === document || l.node === window || l.node === document.body));
  const name = (el) => {
    const lab = el.getAttribute('aria-label'); if (lab) return lab.trim();
    const by = el.getAttribute('aria-labelledby');
    if (by) { const t = by.split(/\\s+/).map(i => (document.getElementById(i) || {}).textContent || '').join(' ').trim(); if (t) return t; }
    if (el.labels && el.labels.length) return Array.from(el.labels).map(l => l.textContent).join(' ').trim();
    const txt = (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim(); if (txt) return txt;
    return (el.getAttribute('title') || el.getAttribute('value') || el.getAttribute('placeholder') || '').trim();
  };
  return Array.from(document.querySelectorAll(sel)).map((el, i) => {
    const r = el.getBoundingClientRect();
    return {
      i, tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', id: el.id || '',
      name: name(el).slice(0, 80), href: el.getAttribute('href') || '',
      disabled: el.disabled === true || el.getAttribute('aria-disabled') === 'true',
      visible: !!(r.width && r.height) && getComputedStyle(el).visibility !== 'hidden',
      form: !!el.closest('form'), formAction: el.closest('form') ? (el.closest('form').getAttribute('action') || '') : '',
      direct: has(el, ['click', 'change', 'input', 'keydown', 'submit']),
      formListener: el.closest('form') ? has(el.closest('form'), ['submit']) : false,
      delegatedClick: delegated(['click']),
      hasInlineHandler: el.hasAttribute('onclick'),
    };
  });
}
"""


def classify(c: dict, origin: str, check_url) -> tuple[str, str]:
    tag = c["tag"]
    if tag == "a":
        href = c["href"]
        if href.startswith("#"):
            if len(href) > 1 and c.get("fragment_ok"):
                return "FRAGMENT_OK", "target exists"
            if c["direct"]:
                return "HANDLER", "fragment target absent; click is handled by page script (dead without JavaScript)"
            return ("FRAGMENT_OK", "bare #") if href == "#" else ("BROKEN_LINK", "no element with that id and no script handler")
        if href.startswith(("mailto:", "javascript:")):
            return "BROKEN_LINK", "scheme not allowed"
        if href.startswith("/") and not href.startswith("//") or href.startswith(origin):
            if href.startswith("/en-US/"):
                return "EXTERNAL", "Splunk Web path, completed to port 8000 by page script; not fetched"
            status = check_url(href if href.startswith("http") else origin + href)
            return ("NAVIGATES", f"HTTP {status}") if status < 400 else ("BROKEN_LINK", f"HTTP {status}")
        return "EXTERNAL", "other origin; not fetched"
    if tag in ("input", "select", "textarea") or tag == "summary":
        if c["type"] in ("submit", "button"):
            pass
        else:
            return "NATIVE", "native widget"
    if c["type"] == "submit" and c["form"]:
        return ("FORM_SUBMIT", "form submit listener" if c["formListener"] else "form action") if (c["formListener"] or c["formAction"]) else ("NO_HANDLER", "submit with no action or listener")
    if c["direct"] or c["hasInlineHandler"]:
        return "HANDLER", "listener attached"
    if c["delegatedClick"]:
        return "HANDLER", "document-level delegated click listener (target not proven)"
    return "NO_HANDLER", "no listener found"


def collect(chromium: str) -> list[dict]:
    from playwright.sync_api import sync_playwright

    app = create_app(AcmeBankClient("http://127.0.0.1:9"))  # unreachable on purpose: no LIVE run can start
    app.config["TESTING"] = True
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    rows: list[dict] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium, headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        ctx.add_init_script(TRACK)

        def check_url(url: str) -> int:
            try:
                return ctx.request.get(url, timeout=8000).status
            except Exception:  # noqa: BLE001 - an unreachable link is reported as 599, not hidden
                return 599

        for path in PAGES:
            page = ctx.new_page()
            resp = page.goto(origin + path, wait_until="load")
            page.wait_for_timeout(600)
            controls = page.evaluate(COLLECT)
            ids = set(page.evaluate("() => Array.from(document.querySelectorAll('[id]')).map(e => e.id)"))
            for c in controls:
                c["fragment_ok"] = c["href"].startswith("#") and c["href"][1:] in ids
                cls, why = classify(c, origin, check_url)
                rows.append({"page": path, "page_status": resp.status if resp else None, **{k: c[k] for k in
                             ("tag", "type", "id", "name", "href", "disabled", "visible")}, "class": cls, "why": why,
                             "unnamed": not c["name"]})
            page.close()
        browser.close()
    server.shutdown()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chromium", required=True, help="path to a Chromium/Chrome executable")
    ap.add_argument("--out", default="docs/reviews/batch1/control_inventory")
    args = ap.parse_args()
    rows = collect(args.chromium)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    totals = Counter(r["class"] for r in rows)
    per_page = {p: dict(Counter(r["class"] for r in rows if r["page"] == p)) for p in PAGES}
    unnamed = [r for r in rows if r["unnamed"] and r["visible"]]
    summary = {"controls": len(rows), "by_class": dict(totals), "by_page": per_page,
               "visible_controls_without_accessible_name": len(unnamed),
               "method": "structural, from rendered DOM with listener tracking; not behavioural proof"}
    out.with_suffix(".json").write_text(json.dumps({"summary": summary, "controls": rows}, indent=1) + "\n", encoding="utf-8")
    lines = ["# UI control inventory (structural)", "", f"Controls found: **{len(rows)}** across {len(PAGES)} pages.", "",
             "| Class | Count |", "|---|---|", *[f"| {k} | {v} |" for k, v in sorted(totals.items())], "",
             f"Visible controls without an accessible name: **{len(unnamed)}**.", "",
             "## Review list (NO_HANDLER and BROKEN_LINK)", "", "| Page | Control | Class | Why |", "|---|---|---|---|"]
    for r in rows:
        if r["class"] in ("NO_HANDLER", "BROKEN_LINK"):
            lines.append(f"| `{r['page']}` | {r['tag']} `{r['id'] or r['href'] or r['name']}` ({'hidden' if not r['visible'] else 'visible'}) | {r['class']} | {r['why']} |")
    out.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
