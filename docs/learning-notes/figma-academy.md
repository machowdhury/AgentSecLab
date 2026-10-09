# AgentSec Academy (P1.4): turning a design into an honest learning surface

## In one paragraph

The Figma file showed what a good AgentSec learning experience looks like: a
home page, a learning path, and a nine-step MCP workshop where you predict,
attack, investigate, defend, retest, compare and explain. The Figma prototype
itself was a self-contained React app with made-up numbers ("LLM calls 4",
"Today, 09:42"). P1.4 rebuilds that experience inside the existing Flask
attack service and wires every number on screen to a real record, either a
committed REPLAY pack or a LIVE run this service launched.

## WHAT IS IT?

Five server-rendered pages (`/academy`, `/academy/foundations`,
`/academy/path`, `/academy/status`, `/academy/labs/LAB-MCP-001`) plus three
read-only JSON endpoints (`/api/academy/evidence/<run_id>`,
`/api/academy/compare`, `/api/academy/status`). One stylesheet and one script.

## WHY DOES IT EXIST?

The Splunk Studio workshop is the evidence workbench, but P1.2/P1.3 measured
that Studio cannot reflow at 400% zoom. A learner needs a path that works with
a keyboard, at 400%, and on a narrow screen, without losing the link to real
evidence. The Academy is that path; Splunk stays the place you verify.

## HOW DOES IT WORK?

1. The page asks the server for a run by `run.id`.
2. `academy_evidence.load_run` accepts only a lowercase UUID. It reads a
   committed REPLAY pack, or a LIVE `artifacts/<run_id>/events.jsonl` only if
   the launcher has a record that it launched that run for LAB-MCP-001.
3. `derive_facts` reads the CTRL-MCP-001 decision event and the presence or
   absence of `agentsec.mcp.started` / `agentsec.pipeline.stopped`. Every fact
   carries the event it came from (sequence, name, timestamp).
4. The browser renders those facts with `textContent` only. Predictions,
   answers and progress stay in this browser and are never sent.
5. Splunk links carry the exact `run.id` and an epoch time window around the
   recorded events, so a recording from September is still found.

## WHERE DOES IT SIT IN AGENTSEC?

Inside the Attack Service (Flask, port 5001), next to the existing lab pages.
It does not touch AcmeBank, the MCP gateway, CTRL-MCP-001 or the Splunk app.

## WHAT IS THE TRUST BOUNDARY?

Browser → Attack Service. Everything from the browser is untrusted: the
`run.id` in the URL, query parameters, and the launch body. The Academy never
takes a decision from the browser; the only state-changing call is the
pre-existing closed `POST /api/launch`, which the runtime authorizes.

## WHAT COULD AN ATTACKER CONTROL?

- The `run_id` path segment: path traversal, other labs' runs, runs never
  launched. Mitigated by the UUID pattern and the launcher-record check.
- Query parameters on compare: extra fields are refused (`unknown_fields`).
- Contents of a LIVE events file, if they could write to `artifacts/`: size
  and event caps, JSON validation, and a `run.id` match on every event. Values
  are shown as text, never HTML.

## WHAT CAN GO WRONG?

- Showing a recorded run as if it were live. Every evidence block carries a
  REPLAY or LIVE badge and the source file hash.
- Reading DENY as "prevented" when the handler actually started. A warning is
  raised if a DENY record also contains `agentsec.mcp.started`.
- Treating a missing decision event as ALLOW. It is shown as NOT MEASURED.
- Comparing a LIVE attack with a REPLAY retest. The UI forces the retest to
  match the attack's provenance, and the compare endpoint warns on mixed pairs.
- Double-clicking Launch and creating two experiments. The client disables
  launch while busy and records one run per mode.

## WHAT TELEMETRY SHOULD EXIST?

The Academy adds no new telemetry; it reads what the runtime already emits:
`agentsec.run.started`, `agentsec.control.decision` (CTRL-MCP-001 decision,
reason, requested and granted scope), `agentsec.mcp.started` or
`agentsec.pipeline.stopped`, and `agentsec.run.completed`.

## HOW WILL SPLUNK SHOW IT?

"Search this run in Splunk" opens Splunk Search with
`index=agentsec_telemetry sourcetype=otel:agentic:json "agentsec.run.id"="<id>"`
and exact `earliest`/`latest` epochs. "Open the Studio workshop" pre-fills
`form.run_id` (REPLAY) or `form.live_run_id` (LIVE); this pre-fill was observed
to work but is not documented by Splunk.

## WHAT CONTROL COULD CHANGE THE RESULT?

Only CTRL-MCP-001, through the security profile: vulnerable fails open
(ALLOW, handler starts), defended denies the out-of-grant tool before the
handler. Nothing in the Academy, and nothing in Splunk, can change a decision.

## WHAT TEST PROVES THE LOGIC?

- `tests/unit/test_p1_4_academy_evidence.py`: facts match the raw packs, each
  fact cites its event, malformed and malicious records are refused.
- `tests/security/test_p1_4_academy_security.py`: GET-only routes, strict CSP,
  no inline script, closed launch body, unlaunched LIVE runs refused, no
  Figma demo values, unbiased Predict step.
- `tests/integration/test_p1_4_academy_browser.py`: Chromium walks the REPLAY
  workflow by mouse and keyboard, reflows from 1920 to 320 CSS px, enforces
  step gating; the double-launch test is mocked and labelled as such.

## Design decision: why not ship the Figma React app?

Shipping React would add a Node toolchain and an npm dependency tree to a
Docker build on a host with 8.6 GB free, and would duplicate the client
contract the Flask templates already test. The visual language (navy, teal,
8px radius, card layout) was ported to CSS; the accessibility of the original
was raised (16px base, solid focus rings instead of a faint outline, system
fonts instead of a blocked web-font CDN, em breakpoints).

## What I should now be able to explain

1. Why does the Academy refuse a LIVE `run.id` that exists on disk but was not
   launched by this service?
2. What is the difference between "CTRL-MCP-001 recorded ALLOW" and "the tool
   ran", and which event proves the second?
3. Why must a missing decision event be shown as NOT MEASURED rather than
   ALLOW or SAFE? Which invariant is this?
4. Why does the Splunk link use exact epoch bounds instead of `-1h`?
5. What could go wrong if the compare view paired a LIVE ATTACK with a REPLAY
   RETEST?
6. Why is a strict CSP with no inline script a meaningful control for a page
   that renders recorded attack payloads?
7. Why is the double-launch browser test a mocked test, and what would a live
   integration test need instead?
8. Where is the policy decision point in this lab, and why is it not Splunk
   and not the Academy page?
