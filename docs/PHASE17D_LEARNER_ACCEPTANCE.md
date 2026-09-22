# Phase 17D — Learner / beginner / advanced acceptance

Walkthrough started at rewritten README (no “Not in this lab slice”).

Beginner path is documented: preflight → `.env` → `lab-up` → `lab-ready` → Home → PI → launch → copy run.id → Search → Path A/B → curriculum → Capstone → Mastery.

Friction found and fixed:

- README described an old PI-only slice (**release-blocking copy**). Replaced.
- Attack Service image could lag git (17C). Rebuilt.
- No `lab-down` / preflight. Added.

Remaining friction (MEDIUM/LOW, documented):

- Path B often visible without a reveal control (Studio limitation).
- REPLAY ids may be empty on a truly new Splunk volume.
- `lab-ready.sh` wrapper was not re-executed end-to-end in this agent session; health endpoints and Playwright views were OBSERVED instead.
- Preflight must run on the host Docker daemon (sandbox `docker info` is not authoritative).

Advanced path: skip ORIENT, open LIVE lab, launch, hunt by run.id, inspect CTRL-MCP-001, ATTACK vs RETEST — supported without source edits.

Capstone/Mastery: HTTP 200; no new LIVE capstone triple minted.
