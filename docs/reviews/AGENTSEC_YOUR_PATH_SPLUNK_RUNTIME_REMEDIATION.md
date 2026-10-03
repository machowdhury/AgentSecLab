# AGENTSEC YOUR PATH SPLUNK RUNTIME REMEDIATION

Starting Commit: `b2f98235a51a491d9719b4b7b9b5d08218d49413`
Ending Commit: `d68b8680972bd3610f6d886d3b417c173da140fd`
Root Cause: SUPPORTED. A live Splunk console exception was NOT MEASURED.

Source Asset State: `splunk_app/agentsec/appserver/static/agentsec_learner_path.js` at the starting commit contained `mount()` and `start()`. `start()` called `mount()` immediately when `document.readyState` was not `"loading"`. `mount()` returned false when `#agentsec-progress` was missing and did not retry.

Deployed Asset State: OBSERVED by the independent check supplied for this task. EC2 file `/opt/splunk/etc/apps/agentsec/appserver/static/agentsec_learner_path.js` was 15246 bytes, SHA-256 `7e85b47e96932051e6731441ccf1d8352cee1ac1f6f108bb11356d9e2a09377c`, matching the source. This session did not re-hash the EC2 file.

Splunk-Served Asset State: OBSERVED by that same check. GET `/en-US/static/app/agentsec/agentsec_learner_path.js` returned the implementation, with Splunk's `i18n_register` bootstrap prepended. A prior HEAD `Content-Length: 0` was not treated as an empty file.

Lifecycle Behavior Before: The view XML placeholder `Learning progress loads in this browser. It is not a Splunk result.` was OBSERVED on `/en-US/app/agentsec/learner_path`. The tally, cards, states, next-workshop line, and reset control were absent. `DOMContentLoaded` was registered only while `readyState === "loading"`. On a Splunk app page that event has already fired before a Classic Dashboard script runs. The HTML panel is inserted by the dashboard after `script="agentsec_learner_path.js"` is evaluated. One `mount()` call then finds no root and returns. The placeholder stays.

Implementation: `begin()` asks for `splunkjs/mvc/simplexml/ready!` when `require` exists, and also arms a waiter immediately. The waiter mounts when `#agentsec-progress` exists. If it does not, a `MutationObserver` on `document.documentElement` plus a timer of 50 attempts at 100ms waits. The observer and the timer stop after a successful mount and after the attempt cap. `data-agentsec-mounted` still makes a second mount return false. The progress key, states, catalog, and visual classes were not redesigned.

Lifecycle Behavior After: UNIT TESTED. A vm document with `readyState` `"complete"` and no root does not paint. After the root is inserted and the `simplexml/ready!` callback runs, the tally, a workshop card, and the reset control appear once. A second mount does not add another card or another style element. STATIC RENDERED against Splunk: NOT MEASURED. SPLUNK-HOSTED RENDERED: NOT MEASURED.

Progress Persistence: UNIT TESTED. `agentsec.learner.progress.v1` still stores `IN PROGRESS`. A second script evaluation against the same storage renders that state. Storage was not moved to an index, KV Store, cookie, or server.

Reset Behavior: UNIT TESTED. The reset click removes only that key and returns the workshop to `NOT STARTED`.

Hard Reload: NOT MEASURED on Splunk. A new script evaluation is what the reload test covers.

Navigate Away / Return: NOT MEASURED on Splunk. A new page load re-runs the script. An in-place panel replacement after the 5s waiter has stopped is NOT TESTED.

Focused Tests: `tests/unit/test_learner_progress.py` includes the late-root sequence. `tests/splunk/test_guided_learning.py` and `tests/unit/test_learner_console.py` passed with it. Process exit 0, 18 passed.

Full Offline Suite: `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`. Exit 0. `1107 passed, 3 deselected` in 9.63s. Failed: 0. Skipped: 0.

Live Splunk Validation: NOT MEASURED. This machine's port 8000 is a different Splunk and was not used. The AgentSec EC2 host was not opened from this session.

Viewport Results: 1920, 1440, 1280, and 1024 were NOT MEASURED.

Keyboard: NOT TESTED on the Splunk page. Controls remain native `button` and `a` elements.

Screen Reader: NOT TESTED.

Schema: `1.9.0` not edited.
ExternalEvidence: `1.0.0` not edited.
DET-MCP-001: not edited. It stays disabled.
CTRL-MCP-001: not edited.

Secret Hygiene: `.env` was not read, printed, or staged. No credential, certificate, key, token, or crypto was added. TLS verification was not disabled.

Files Modified: `splunk_app/agentsec/appserver/static/agentsec_learner_path.js`, `tests/unit/test_learner_progress.py`, this review.

Git Status: `develop` only. `main` not modified. No tag. No GitHub Release. `refreshAPP.sh` was not in this working tree and was not touched.

Remaining Limitations: Splunk-hosted paint is NOT MEASURED. A panel inserted after the 5 second cap is not mounted. True browser 200% zoom is NOT MEASURED. Screen reader is NOT TESTED.

External Re-Verification Targets:

1. Hard-refresh `/en-US/app/agentsec/learner_path` after the app refresh. The placeholder alone is not enough. Confirm `#agentsec-progress-tally`, workshop cards, a next-workshop line, and `#agentsec-progress-reset`.
2. Mark a workshop IN PROGRESS, leave the view, return, and reload. The state should remain. Reset should return it to NOT STARTED and should not delete Splunk data.
3. Confirm the 13-entry guided nav still renders and that INVESTIGATED is not labeled SAFE, PASSED, or AUTHORIZED.
4. Confirm schema `1.9.0`, ExternalEvidence `1.0.0`, and DET-MCP-001 still disabled.

EC2 update on the existing checkout, without deleting volumes and without touching `refreshAPP.sh`:

```sh
git fetch origin
git checkout develop
git merge --ff-only origin/develop
./scripts/precheck.sh --remote
./scripts/lab-up.sh --build --refresh-app --remote
```
