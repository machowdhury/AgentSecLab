# AgentSec — Splunk static-asset versioning + locale URL remediation

**Verdict: IMPLEMENTED — LIVE SPLUNK RE-VERIFICATION REQUIRED**

| | |
|---|---|
| Starting commit | `2495ee91f9037a29207e9049aed897bc8eb0fd66` |
| Ending commit | `f8d92dd7cdca4163b645df1138f9eb93fd74fb5a` (code: `6981660`, repair: `f8d92dd`) |
| Branch | `develop`, pushed to `origin/develop` |
| Schema | `1.9.0` unchanged |
| ExternalEvidence | `1.0.0` unchanged |
| Product version | `1.1.0` unchanged |
| CTRL-MCP-001 | unchanged |
| DET-MCP-001 | unchanged, still disabled |
| `main` | unchanged at `0178c70e20cfe0152648e2aafb8e607280625c40` |
| Tags | unchanged (`v1.0.0` → `537be71a`, `v1.1.0` → `0178c70e`) |
| Release created | no |

## Root cause

### Stale static cache identity

Splunk Classic Simple XML loads custom dashboard JavaScript through
`ExtensionLoader`, which resolves `appStaticFileAppVersioned(...)` and fetches
the result with `jQuery.ajax({dataType: "text", cache: true})`, then `eval`s it.
The URL is:

```
/<locale>/static/@<splunk build>.<push version>-<app build>/app/agentsec/<file>
```

`<app build>` is `[install] build` from the app's `app.conf`, read by
`AppLocal.getBuild()`. It is the only segment AgentSec controls, and it had been
pinned at `3` since commit `829de82` while `agentsec_learner_path.js` changed
repeatedly — including the dashboard-ready lifecycle fix in `d68b868`.

| | |
|---|---|
| Old app build | `3` |
| New app build | `4` |
| Old versioned URL | `/en-US/static/@bcdcf0552e0c.1-3/app/agentsec/agentsec_learner_path.js` |
| New versioned URL | `/en-US/static/@bcdcf0552e0c.<push>-4/app/agentsec/agentsec_learner_path.js` |

The Splunk build (`bcdcf0552e0c`) and push version (`1`) were MEASURED on the
live host and are Splunk's to change, not AgentSec's.

The deployed `agentsec_learner_path.js` on EC2 was already byte-identical to the
repository copy (`d888136e6fd7156d8724d894c30401fb9c95ccf727313eb7fffbc61944b29f4f`),
and the old versioned URL returned HTTP 200 with real JavaScript rather than
Splunk's `/*--fallback--` placeholder. The remaining explanation for a browser
not running the fixed code is a cached response under an unchanged cache key.

### Locale duplication

AgentSec link text hard-coded `/en-US/app/agentsec/...`.
`Splunk.util.make_url` unconditionally prefixes the active locale onto a
root-relative path, so an already-localised path can be localised twice,
producing the observed `/en-US//en-US/app/agentsec/learner_path`. MEASURED
against the live Splunk:

* `/app/agentsec/learner_path` → `303` → `/en-US/app/agentsec/learner_path`,
  query string preserved.
* `/en-US//en-US/app/agentsec/learner_path` → `404`.

The browser component that emitted the doubled request was never identified;
the Chrome initiator is NOT MEASURED. Removing the hard-coded locale from
AgentSec link text makes the doubled shape unreachable from AgentSec-owned
content regardless of which component applied the second prefix.

### Generator reverting a committed fix

While validating, running `scripts/apply_guided_learning.py` rewrote
`agentsec_learner_path.js` with 229 lines removed. The generator emitted the
entire file from a template that predated both the styling work and the
dashboard-ready lifecycle fix, so any future run would silently revert them and
ship the regression under whatever app build was current. It now splices in only
the catalog it derives from the curriculum.

## Files modified

**Cache identity**

* `splunk_app/agentsec/default/app.conf` — `[install] build` `3` → `4`
* `scripts/static_cache_identity.py` — new
* `splunk_app/static_cache_identity.json` — new lock, outside `splunk_app/agentsec/`
  so `scripts/splunk_app_init.sh` does not stage it into the app

**Locale** — 348 occurrences of `/en-US/app/agentsec/` → `/app/agentsec/` across
79 files: 32 workshop view XMLs plus Home, Arena and Mastery; 33
`learning/**/*.definition.json`; `agentsec_learner_path.js`; and the generators
that emit them (`apply_guided_learning.py`, `build_agentsec_home_dashboard.py`,
`build_agentsec_mastery_dashboard.py`, `build_lab_*_dashboard.py`).

**Generator** — `scripts/apply_guided_learning.py::write_path`

**Docs** — `docs/learning-notes/splunk-static-asset-cache-identity.md`

### Deliberately not changed

| Scope | Reason |
|---|---|
| `src/agentsec/**` | Attack Service pages on port 5001. `learnerHref` keys on the `/en-US/` prefix to decide which root-relative links cross to Splunk on port 8000. |
| `learning/academy/curriculum.json` `attack_service_url` | Attack-Service-owned string with no current consumer. Pinned by a test so the exclusion is deliberate. |
| 192 `/en-US/app/search/search` handoff links | Splunk core search app, out of scope. |
| `learning/**/*.md` absolute `http://127.0.0.1:8000/...` links | Documentation, not Splunk-rendered. |
| `src/agentsec/workshop_flows.py` flow SVG URLs | `/en-US/static/app/agentsec/flows/*.svg` has no `@build` segment at all — a second cache-identity gap. Static diagrams, so the consequence is cosmetic. Documented, not fixed. |
| `learner_path.xml`, `nav/default.xml` | The Simple XML `script` declaration and the 13-entry guided nav are unchanged, as required. |

## Tests

**Added**

* `tests/unit/test_static_cache_identity.py` — 6 tests. Lock matches current
  assets and `app.conf`; the build-3 digest is pinned and the current digest
  differs; history never reuses a build or a digest; a changed asset under an
  unchanged build is detected and the error names the fix; the app build is not
  the product version; the digest covers every file under `appserver/static`.
* `tests/security/test_locale_safe_navigation.py` — 7 tests. No hard-coded
  locale in Splunk-rendered content; locale prefixing cannot duplicate;
  Home and Arena reach Your Path without a locale; all 32 catalog hrefs are
  relative; nav uses view names; the Attack Service `/en-US/` contract is intact.
* `tests/unit/test_guided_learning_generator_preserves_path_js.py` — 2 tests.
  `write_path` is idempotent against the committed asset and preserves the
  lifecycle and styling markers; the catalog covers every guided workshop.

**Modified** — `tests/splunk/test_lab_{agent_delegation,memory_security,rag_context}_dashboard.py`.
Each asserted `/en-US/app/agentsec/open_attack?path=/labs/<LAB>`. Updated to the
corrected link and strengthened with a negative assertion that the localised
form is absent. The query string these tests exist to guard is unchanged.

## Results

| Run | Result |
|---|---|
| Focused (new + modified) | 16 passed |
| Full offline suite | **1123 passed, 3 deselected**, exit code **0** |

```
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

Generator idempotence verified separately: re-running the three generators
leaves `git diff` byte-identical, and `scripts/static_cache_identity.py --check`
exits `0` afterwards.

### Correction during verification

`6981660` was pushed with `viz_guide_shell` missing from
`ws_agentsec_mastery.xml` and `learning/academy/mastery.definition.json`. The
`build_*_dashboard.py` scripts rebuild a definition from scratch and drop the
guide shell that `apply_guided_learning.py` adds, so `apply_guided_learning.py`
must run last; I ran them in the wrong order while checking idempotence.
`tests/splunk/test_guided_learning.py` caught it. Repaired in `f8d92dd` by
regenerating in the correct order. Both files now differ from the pre-task
baseline `2495ee9` only by the locale rewrite.

## Evidence classification

UNIT TESTED. These are repository contracts. The lock file proves nothing about
a deployed URL, and no browser request has been made against the new app build.
Only live verification against the running Splunk can change this verdict to
FIXED.
