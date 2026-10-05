# Splunk static-asset cache identity and locale-relative navigation

## What is it?

Two deployment contracts for the AgentSec Splunk app:

1. **Cache identity.** If a file under `splunk_app/agentsec/appserver/static/`
   changes, the URL Splunk serves it from must change too.
2. **Locale ownership.** Splunk owns the locale segment of its own URLs.
   AgentSec link text must not contain one.

## Why does it exist?

Both were discovered from a live defect. Your Path rendered its static HTML but
the browser-local progress UI never mounted, even though the JavaScript on the
EC2 host was byte-identical to the fixed version in the repository.

### Cache identity

Splunk Classic Simple XML does not put custom dashboard JavaScript into a
`<script src>` tag. `dashboard_1.1.js` reads the `script` attribute, resolves a
URL, fetches it with `jQuery.ajax({dataType: "text", cache: true})`, and runs
the response through `eval`. The resolved URL is:

```
/<locale>/static/@<splunk build>.<push version>-<app build>/app/agentsec/<file>
```

* `<splunk build>` and `<push version>` come from Splunk itself.
* `<app build>` is `[install] build` in the app's `app.conf`, read by
  `AppLocal.getBuild()`.

`<app build>` is the only segment AgentSec controls. It had been pinned at `3`
since commit `829de82` while `agentsec_learner_path.js` changed repeatedly. Every
deployment therefore shipped new bytes under a URL the browser had already
cached with `cache: true`. Nothing in the repository prevented that.

### Locale ownership

AgentSec link text hard-coded `/en-US/app/agentsec/...`. Splunk's
`Splunk.util.make_url` unconditionally prefixes the active locale onto a
root-relative path, so an already-localised path can be localised twice. That is
the shape behind the observed `/en-US//en-US/app/agentsec/learner_path`, which
returns 404. Verified against the live Splunk: `/app/agentsec/learner_path`
returns `303` to `/en-US/app/agentsec/learner_path` with the query string intact.

## How does it work?

`scripts/static_cache_identity.py` digests every file under
`appserver/static` (relative path plus per-file SHA-256) and compares the result
with `splunk_app/static_cache_identity.json`. The lock also records an
append-only history of `(app_build, assets_sha256)` pairs so a build number can
never be reused for different bytes. The lock lives outside
`splunk_app/agentsec/` so `scripts/splunk_app_init.sh` does not stage it into the
deployed app.

Locale handling is now simply the absence of a locale: AgentSec emits
`/app/agentsec/<view>` and lets Splunk redirect.

## Where does it sit in AgentSec?

Deployment and presentation, not the control plane. Neither contract makes an
authorization decision and neither produces telemetry.

## What is the trust boundary?

The browser. Everything here concerns content AgentSec hands to a user's browser
through Splunk. The browser cache is outside AgentSec's control, which is exactly
why the cache key has to be correct at deploy time rather than repaired later by
asking a learner to hard-refresh.

## What could an attacker control?

Nothing new. No input is parsed, no authority is granted, and `localStorage`
progress remains what it already was: browser-local learning state, never
evidence and never a control decision. The genuine risk is the inverse of an
attack: a security fix that silently fails to reach the browser, so a learner
sees stale behaviour and believes a defect still exists.

## What can go wrong?

* Changing a static asset without bumping `[install] build`. The lock test fails.
* Reusing a build number for different bytes. The history test fails.
* A generator overwriting hand-maintained code. This actually happened:
  `scripts/apply_guided_learning.py` emitted the whole of
  `agentsec_learner_path.js` from a stale template, so running it reverted both
  the styling work and the dashboard-ready lifecycle fix. The generator now
  splices in only the catalog it owns, and a test asserts idempotence.
* Running the generators in the wrong order. `scripts/build_*_dashboard.py`
  rebuild a dashboard definition from scratch and drop the guide shell that
  `scripts/apply_guided_learning.py` adds, so `apply_guided_learning.py` must
  run last. `tests/splunk/test_guided_learning.py` catches the mistake, which is
  why the suite has to be run after regenerating anything.
* `splunk_app/static_cache_identity.json` is a repository contract. It proves
  nothing about a deployed URL. Only an HTTP request to the running Splunk does.

## Release and deploy rule

Automatic enforcement stops at the repository boundary, so the deploy half is a
written rule:

1. Change a file under `splunk_app/agentsec/appserver/static/`.
2. Increment `[install] build` in `splunk_app/agentsec/default/app.conf`.
   Leave `[launcher] version` alone — the app build is a cache key, not the
   product semantic version.
3. Run `python3 scripts/static_cache_identity.py --write`.
4. Commit the asset, `app.conf`, and the lock together.
5. After deploying, request the versioned URL and confirm it carries the new app
   build and returns real JavaScript rather than Splunk's
   `/*--fallback--` placeholder.

## Known limitation

`src/agentsec/workshop_flows.py` serves the 31 workshop flow diagrams from
`/en-US/static/app/agentsec/flows/<name>.svg`, which has no `@build` segment at
all. Those are static diagrams rather than executable code, so the stale-cache
consequence is cosmetic. Recorded here, not fixed.

## What I should now be able to explain

1. Why `document.scripts` is empty on a Classic Simple XML dashboard that does
   load custom JavaScript.
2. Which part of the Splunk app-static URL AgentSec controls, and which parts
   Splunk owns.
3. Why identical bytes on disk did not mean identical bytes in the browser.
4. Why `[install] build` must not track the product semantic version.
5. What `splunk_app/static_cache_identity.json` proves, and what it does not.
6. Why the lock file is stored outside `splunk_app/agentsec/`.
7. Why `/app/agentsec/learner_path` is safer than `/en-US/app/agentsec/learner_path`
   inside Splunk, but not in Attack Service pages.
8. How a code generator can silently revert a committed security fix, and what
   test shape catches it.
9. Why "hard refresh" is a workaround for this class of defect rather than a fix.
10. What evidence would be required to call this FIXED rather than IMPLEMENTED.
