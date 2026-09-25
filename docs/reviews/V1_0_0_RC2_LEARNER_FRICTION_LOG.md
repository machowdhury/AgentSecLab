# AgentSec v1.0.0-rc2 — learner friction log

**Reviewed commit:** `d38d33f327b728e469b84032553673dfe7ee9c37`  
**Date:** 2026-09-24  
**Mode:** assessment only. No remediation.

Chronological friction as an external learner following shipped docs.

| STEP | PERSONA | EXPECTED | ACTUAL | WORKAROUND REQUIRED? | DOCUMENTED? | SEVERITY |
|------|---------|----------|--------|----------------------|-------------|----------|
| Discover GitHub | A | Repo description matches README: educational range, not a detection product | Public description: “observe, detect, investigate, defend, and validate AI-agent security.” README is tighter. | Read README immediately | README yes; GitHub blurb no | MEDIUM |
| 60-second README | A | How long will this take? | Effort is in `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` / `curriculum.json`, not README | Open matrix | Partial | LOW |
| Clone | A | `git clone` then docs | Shallow clone of public repo succeeded; no `.env` in tree | `cp .env.example .env` | YES | LOW |
| `.env` | A | Know which values matter | Lab defaults include Splunk password and HEC token labeled as lab defaults | Copy example once | YES | INFORMATIONAL |
| Preflight | A | Script tells PASS/FAIL | Script exists; this review did not start a second compose project | Use existing stack | YES | LOW |
| First boot | A | Clean VM proof | RC1 and this review: **not clean-room**. Existing Docker volumes reused. | Accept PARTIAL | YES (`KNOWN_LIMITATIONS`, RC1 reproducibility) | MEDIUM |
| Splunk login | A | Credentials obvious | Password is `.env` `SPLUNK_PASSWORD`; Academy URL 303 to login | Read QUICKSTART table | YES | LOW |
| Academy Home | A | Where do I start? | START tab + primary PI link. ORIENT is a separate tab; advanced path may skip it | Open ORIENT | YES | LOW |
| LIVE vs REPLAY | A/B | Understand empty REPLAY tables | Documented: fresh index may lack specimens. Beginner may still treat empty as DENY | LIVE launch + Search | YES | MEDIUM |
| First PI launch | A | Evidence READY | Launch JSON: `evidence_state=WAITING_FOR_EVIDENCE`, `hec.ok=false`, `otlp.ok=true`, local 22 events. Splunk later `dc(_raw)=22` | Wait / Search anyway | Partial (WAITING_FOR_EVIDENCE + HEC≠completeness) | MEDIUM |
| Copy run.id | A | One obvious ID | PI is one id. Memory/Capstone need retrieve/write/recall. Memory copy buttons still mix generic “Copy” vs labeled write | Follow labels | Partial | LOW |
| Splunk Path A | B | Hunt without answers | Ten-tab labs put solutions in later tabs; Path B still visible. Capstone uses four tabs. Mastery states Studio cannot hide Path B | Discipline | YES as limitation | MEDIUM |
| Execution language | C | REQUEST≠ALLOW≠INVOKED≠COMPLETED | Capstone source + ToolRegistry docstring are precise. Home, RAG/Memory Attack UI, and most workshops still say handler count is authoritative execution/non-execution | Ignore overclaim; use mcp.started/completed | Capstone yes; rest no | HIGH |
| Rebuild after pull | A | `lab-up` enough | QUICKSTART: `--build` after Attack UI/source changes. This stack’s Capstone HTML still served pre-remediation copy (“handler count remains the execution authority”) | `./scripts/lab-up.sh --build` | YES | MEDIUM |
| Q-RUN / Q-DENY | B | Validated hunts | Disabled Phase 2 placeholders. CHANGELOG still lists them as packaged hunts | Use Studio Path B + `Q-RUN-EVENTS` | Inventory yes; CHANGELOG misleading | LOW |
| Mastery | A | Test understanding | Challenges are strong; answers sit on the same dashboard | Attempt Path A first | YES | MEDIUM |
| Independent operation | A | Finish without tribal knowledge | Possible if learner follows QUICKSTART + Home + LIVE labs. Clean-room, rebuild, and execution-vocabulary gaps remain | Instructor/docs | Partial | MEDIUM |
