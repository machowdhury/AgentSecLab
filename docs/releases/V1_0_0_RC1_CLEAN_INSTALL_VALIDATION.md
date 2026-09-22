# AgentSec v1.0.0-rc1 — clean install validation

**NOT FULLY CLEAN-ROOM VALIDATED.** This workstation already had Docker images, Splunk volumes, and `.env`.

| Step | Command | Expected | Observed | Result | Docs |
|------|---------|----------|----------|--------|------|
| Landing | open README | what/how/start | README answers what, start, LIVE/REPLAY, limits | PASS | README |
| Prerequisites | `./scripts/lab-preflight.sh` | PASS/WARN/FAIL | Host Docker required; sandbox `docker info` is not authoritative | PARTIAL | QUICKSTART |
| `.env` | `cp .env.example .env` | exists, gitignored | `.env` present, `git check-ignore` hits `.env` | PASS | QUICKSTART |
| Start | `./scripts/lab-up.sh` | READY | Stack already up; `--build` used in 17D; `--refresh-app` restaged app 1.0.0-rc1 | PARTIAL (not first boot this session) | QUICKSTART |
| Health | curl login/HEC/Attack/AcmeBank | 200 | OBSERVED 200 | PASS | OPERATIONS |
| Academy | Home URL | loads | Playwright HTTP 200 | PASS | README |
| First LIVE | PI ATTACK | new run.id | RC1 pair MEASURED | PASS | QUICKSTART |
| First Search | quoted run.id | dc(_raw) match | PI 22=22 | PASS | TROUBLESHOOTING |

Hidden developer knowledge required for this session: existing Splunk volume with historical REPLAY ids. **A brand-new Splunk volume may have empty REPLAY tables.** Documented in KNOWN_LIMITATIONS / LIVE_VS_REPLAY. Not scored as a failed install of LIVE.

Documentation source for every learner command: README + QUICKSTART. No undocumented compose flags required.
