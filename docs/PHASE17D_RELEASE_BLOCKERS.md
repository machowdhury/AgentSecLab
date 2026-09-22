# Phase 17D — Release blockers

Unresolved **BLOCKER:** 0  
Unresolved **HIGH:** 0

## MEDIUM (documented, not RC-blocking)

- Full `lab-ready.sh` including new Home/Mastery REST checks was not executed as one script in this session (classifier blocked the wrapper). Individual health URLs and Studio HTTP 200 were OBSERVED.
- Host re-run of `lab-preflight.sh` after the Docker-visibility fix was similarly blocked; sandbox run false-failed `docker info`. Script is intended to be run on the learner’s host.
- Capstone LIVE triple not reminted as release smoke (avoid replacing official historical ids). View loads.
- Path B visibility without a click (pre-existing Studio limitation).
- Not a clean-room OS install.

## LOW

- Historical `docs/PHASE*.md` remain; learners should start at README.
- Product PEP 440 string is `1.0.0rc1` in `pyproject.toml` vs `1.0.0-rc1` in Splunk `app.conf` (same candidate).
