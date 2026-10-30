# Legacy guide: the Splunk-based Academy Home (L0–L10)

> **Legacy: not the supported path. Legacy / historical.** This is the original v1.0 and v1.1 reading path, kept for provenance. It describes the Splunk Academy Home at port 8000 and the L0–L10 curriculum, which still work in the old flow. In RC2 learners use only the React Academy at `https://localhost/learn` and never open Splunk Web or the internal ports; start with the [README quick start](../README.md#quick-start-ubuntu-2404-docker) and the [Learner guide](LEARNER_GUIDE.md). Statements below about `main` or `v1.1.0` describe those earlier releases, not the current `main` (v1.2.0).


The L0–L10 academy is v1.1.0 on `main` and annotated tag `v1.1.0`. Tag `v1.0.0` is the previous release and was not moved. Tag `v1.0.0-rc1` is the older RC1 baseline and does not contain L6–L10. Tags `v1.0.0-rc2` and `v1.0.0-rc3` were not moved.

Use these pages in order:

1. [AGENTSEC_PREREQUISITES.md](AGENTSEC_PREREQUISITES.md) — host, Docker, Windows/macOS/Linux, hardware, security notes for setup.
2. [QUICKSTART.md](QUICKSTART.md) — preflight, what `lab-up.sh` does, how long to wait, READY versus DEGRADED, then L0.
3. [../README.md](../README.md) and [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md) — the academy after the lab is up.
4. [OPERATIONS.md](OPERATIONS.md) — stop, restart, and reset.
5. [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Docker and host failures.
6. [REMOTE_ACCESS.md](REMOTE_ACCESS.md) — a Linux server or cloud VM. Laptops stay on the localhost commands above.

After the lab is up, stay in Academy Home. The path is LEARN, launch or select a specimen, paste or select the run.id, read the SPL and the inline table, interpret, compare, conclude, continue. LIVE labs need a fresh run.id copied from Attack Service. Studio does not receive that id by itself. REPLAY workshops use the Investigate specimen. REPLAY is a teaching mode. It is not a fresh LIVE launch and it is not a weaker evidence rule.

A control decision is not execution. Execution is not a measured downstream resource change. An empty table is not DENY. HEC HTTP 200 is not the inline table.

Your path is the authoritative progress surface. Native Splunk navigation and Dashboard Studio workshops cannot read that browser list. The page should list the curriculum, the progress tally, and Reset learning progress. Arena is optional and comes after Mastery. It uses the same LIVE launchers and the same evidence rules. On Attack Service, the lab switcher and NEXT LAB stay on port 5001. Home and Search on that page use port 8000 on the same hostname.

After L5, the Splunk Defender Bridge is the REPLAY checkpoint before L6. See [SPLUNK_DEFENDER_BRIDGE.md](SPLUNK_DEFENDER_BRIDGE.md).

Do not follow historical `docs/PHASE*.md` files as the install path. Those remain provenance.


## Academy shell, Centers and tests (v1.2.0)

### Rebuild the Academy UI
```bash
sh scripts/build_academy_ui.sh   # needs Docker; runs the typecheck; writes src/agentsec/static/learn
```

### Run the tests
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test,ui]'
PYTHONPATH=src .venv/bin/python -m pytest
```
Browser tests need Chromium: run `playwright install chromium` or set `AGENTSEC_CHROMIUM`.

Problems: [Troubleshooting](TROUBLESHOOTING.md).
