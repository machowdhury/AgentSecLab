# Batch 5 review pack

| File | Contents |
|---|---|
| `LEARNER_ACCEPTANCE.md` | 30–45 min facilitated task script, automated browser results (not a usability study), defects found |
| `PILOT_PROTOCOL.md` | Five-person pilot protocol. **Status: NOT CONDUCTED** |
| `COVERAGE_MATRIX.md` | Traceability for the repo's 32 labs, 10 `CTRL-*` controls and the 17 vision subjects. The requested "30 controls" list was not available, see §0 |
| `NEXT_10_LABS.md` | Ten missing hands-on exercises, scored and ranked |
| `STABILITY_FINDINGS.md` | KV_MODE compatibility, bridge trust boundary, verifier lifecycle, cold-start risks |
| `learner_walkthrough.json`, `live_lab_sweep.json`, `kvmode_unbound.json`, `kvmode_dashboards.json` | Raw evidence |

Scripts added: `scripts/loan_desk_learner_walkthrough.py`, `scripts/live_lab_sweep.py`, `scripts/spl_compat_unbound.py`,
`scripts/spl_compat_dashboards.py`. Test added: `tests/test_loan_desk_stability_probes.py` (6 strict xfails that pin known defects).
No product code, Splunk configuration, Docker object or develop-tree file was changed in Batch 5. Side effects: the live sweep added 21 runs to the lab's Splunk index and the walkthrough added one explore, attack and retest run (all additive, via the public launch/mission APIs).
