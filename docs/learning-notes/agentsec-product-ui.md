# AgentSec product UI (pre-Phase-14)

**What is it?** A shared information architecture and workshop shell for AgentSec Splunk so labs look like one security product instead of a list of `LAB-*` experiments.

**Why does it exist?** Security content outgrew a flat navigation bar and raw UUID form fields. Learners and SOC reviewers need human titles, canonical specimens, and evidence cards.

**How does it work?** Grouped Splunk nav collections. Home orients. Workshops keep LEARN→PROVE tabs. Hunt uses a dropdown whose values are still canonical run.id strings. Specimen pages bind those IDs as literals.

**Where does it sit?** Splunk app `agentsec` views and builders. Not the runtime PDP.

**Trust boundary?** Unchanged. UI presentation is not authorization.

**What could an attacker control?** Nothing new. Dropdown values are build-time constants.

**What can go wrong?** Treating dropdown labels as verdicts. Treating empty tables as SAFE. Sharing a hunt token with a custom text field and wiping the default.

**Telemetry?** None added. Schema stays 1.9.0.

**How will Splunk show it?** Home + collections + short XML labels + Investigate specimen.

**What control could change the result?** None. This phase does not change CTRL-* behavior.

**What test proves the logic?** `tests/splunk/test_agentsec_ui_shell.py`, `tests/splunk/test_agentsec_home_dashboard.py`, plus existing workshop dashboard bind tests.

## What I should now be able to explain

1. Why every `LAB-*` id must not be a top-level nav item.
2. How canonical specimen IDs reach a panel without a UUID text field.
3. Why Hunt is a dropdown and custom run.id is Search.
4. Why Submit is no longer part of canonical workshop initialization.
5. Why Goal Integrity visual grammar is not RAG/Memory evidence.
6. What LIVE vs SIMULATED must look like on a specimen card.
7. Why empty hunt rows are not SAFE.
8. Which two navigation layers a learner must distinguish.
9. What must not change when making a panel prettier (SPL, detectors, schema).
10. Why Phase 14 is still not started.
