# Documentation index

The documentation follows the [Diátaxis](https://diataxis.fr/) split: **tutorials** (learn by doing), **how-to guides** (accomplish a task), **reference** (look something up) and **explanation** (understand why). Everything in the first four sections describes RC2 (release candidate 2, a restricted single-user beta), verified on Ubuntu 24.04 x86-64 with Docker Engine only. New here? Read the [README](../README.md), then [your first hour](LEARNER_GUIDE.md#your-first-hour).

## Tutorials: learn by doing

| Guide | What you do |
|---|---|
| [Learner guide: your first hour](LEARNER_GUIDE.md#your-first-hour) | Open the Academy, sign in, take the beginner path, finish a first workshop, run BASELINE, ATTACK and RETEST, investigate, and read a finding |
| [A practitioner learning path](LEARNER_GUIDE.md#12-a-practitioner-learning-path) | Ten stages through the 33 workshops, with an evidence template |
| [AI Security Assurance](AI_SECURITY_ASSURANCE.md) | Read your first Security Assurance finding and compare it with its retest |

## How-to guides: accomplish a task

| Task | Guide |
|---|---|
| Install on your own computer (LOCAL) or a remote server (REMOTE) | [Installation and deployment](INSTALLATION_AND_DEPLOYMENT.md) |
| Launch an attack, read a decision, investigate a run, compare baseline and retest | [Learner guide](LEARNER_GUIDE.md) |
| Run a workshop for a class | [Instructor guide](INSTRUCTOR_GUIDE.md) |
| Fix a problem | [Troubleshooting](TROUBLESHOOTING.md) and [installer failures](TROUBLESHOOTING.md#installer-common-failures-and-exact-recovery) |
| Play the three CTF challenges | [CTF](CTF.md) |

## Reference

| Topic | Guide |
|---|---|
| All 33 workshops: mode, how to start, expected outcomes, evidence, completion, reset | [Workshop catalog](WORKSHOP_CATALOG.md) |
| Installer settings, platform status, upgrade, backup, uninstall | [Installer](INSTALLER.md) |
| HTTPS gateway, certificates, authentication, roles | [Gateway](GATEWAY.md) |
| Bundled Splunk, search access, kernel note | [Splunk integration](SPLUNK_INTEGRATION.md) |
| Assurance statuses, rules, metrics, framework mapping | [AI Security Assurance](AI_SECURITY_ASSURANCE.md) |
| Integrated tools: version, licence, use, limits | [Security tools](SECURITY_TOOLS.md) · [third-party notices](../THIRD_PARTY_NOTICES.md) |
| EVAL, Risk and Governance semantics | [Evaluation and risk](EVALUATION_AND_RISK_GUIDE.md) · [Governance](GOVERNANCE_GUIDE.md) |
| The Loan Desk mission | [Loan Desk mission](LOAN_DESK_MISSION.md) |
| What is not claimed or not tested | [README: compatibility and limits](../README.md#compatibility-and-limits) and [Installation and deployment: where this has been verified](INSTALLATION_AND_DEPLOYMENT.md) |

## Explanation

| Topic | Guide |
|---|---|
| Why it matters per role, trust boundaries, LLM versus deterministic decisions, what is not claimed | [Benefits, architecture and security](BENEFITS_AND_SECURITY_ARCHITECTURE.md) |
| Diagrams and product screenshots | [Visual guide](VISUAL_GUIDE.md) |
| Live, recorded and simulated evidence | [Live versus replay](LIVE_VS_REPLAY.md) |
| How the pieces fit (short, internal) | [Architecture](ARCHITECTURE_GUIDE.md) |

## Historical and legacy (not the supported path)

These describe the earlier multi-port, plain-HTTP flow of release v1.2.0 or earlier proposals. They are kept for provenance and carry a note saying so. Do not mix that flow with the installer on one machine.

| Page | What it is |
|---|---|
| [Legacy multi-port flow](LEGACY_MULTI_PORT_FLOW.md) | The v1.2.0 flow, moved out of the README |
| [Getting started](GETTING_STARTED.md) · [Quickstart](QUICKSTART.md) · [Remote access](REMOTE_ACCESS.md) · [Prerequisites](AGENTSEC_PREREQUISITES.md) | The v1.2.0 beginner path, startup, remote and prerequisites pages |
| [Legacy Splunk Academy guide](LEGACY_SPLUNK_ACADEMY_GUIDE.md) · [Known limitations](KNOWN_LIMITATIONS.md) | The v1.0 and v1.1 reading path; the v1.1.0 limitations list (Splunk dashboard accessibility), not an RC2 list |
| [v1.2.0 release notes](RELEASE_NOTES_v1.2.0.md) · [Full project reference](PROJECT_REFERENCE.md) · [HTTPS ingress proposal](HTTPS_INGRESS_PROPOSAL.md) · [Security boundary](SECURITY_BOUNDARY.md) | Past release notes, the earlier long README, a superseded proposal, the v1.0 boundary note |

Acceptance and validation records are internal development evidence and are not published; the README and installer reference summarise them.
