# Code agent bounds — implementation and independent review

SIMULATED / REPLAYED. No GitHub credential. No external repository change. Dependency name is not installed.

ATTACK and RETEST submit `install_dependency` against delegated and approved `read_repository`. ATTACK ALLOW is packet-only. RETEST DENY `operation_not_granted` is not in `authorize.py`. BASELINE read is ALLOW `tool_granted` and is not install, pull-request, or deploy authority.

Focused tests: 51 passed. Full offline suite: 1060 passed, 3 deselected, 10.67s.

## Independent review

The packet keeps identity, authentication, delegation, approval, credential, and tool decision as separate labels. Pull request and deploy are not performed. Schema unchanged.

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured.

Verdict: GO — CODE AGENT BOUNDS VALIDATED FOR THE SIMULATED PACKET.
