# Component provenance workshop — implementation and independent review

DOCUMENTED / SIMULATED packet. Ollama pin debt is recorded and NOT RESOLVED. No digest was measured, so none was written into `docker-compose.yml`.

ATTACK and RETEST share `ollama/ollama:latest` plus `lookup_customer_tier`. ATTACK ALLOW is the packet-only reason `vulnerable_profile_fail_open:known_component_treated_as_grant`. RETEST DENY reason `provenance_is_not_a_grant` is absent from `authorize.py`. BASELINE says the Flask pin did not authorize `lookup_policy`.

Scanner and garak sentences stay non-authorization. Schema 1.9.0 and ExternalEvidence 1.0.0 unchanged.

Focused registration tests: 51 passed. Full offline suite: 1059 passed, 3 deselected, 9.80s.

## Independent review

The workshop does not convert inventory, a pin, a scanner finding, or an evaluation into a tool decision. Leaving `latest` in place is the safe choice because a guessed digest would be fabricated evidence.

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured. LOW 2: Ollama pin remains accepted debt.

Verdict: GO — COMPONENT PROVENANCE WORKSHOP VALIDATED FOR THE DOCUMENTED PACKET.
