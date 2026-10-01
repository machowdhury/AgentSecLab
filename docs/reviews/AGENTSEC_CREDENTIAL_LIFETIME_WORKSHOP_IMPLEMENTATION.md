# Credential lifetime workshop — implementation

Status: one SIMULATED / REPLAYED workshop. Synthetic references only.

No OAuth deployment, PKI, private key, certificate, or secret.

ATTACK and RETEST present expired `sim-cred-expired-001` with `lookup_customer_tier` / `cust-001`. ATTACK ALLOW reason `vulnerable_profile_fail_open:expired_credential_accepted` is packet-only. RETEST DENY reason `expired_credential` is not in `authorize.py`. BASELINE uses current `sim-cred-current-001` with `lookup_policy` / `lending-basics` and ALLOW `tool_granted`. The note states the current credential did not itself authorize the tool.

Approval expiry `2026-10-01T16:05:00Z` is recorded separately from credential expiry `2026-10-01T13:00:00Z`.

Focused contracts after registration: 51 passed. Full offline suite: 1054 passed, 3 deselected, 9.66s.

Browser and screen reader: NOT TESTED. Deferred to the UI phase.

Codeguard credential rule: applied by using synthetic `sim-cred-*` references and rejecting PEM, JWT-shaped, AWS, and live-secret markers in the packet test. No credential value is stored.
