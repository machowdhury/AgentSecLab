# Credential lifetime workshop — independent implementation review

Reviewed the packet, absence search, curriculum checkpoint, and `tests/splunk/test_credential_lifetime_workshop.py` after the files were written.

## Checks

- ATTACK and RETEST share the expired reference and the privileged tool request.
- RETEST denies and does not infer execution.
- BASELINE uses a different, current reference and an in-scope tool. The packet says that reference did not itself authorize the tool.
- Approval expiry and credential expiry are different timestamps.
- Rotation and revocation enforcement are NOT DEMONSTRATED.
- `expired_credential` is absent from `authorize.py`.
- Schema 1.9.0 and ExternalEvidence 1.0.0 are unchanged.
- No PEM, JWT-shaped, or live secret marker is in the packet.

## Not measured

Indexed credential lifetime was not exported. The search labels it NOT OBSERVED. Browser and screen reader: NOT TESTED.

## Findings

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured for this view.

## Verdict

GO — CREDENTIAL LIFETIME WORKSHOP VALIDATED FOR THE SIMULATED PACKET. Continue to RAG purpose authorization.
