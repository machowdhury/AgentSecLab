# AgentSec v1.0 security boundary

AgentSec **intentionally contains vulnerable educational behavior**. Use it on localhost for learning. Do not expose Attack Service or Splunk to untrusted networks.

## Educational vulnerable behavior

Security profiles include **vulnerable** (fail-open / overlay for ATTACK) and **defended** (RETEST). The browser does not choose the profile. Specimens map to server-owned `ExperimentContext`.

## Localhost assumptions

Compose publishes Splunk, HEC, AcmeBank, and Attack Service on **127.0.0.1**. Attack Service has **no authentication**. That is an educational boundary, not a product feature.

## Attack Service trust boundary

The launcher is an **untrusted client** of AcmeBank.

Allowed launch JSON fields only: `lab_id`, `specimen_id`, `mode`, `execution`.

The browser cannot:

- choose an arbitrary security profile
- submit grants, tools, scopes, or SPL
- mutate `coded_policy()`
- execute Search

Unknown and authority-like fields return **ERROR** (`unknown_fields`), not a control DENY.

## Server-owned fields

`ExperimentContext` (profile, grants, experiment id, schema, workflow) is constructed on the server from allowlisted labs/specimens. ATTACK overlay must not leak into RETEST.

## Tool grants and coded policy

`CTRL-MCP-001` / `coded_policy()` is the tool PDP. OBSERVE classifiers (RAG/memory input) are not ALLOW. Splunk hunts are not grants.

## Splunk’s role

Observation, indexing, investigation, packaged detections (educational, DET-MCP-001 disabled by default). **Splunk is not the PDP.**

## Telemetry

OpenTelemetry export can fail independently of a successful tool decision. Launch may report WAITING_FOR_EVIDENCE honestly.

## Secrets

`.env` holds lab Splunk password and HEC token. Do not commit `.env`. Do not return secrets to the browser. Screenshot/docs must not capture live non-lab credentials.

## Production limitations

Not multi-tenant. Not OAuth/OIDC/SPIFFE. Not a production gateway. Regex input control is educational. RAG uses exact-id fixtures. Memory is in-process. Identity authentication is not modeled as a real IdP.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) and historical [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md) (Phase 1A contract).
