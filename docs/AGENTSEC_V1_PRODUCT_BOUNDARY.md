# AgentSec v1.0 product boundary

**Product version:** 1.0.0-rc1 (see `pyproject.toml` `1.0.0rc1` / Splunk `app.conf` `1.0.0-rc1`)  
**Telemetry schema:** 1.9.0 (independent)  
**Status:** release-candidate documentation. Not a production certification.

## What AgentSec v1.0 IS

Validated against the implementation:

| Description | Support |
|-------------|---------|
| Hands-on agentic-security learning environment | YES — published Academy + runtime labs |
| Splunk-centered security investigation academy | YES — Dashboard Studio + Search |
| Controlled vulnerable / defended agent experiments | YES — profiles selected server-side from specimens |
| Purple-team learning range | YES — ATTACK → DEFEND → RETEST → COMPARE → PROVE on LIVE labs |
| Evidence-driven security reasoning environment | YES — LIVE/REPLAY, Path A/B, claim classification |

## What AgentSec v1.0 IS NOT

| Description | Status |
|-------------|--------|
| Production security gateway | NOT |
| Production PDP / authorization product | NOT — reference controls in a lab runtime |
| Commercial SIEM content pack | NOT — educational app + hunts |
| Full A2A implementation | NOT — identity/delegation lab is educational, not a protocol stack |
| OAuth / OIDC / SPIFFE identity platform | NOT |
| General-purpose AI agent framework | NOT |
| Production RAG platform | NOT — fixture retriever |
| Production memory system | NOT — in-process educational memory |
| Autonomous SOC | NOT |
| Certification program | NOT — Mastery Check is unscored |
| Production attack platform | NOT — closed localhost launcher |
| Multi-tenant SaaS | NOT |
| Progress persistence / leaderboard | NOT |

## Security statement

AgentSec intentionally contains vulnerable educational behavior. It is designed for controlled local learning. It should not be exposed directly to untrusted networks. Splunk observes experiments; it does not become the enforcement engine merely because evidence is indexed there.

See [SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md) and [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
