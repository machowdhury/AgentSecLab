# AgentSec v1.0 product boundary

**Tagged RC1:** `main` and annotated tag `v1.0.0-rc1` peel to `e6115b6d1c03a1672b4364e84748c7840671fbfc`. That baseline does not contain the L6–L10 academy.

**Current candidate:** `develop` and annotated tag `v1.0.0-rc2`. This is the L0–L10 academy. It is not final `v1.0.0`. Do not describe `develop` as v1.0.0-rc1.

**Version strings:** `pyproject.toml` says `1.0.0rc2`. Splunk `app.conf` says `1.0.0-rc2`. Those strings name this candidate. They do not move `main`.

**Telemetry schema:** 1.9.0 (independent)

**External evidence contract:** 1.0.0 (independent)

**Status:** educational lab documentation. Not a production certification. The “is not” list below still applies on `develop`. L10 and Mastery Check do not add a certification.

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
