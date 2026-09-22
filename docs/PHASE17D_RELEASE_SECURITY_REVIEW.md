# Phase 17D — Release security review

Architecture freeze held. Launch with extra `profile` field: HTTP 400 `unknown_fields` ERROR (not DENY).

MCP ATTACK vs RETEST (release smoke): CTRL-MCP-001 ALLOW vs DENY on independent run.ids. RETEST profile `defended`.

Secrets: `.env` gitignored and untracked. No PEM private keys or cloud key prefixes found in a repo content grep. `.env.example` contains **lab defaults** only.

Attack Service remains unauthenticated localhost. No remote-access feature added.

No new detector. No schema bump.

Failure injection: stopping Attack Service made `/health` unreachable (URLError); after `docker start`, HTTP 200. That is infrastructure, not a control decision.

**BLOCKER/HIGH security findings this phase:** none unresolved.
