# How to operate AgentSec v1.0

## What is it?

A documented start/stop/readiness path so someone who did not build AgentSec can run the Academy.

## Why does it exist?

Phase 17D is release operability, not a new attack domain.

## How does it work?

`lab-preflight.sh` → `.env` → `lab-up.sh` → `lab-ready.sh` → Academy Home → Attack Service → Search. Rebuild with `--build` because Attack Service Python is baked into the image.

## Where does it sit?

Operator scripts wrap Docker Compose. Splunk remains observation. AcmeBank remains enforcement.

## Trust boundary

Attack Service stays an untrusted localhost client.

## What could an attacker control?

If you publish ports beyond localhost, anyone who can reach :5001 can launch educational attacks. Do not do that.

## What can go wrong?

Stale images, HEC lost after Splunk restart, REPLAY ids missing on a fresh volume, indexing delay.

## Telemetry

Unchanged schema 1.9.0.

## Splunk

Academy Home default view.

## Control

None added.

## Test

`tests/unit/test_phase17d_release.py` proves docs/version consistency, not a clean-room install.

## What I should now be able to explain

1. Why `lab-up.sh --build` is required after Attack Service source changes.
2. Why READY is not searchable evidence.
3. What FULL RESET destroys.
4. LIVE vs REPLAY for a new Splunk volume.
5. Why `.env` must not be committed.
6. Product version vs schema version.
7. Why Attack Service must not be internet-exposed.
8. Where Path A happens.
9. What a missing Search row does not prove.
10. What v1.0.0-rc1 does and does not claim.
