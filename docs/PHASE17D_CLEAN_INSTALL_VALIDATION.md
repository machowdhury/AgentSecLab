# Phase 17D — Clean install validation

**NOT FULLY CLEAN-ROOM VALIDATED.**

What was done:

- `./scripts/lab-up.sh --build` rebuilt `agentseclab-attack_service` and `agentseclab-acmebank` from this repository.
- Attack Service container recreated; template in container contains REQUIRES REVALIDATION.
- `./scripts/lab-up.sh --refresh-app --no-wait` restaged `splunk_app/agentsec` into `splunk_app_agentsec`. Volume `app.conf` version **1.0.0-rc1**.
- Existing Splunk indexed data and Ollama model volume were **not** destroyed.

What was not done:

- Empty Docker / new VM / new user home
- `docker compose down -v` full wipe
- Fresh clone on a second machine

A learner following README on a new workstation still depends on Docker image pulls and first Splunk boot (observed 10–20 minutes). That path is documented, not executed here as a clean room.
