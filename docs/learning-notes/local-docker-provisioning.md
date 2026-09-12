# Local Docker Splunk app provisioning

## WHAT IS IT?

An automatic copy of `splunk_app/agentsec` into a **writable Docker named volume**, mounted at `/opt/splunk/etc/apps/agentsec`, plus `lab-up.sh` / `lab-ready.sh`.

## WHY DOES IT EXIST?

Splunk Ansible `chown`s `/opt/splunk` at first boot. A `:ro` bind of the git app onto that path is EROFS. A read-write bind would `chown` the repository. Manual `cp` inside the container is not a local-dev workflow.

## HOW DOES IT WORK?

`splunk_app_init` (busybox) reads the repo bind at `/src` and writes volume `splunk_app_agentsec`. Splunk starts only after that copy exits 0. HEC/index remain `splunk_hec_init`. READY is `lab-ready.sh`, not “container running.”

## WHERE DOES IT SIT IN AGENTSEC?

Compose profile `local` only. External Splunk is a different path: operator installs the same app package and points HEC env at their endpoint.

## WHAT IS THE TRUST BOUNDARY?

Unchanged. This is packaging. Splunk still does not ALLOW or DENY loans.

## WHAT COULD AN ATTACKER CONTROL?

Not this volume. Credentials stay in `.env` (not committed). Init does not print passwords.

## WHAT CAN GO WRONG?

Re-running `docker compose up -d` while the stack is already up does **not** restage the app (init already exited 0). Use `./scripts/lab-up.sh --refresh-app`. Binding the repo `:ro` onto `/opt/splunk/etc/apps` again will EROFS.

## WHAT TELEMETRY SHOULD EXIST?

None new. Schema 1.0.0 unchanged.

## HOW WILL SPLUNK SHOW IT?

The AgentSec app and `ws_lab_pi_001` appear after a successful local boot, without a manual copy.

## WHAT CONTROL COULD CHANGE THE RESULT?

None. CTRL-INPUT-001 is unrelated.

## WHAT TEST PROVES THE LOGIC?

`tests/unit/test_splunk_app_init.py` copies into a temp dir. `tests/splunk/test_local_compose_provisioning.py` forbids the EROFS mount. Live READY is `./scripts/lab-ready.sh` after a real compose boot.

## What I should now be able to explain

1. Why `:ro` on `/opt/splunk/etc/apps` fails.
2. Why a RW bind of the repo is also wrong.
3. What named volume `splunk_app_agentsec` is for.
4. When `splunk_app_init` runs vs `--refresh-app`.
5. Why Splunk health is not the same as lab READY.
6. What `lab-ready.sh` checks.
7. How EXTERNAL Splunk is supposed to get the app.
8. Why this change must not edit validated SPL.
9. What `docker compose down` vs `down -v` does to the app volume.
10. Why first boot can take 10–20 minutes.
