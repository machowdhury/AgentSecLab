# Gate 1 deployment plan (AcmeBank only)

State before (read-only inspection, 2026-10-22):
- Compose project `agentseclab`; config files = main tree docker-compose.yml + docker-compose.local.yml (+ .env). Develop tree is only *read*.
- Running: agentsec_acmebank (image agentseclab-acmebank:latest = b69e230c4a46), attack_service, splunk, otel_collector, ollama. All healthy.
- AcmeBank talks to HOST Ollama (host.docker.internal:11434); host models: llama3.2:latest a80c4f17acd5, llama3.2:1b, mistral.
- Volumes (none removed or recreated): agentseclab_shared_telemetry, agentseclab_ollama_models, agentseclab_splunk_app_agentsec; bind ./artifacts.

Operations (exactly these):
1. docker tag agentseclab-acmebank:latest agentseclab-acmebank:pre-batch3-b69e230c4a46   (rollback anchor)
2. docker build -f docker/Dockerfile.acmebank -t agentseclab-acmebank:batch3-a821a3a -t agentseclab-acmebank:latest  <feature worktree @ a821a3a>
3. (cd main tree) docker compose -p agentseclab up -d --no-deps --no-build acmebank

Affected: agentsec_acmebank container only (recreated, ~10 s outage on :5000). Not touched: splunk, otel_collector, ollama, attack_service, all volumes, .env, compose files.
Rollback: docker tag agentseclab-acmebank:pre-batch3-b69e230c4a46 agentseclab-acmebank:latest && (cd main tree) docker compose -p agentseclab up -d --no-deps --no-build acmebank
In-memory Loan Desk runs and the container's JSONL telemetry are lost/replaced with the container; indexed Splunk data is not affected.

## Second AcmeBank redeploy (final Gate 1-3 backend), 25a5f95
Same three operations and rollback as above. Before: agentseclab-acmebank:latest = image of commit a821a3a (tag batch3-a821a3a kept).
Attack Service container is NOT touched: the Academy mission was exercised with a host-process Attack Service on a spare
port talking to the Docker AcmeBank at 127.0.0.1:5000. Deploying the mission into the attack_service container needs its own approval.

## Batch 4 deployment (ba43da6): AcmeBank + Attack Service + additive Splunk app update
1. docker tag agentseclab-acmebank:latest agentseclab-acmebank:pre-batch4-463c765b9930
   docker tag agentseclab-attack_service:latest agentseclab-attack_service:pre-batch4-e5dc7f88bc9a
2. docker build -f docker/Dockerfile.acmebank -t agentseclab-acmebank:batch4-ba43da6 -t agentseclab-acmebank:latest .
   docker build -f docker/Dockerfile.attack -t agentseclab-attack_service:batch4-ba43da6 -t agentseclab-attack_service:latest .
3. Splunk app volume agentseclab_splunk_app_agentsec: restaged from this commit with scripts/splunk_app_init.sh (the supported copy), then views/nav reload through Splunk's _reload endpoints. Backup: splunk_app_volume_backup.tgz (95 files, props.conf identical to the repo before the change). No Splunk restart, no data volume touched.
4. (cd main tree) docker compose -p agentseclab up -d --no-deps --no-build acmebank attack_service
5. AGENTSEC_ARTIFACTS_HOST_DIR=<main>/artifacts scripts/loan_desk_verifier.sh start
Rollback: retag the two pre-batch4 images as :latest and rerun step 4; restore the Splunk app volume from the tarball (validated on a scratch volume); scripts/loan_desk_verifier.sh stop.
