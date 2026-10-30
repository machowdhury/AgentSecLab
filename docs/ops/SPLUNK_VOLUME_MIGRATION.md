# Splunk persistence: audit, named volumes, and a safe migration

**Status: DESIGN AND PROCEDURE ONLY. No volume has been migrated, copied, deleted, pruned or reattached by this work, and no container was restarted for it.** The tooling (`scripts/splunk_volumes.py`) only reads volumes (`:ro`) or prints text. Volume names are shortened to 8 hex characters.

## 1. Audit: where Splunk's state lives
| Path in the container | Holds | Before | After (this branch) |
|---|---|---|---|
| `/opt/splunk/var` | **indexed events** (buckets), fishbucket, KV store, search artifacts, internal logs | **anonymous** volume (the image only declares it as a `VOLUME`) | named `<project>_splunk_var` |
| `/opt/splunk/etc` | **configuration**: users and password hash, HEC input and its TLS setting, index definitions, licence state, `splunk.version` | **anonymous** | named `<project>_splunk_etc` |
| `/opt/splunk/etc/apps/agentsec` | the AgentSec app (views, `KV_MODE`, props) | named `splunk_app_agentsec`, **re-staged from the repository on every `up`** | unchanged |
| `/var/log/agentsec` | shared telemetry files | named `shared_telemetry` | unchanged |
| host `.env`, `.certs/` | admin password source, HEC token, HEC certificate | host files | unchanged |

**The defect.** An anonymous volume belongs to one container. `docker compose down` removes the container; the next `up` creates a *new* container with *new empty* volumes, and the old ones stay on disk, attached to nothing. Recreating a container in place (`up --force-recreate`) and stop/start keep them. Proven with a throwaway project (`tests/integration/test_volume_persistence_docker.py`, including the control that reproduces the loss).

### What each command does to Splunk's data
| Command | Containers | Named volumes | Anonymous volumes (legacy layout) | Splunk data |
|---|---|---|---|---|
| `lab-down.sh` (now `docker compose stop`) / `start` | kept, stopped/started | kept | kept, still attached | **safe** |
| `up -d --force-recreate <svc>` | replaced | kept, reattached | **kept, reattached** | **safe** |
| `lab-down.sh --remove-containers` (`docker compose down`) then `up` | removed | kept, reattached | **orphaned; a new empty volume is created** | safe with named volumes; **hidden with the legacy layout** (the script refuses) |
| `lab-down.sh --purge --yes-delete-all-lab-data` (`down -v`) | removed | **deleted** | deleted with the container | **destroyed** |
| `docker volume prune` / `system prune --volumes` | n/a | deletes unreferenced ones | **deletes orphans**, i.e. any "lost" history | **destroyed**; never run it on a lab host |

## 2. What changed in the product
- `docker-compose.yml`: `splunk_etc` and `splunk_var` are named volumes mounted at `/opt/splunk/etc` and `/opt/splunk/var` (the app volume stays nested under `etc`).
- `scripts/lab-down.sh`: default is **pause** (`stop`). `--remove-containers` runs `down` (named volumes kept) and **refuses** while Splunk still uses anonymous volumes. `--purge` needs `--yes-delete-all-lab-data`.
- `scripts/lab-up.sh`: a guard refuses to recreate a Splunk container that is still on anonymous volumes (it would attach new empty ones). `--fresh-splunk-data` is the explicit acknowledgement; the old volume is named in the warning and left in place.
- `scripts/splunk_volumes.py`: `inventory` (read-only), `verify` (read-only `diff -rq` plus per-index event comparison), `plan` (prints a migration script, runs nothing).
- Nothing reattaches an old volume automatically. Attaching one is always a deliberate, reviewed step.

**Operator caveats that come with persisted `etc`**
- `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN` and `SPLUNK_HEC_SSL` from `.env` apply **only when `splunk_etc` is first created empty**. Editing `.env` later does not change an existing Splunk. Rotating the admin password means changing it inside Splunk.
- An old `etc` volume masks the image's own `etc`. Upgrading `SPLUNK_IMAGE` across versions relies on Splunk's migration at start; take a backup first.

## 3. Storage inventory
`python3 scripts/splunk_volumes.py inventory` lists, read-only, every Splunk `var` and `etc` volume with its Splunk version, event counts and time ranges, whether a container uses it (ANONYMOUS, EMPTY, LIVE or orphaned) and, for volumes created together, a pairing by creation time (a heuristic: one container creates both within the same second). Run it before and after any change.

## 4. Recommendation: which dataset becomes active
**On a host whose old Splunk volumes you do not need live, start clean on named volumes and do not attach an old dataset to the active Splunk.** Reasons:
1. **HEC settings apply only when `etc` is first created.** An old `etc` volume keeps its own HEC mode (HTTP or HTTPS) and token; the OTel collector expects HTTPS, so attaching an old one can stop ingestion.
2. **The admin credential may be unknown.** An old `etc` holds password hashes; attaching one needs the original credential or a reset first.
3. **Instances are not mergeable.** Each volume pair is a separate Splunk instance (users, GUID, HEC state, schema generation); copying buckets between instances is not a supported way to combine them. Keep separate archives, or export each dataset's events to JSONL. **No two datasets are to be combined.**
4. **Disk.** An old `var` carries Splunk's own internal indexes.

If history must be live anyway, treat it as a separate project: reset the credential, set `enableSSL = 1` with the current certificate and HEC token, check the version against the target image, and verify on a copy first.

**To keep the data of a live legacy lab (anonymous volumes), migrate it in place** with procedure A.

## 5. Procedures
All commands are run by the deployment owner, with the lab paused and nothing else touching the host. Space needed for a copy is the size of the sources (check `docker system df` and the filesystem first; on a small cloud disk check free space first).

### A. Migrate a live legacy lab (anonymous) to named volumes, keeping its data
**Explicit volumes (substitute your own from `inventory`):** `<SRC_ETC>` and `<SRC_VAR>`; destination `<project>_splunk_etc` and `<project>_splunk_var` (project is the compose project name, normally the repository directory name lower-cased).
1. **Record.** `python3 scripts/splunk_volumes.py inventory | tee ~/agentsec-backups/inventory-before.txt`. Note the event counts of `agentsec_telemetry` and the user count.
2. **Back up both sources outside Docker, then verify the backup.**
   ```bash
   mkdir -p ~/agentsec-backups && chmod 700 ~/agentsec-backups
   for v in <SRC_ETC> <SRC_VAR>; do
     docker run --rm -v "$v":/src:ro -v ~/agentsec-backups:/out busybox:1.36 sh -c "cd /src && tar czf /out/splunk-$(date +%Y%m%d)-${v%${v#????????}}.tgz ."
   done
   gzip -t ~/agentsec-backups/splunk-*.tgz && shasum -a 256 ~/agentsec-backups/splunk-*.tgz | tee ~/agentsec-backups/splunk-backup.sha256
   ```
3. **Pause (do not remove) Splunk and the verifier.** `./scripts/loan_desk_verifier.sh stop` then `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env stop splunk`.
4. **Generate the plan and read every line.**
   `python3 scripts/splunk_volumes.py plan --src-etc <SRC_ETC> --src-var <SRC_VAR> --dst-etc <project>_splunk_etc --dst-var <project>_splunk_var --project <project> > migrate.sh`
   It refuses to reuse an existing destination, mounts sources `:ro`, **copies** (never moves) preserving owner `41812`, and ends with `verify`. Run it with `sh migrate.sh`.
5. **Verify (must print `VERIFIED` for both).** `diff -rq` identical and the per-index event and bucket counts equal. A mismatch is a stop.
6. **Switch Splunk onto the copies.** The existing container still points at the anonymous volumes, so `lab-up.sh` will refuse by design. Recreate in place with the new compose file:
   `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env up -d --force-recreate splunk` then `./scripts/loan_desk_verifier.sh start`.
7. **Verify live.** Splunk healthy; a real search `index=agentsec_telemetry | stats count` equals the recorded count; the admin can log in with the **existing** password; HEC settings and the dashboards load; `python3 scripts/learner_ready.py` passes. Then run the stop/start and `--remove-containers` then `lab-up.sh` cycles once and confirm the count is unchanged.
8. **Retain** the source volumes and backups untouched until the owner signs off in writing. Deleting them is a separate, later decision.

**Rollback (sources are never modified).** Stop Splunk, then recreate it on the original volumes using an override file:
```yaml
# docker-compose.rollback.yml  (put the real source volume names in)
volumes:
  legacy_etc: { external: true, name: <SRC_ETC> }
  legacy_var: { external: true, name: <SRC_VAR> }
services:
  splunk:
    volumes:
      - legacy_etc:/opt/splunk/etc
      - legacy_var:/opt/splunk/var
```
`docker compose -f docker-compose.yml -f docker-compose.local.yml -f docker-compose.rollback.yml --profile local --env-file .env up -d --force-recreate splunk` (service volumes merge by mount path, so these replace the named ones). Verify the count again. The destinations stay in place for another attempt. If a source were damaged, restore it from the verified `.tgz` into a **new** volume; never overwrite the original.

### B. Cloud host: start clean on named volumes (recommended)
No copy is needed. After checking free disk space and taking a snapshot, `./scripts/lab-up.sh` finds no Splunk container, so the guard passes and Compose creates empty `<project>_splunk_etc` and `<project>_splunk_var` with the new password, HTTPS HEC and current app. **Any orphaned var/etc pairs are left exactly as they are**; nothing attaches or deletes them. Afterwards, the operator may archive what matters (section C) and decide separately about disk.

### C. Archive an old dataset's events without attaching it
On a host with room for a **copy**: copy the two volumes (as in A, to scratch volumes), start a throwaway Splunk on the copies **with no published ports and a separate project name**, export the events with Splunk's search export, record counts and time ranges, compare them to `inventory`, and remove only the scratch volumes. Store the JSONL with its SHA-256.

### D. Never do these
`docker volume prune` or `system prune --volumes`; `down -v` on a lab with history; pointing two Splunk containers at one volume; editing files inside a volume; combining buckets from two instances; deleting a source volume before the migrated copy has been verified live and signed off.

## 6. Data verification checklist
- [ ] `inventory` before and after: same event counts, bucket counts and time ranges per index.
- [ ] `splunk_volumes.py verify` prints `VERIFIED` for etc and var.
- [ ] A live search count equals the recorded count; `dc(_raw)` equals the count (no duplicates).
- [ ] Admin login works with the existing credential; the user count is unchanged.
- [ ] HEC: `enableSSL = 1` (HTTPS), input enabled, ingestion of a canary event is searchable.
- [ ] `KV_MODE` in the deployed app is unchanged (compare with the repository).
- [ ] The workflows survive: stop then start, `up --force-recreate`, `--remove-containers` then `lab-up.sh`; the count is unchanged each time.

## 7. Tests that back this up
| Test | Proves |
|---|---|
| `tests/unit/test_splunk_persistence_contract.py` (21; 12 fail against the old files) | compose names the volumes; `lab-down.sh` pauses by default, refuses to orphan, needs two flags to purge; `lab-up.sh` guard blocks recreation over legacy volumes; the plan never deletes or modifies sources |
| `tests/integration/test_volume_persistence_docker.py` (6, need Docker) | with the real compose volume lines: state survives stop/start, recreate and `down` then `up`; only `down -v` removes it; control reproduces the original loss |
| `tests/integration/test_splunk_real_persistence.py` (opt-in) | a **real Splunk** keeps a marker user and an indexed marker event through the same three workflows |

## 8. Decisions for the deployment owner
1. Start clean (section 4) or migrate a live lab with procedure A, and when (A pauses Splunk for the length of the copy and one recreate).
2. Retention: how long orphaned volumes stay and who may approve their deletion. Until then, nothing is deleted.
3. Whether to adopt the `docker-compose.rollback.yml` pattern as a committed template.
