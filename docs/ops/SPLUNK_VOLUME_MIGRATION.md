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

## 3. Storage inventory (read-only, from `scripts/splunk_volumes.py inventory`)
The tool's event count (a bucket's `Sources.data` header) reproduced two known truths exactly before it was used on anything new: 2,036 events in 60 buckets and 56 events. Pairing of `var` with `etc` is by creation time, which is a heuristic (one container creates both, within the same second).

### EC2 host: 17 Splunk `var` volumes and 17 `etc` volumes, **all orphaned** (no container exists)
| var / paired etc | Created | Splunk | `agentsec_telemetry` | Time range | Notes |
|---|---|---|---|---|---|
| `d68af7d0` / `815befad` | 2026-10-02 12:51 | 10.2.6 | **618 events**, 20 buckets (1 hot) | 2026-09-12 to 2026-10-08 | AgentSec's largest history; 5.1 GB, 1.8 GB of it Splunk internal indexes; **HEC plain HTTP**; admin password lost (its `.env` was deleted) |
| `6af3c444` / `d5bbacc5` | 2026-10-02 04:37 | 10.2.6 | **146 events**, 4 buckets | 2026-10-02 | same configuration |
| `5d84d1dd` / `0c57ba1a` | 2026-10-23 15:12 | 10.2.6 | 0 | none | the `v1.1.0` clean install; empty |
| `c49003f2`/`82b6c212`, `bab086e2`/`5cf5249e`, `7111fcdb`/`8fd63001` | 2026-10-02 | 10.2.6 | 0 | none | empty AgentSec-era installs |
| `e2b1fdf0` / `af4d1a22` | 2026-08-15 | 10.2.6 | none (`acme_agentic_telemetry` 77,607 events and `security` 19,460) | 2026-08-15 to 2026-10-02 | another project's index and schema; 8.1 GB |
| `23b984`/`e4568e`, `b6362c`/`ac3999`, `822e4d`/`fd15e9` | 2026-07-28 to 08-15 | 9.2.1 and 10.2.6 | none (`acme_agentic_telemetry` 624 / 181 / 12 events) | July to August | other project |
| seven 2026-07-09 to 07-29 pairs | 2026-07 | 9.2.1 | none | n/a | Splunk internal data only; the largest (`51958c6b`) is 4.7 GB |
AgentSec's own retained history on this host is **764 events** (618 + 146).

### Mac: the live lab and orphans
| var / paired etc | Created | Splunk | `agentsec_telemetry` | Time range | State |
|---|---|---|---|---|---|
| `f2323678` / `f5794832` | 2026-10-20 | 10.2.7 | **3,628 events**, 3 buckets | 2026-09-11 to 2026-10-23 | **LIVE** (container `agentsec_splunk`), anonymous, **HEC HTTPS** |
| `0aa27f8f` / `8f86409c` | 2026-09-12 | 10.2.7 | **2,036 events**, 60 buckets | 2026-09-12 to 2026-10-09 | orphaned; backed up (Batch 9) |
| `65a0bd8b` / `ca420456` | 2026-09-11 | 10.2.7 | **56 events** | 2026-09-11 to 2026-09-12 | orphaned; backed up |
| five `netspout*` and unlabelled pairs | 2026-10-03 to 10-09 | 10.2.7 | none (other project's indexes) | n/a | orphaned; not ours |

## 4. Recommendation: which dataset becomes active
**EC2: start clean on named volumes. Do not attach any old dataset to the active Splunk.** Reasons, from the inventory:
1. **A hard configuration conflict.** Every EC2 `etc` volume, including today's, has the HEC input on **plain HTTP (`enableSSL = 0`)**; the branch, the OTel collector and the Mac run **HTTPS**. HEC settings apply only when `etc` is first created, so attaching an old `etc` would leave Splunk on HTTP while the collector expects HTTPS and ingestion would fail.
2. **The admin credential is gone.** The old `etc` volumes hold password hashes whose source `.env` was deleted at 14:46 on 2026-10-23. Attaching one needs a credential reset first.
3. **The history is small and fully archivable.** 764 events. Raw events can be exported from a read-only throwaway Splunk on a **copy** (the Batch 9 method, `docs/reviews/batch9/specimen_recovery.json`) and kept as JSONL evidence, which carries no configuration baggage.
4. **They are not mergeable.** Each volume is a separate Splunk instance (own users, GUID, HEC state, schema generation). Splunk cannot merge two instances' indexes, and copying buckets between instances is not a supported way to combine them. **No two datasets are to be combined.** If more than one history is wanted, keep them as separate archives or export each to JSONL.
5. Disk: attaching the 5.1 GB volume makes the active Splunk carry 1.8 GB of stale internal indexes.

If history *must* be live on EC2 anyway, the only candidate is `d68af7d0` / `815befad` (618 events, 2026-09-12 to 2026-10-08, Splunk 10.2.6). It additionally needs: an admin credential reset, `enableSSL = 1` with the current certificate, the current HEC token, a version check against the target image, and a verification pass on a copy first. Treat it as a separate project; it is not part of the cutover.

**Mac: migrate the live lab in place** (3,628 events, already HTTPS, current schema) using procedure A. The two orphaned September volumes stay as they are (already backed up; their events are already re-seeded as REPLAY specimens in the repository).

## 5. Procedures
All commands are run by the deployment owner, with the lab paused and nothing else touching the host. Space needed for a copy is the size of the sources (check `docker system df` and the filesystem first; on EC2 only after the disk gate in `docs/ops/EC2_ACCEPTANCE_CHECKLIST.md`).

### A. Migrate a live legacy lab (anonymous) to named volumes, keeping its data
**Explicit volumes (Mac example; substitute your own from `inventory`):** source etc `f5794832…`, source var `f2323678…`; destination `<project>_splunk_etc` and `<project>_splunk_var` (project is the compose project name, normally the repository directory name lower-cased).
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

### B. EC2: start clean on named volumes (recommended)
No copy is needed. After the storage and snapshot gates, `./scripts/lab-up.sh` finds no Splunk container, so the guard passes and Compose creates empty `<project>_splunk_etc` and `<project>_splunk_var` with the new password, HTTPS HEC and current app. **The 17 orphaned var/etc pairs are left exactly as they are**; nothing attaches or deletes them. Afterwards, the operator may archive what matters (section C) and decide separately about disk.

### C. Archive an old dataset's events without attaching it
On a host with room for a **copy**: copy the two volumes (as in A, to scratch volumes), start a throwaway Splunk on the copies **with no published ports and a separate project name**, export the events with the Batch 9 exporter, record counts and time ranges, compare them to `inventory`, and remove only the scratch volumes. Store the JSONL with its SHA-256. This is how the Batch 9 specimens were recovered.

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

## 8. Decisions needed from the deployment owner
1. Approve **start clean** on EC2 (section 4), leaving the old pairs in place and archiving AgentSec's 764 events later; or choose the separate project of attaching `d68af7d0`.
2. Approve migrating the Mac's live lab with procedure A, and when (it pauses Splunk for the length of the copy and one recreate).
3. Retention: how long the 17 EC2 and the Mac orphans stay, and who may approve their deletion. Until then, nothing is deleted.
4. Whether to adopt the `docker-compose.rollback.yml` pattern as a committed template.
