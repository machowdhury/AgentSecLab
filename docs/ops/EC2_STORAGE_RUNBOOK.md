# EC2 storage runbook: snapshot, then expand the root volume

**Not executed.** This is a prepared procedure. Nothing here has been run, and each part needs the deployment owner's written approval (see `docs/ops/EC2_ACCEPTANCE_CHECKLIST.md`, gate G0). Identifiers are placeholders: `<region>`, `<instance-id>`, `<volume-id>`, `<snapshot-id>`.

## Facts this runbook relies on (measured read-only on the host)
- One EBS root volume: **100 GB gp3, 3000 IOPS, 125 MB/s, encrypted** (account default EBS key), `DeleteOnTermination = true`, availability zone `us-east-2c`. It holds the OS, `/var/lib/docker`, `/home` and the repository. There is no other data volume.
- Root is **partition 1 of `/dev/nvme0n1`, ext4, and it is the last partition**, so it can grow in place. `growpart`, `resize2fs`, `tune2fs` and `parted` are installed. 0 reserved blocks, so `df` free space is accurate. Mounted with `discard` (freed blocks are trimmed, which keeps snapshots smaller).
- `/` is 96 GB, 91 GB used, **5.2 GB free**. `/tmp` is a 16 GB RAM-backed tmpfs and does not count.
- **No Elastic IP**: the public address changes if the instance is ever stopped. No API termination protection. No existing snapshots.
- The caller's IAM permissions allow `CreateSnapshot` and `ModifyVolume` (verified with `--dry-run`, which created and changed nothing). The last resize was in August, so there is no 6-hour modification cooldown today.
- The AWS CLI is **not installed on the host**; run the `aws` commands from the operator's machine. Host commands run on the instance.

## Prerequisites (all must be true)
1. A named **deployment owner** has approved this runbook and is the only person changing the host (no concurrent SSH session running lab commands; check `loginctl list-sessions` and `docker ps -a`).
2. The lab is **stopped but not removed**: `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env stop` (never `down`: see the Splunk warning below). If the lab is already down, leave it that way.
3. Do not touch other projects' volumes, images or files.

> **Splunk warning.** Splunk's `/opt/splunk/etc` and `/opt/splunk/var` are anonymous volumes. `docker compose down` followed by `up` starts Splunk with new empty volumes and orphans the old ones. Use `stop`/`start`, or recreate in place (`up -d --force-recreate <service>`), which keeps them.

## Part 1: snapshot (do this first, always)
**Consistency.** A snapshot is crash-consistent at the instant of the call. With the lab's containers stopped, Splunk's files are quiescent, which gives an application-consistent state for AgentSec. Other workloads (Jupyter, the hourly replay loop) keep writing and are only crash-consistent. Do **not** `fsfreeze` the root filesystem (it would freeze SSH and the SSM agent).

1. On the host: `sync`.
2. From the operator machine:
   ```bash
   REGION=<region>; VOL=<volume-id>
   SNAP=$(aws ec2 create-snapshot --region $REGION --volume-id $VOL \
     --description "agentsec pre-cutover $(date -u +%F) owner=<name>" \
     --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Name,Value=agentsec-pre-cutover},{Key=Owner,Value=<name>},{Key=SourceCommit,Value=<commit>},{Key=DeleteAfter,Value=<YYYY-MM-DD>}]' \
     --query SnapshotId --output text)
   ```
3. Wait for completion (the first snapshot of about 91 GB can take tens of minutes to a couple of hours; **not measured**). The built-in waiter gives up after about 10 minutes, so loop:
   ```bash
   until [ "$(aws ec2 describe-snapshots --region $REGION --snapshot-ids $SNAP --query 'Snapshots[0].State' --output text)" = completed ]; do
     aws ec2 describe-snapshots --region $REGION --snapshot-ids $SNAP --query 'Snapshots[0].Progress' --output text; sleep 60; done
   ```
4. Verify: state `completed`, `VolumeSize` 100, `Encrypted` true, same `KmsKeyId` as the volume, and the tags present. **Do not proceed to Part 2 until this passes.**

### Expected charges (AWS Pricing API, us-east-2, 2026-10)
| Item | Rate | Estimate |
|---|---|---|
| Snapshot storage | $0.05 per GB-month | first snapshot about 91 GB: **about $4.55 per month** (up to $5.00); later snapshots store only changed blocks |
| Archive tier (optional) | $0.0125 per GB-month, 90-day minimum | about $1.14 per month, slower to restore |
| gp3 volume (current) | $0.08 per GB-month | $8.00 per month |
| After expansion to 150 GB | +50 GB | **+$4.00 per month** (total $12.00) |
| Recovery-rehearsal volume | gp3, prorated | pennies for an hour |
Creating a snapshot has no request charge. Set `DeleteAfter` and delete the snapshot only with the owner's approval.

### Recovery rehearsal (recommended, non-destructive)
Proves the snapshot is usable without touching the live disk. From the operator machine: create a temporary gp3 volume from `$SNAP` in the **same availability zone** and attach it to the instance as `/dev/sdf`. On the host: `lsblk` (it appears as another NVMe disk), `sudo mkdir /mnt/restore-check && sudo mount -o ro /dev/<new-partition> /mnt/restore-check`. Check that the repository, the `.env` (compare a SHA-256, never print it), the Docker volume directories under `var/lib/docker/volumes`, and the rollback copies exist. Then `sudo umount`, detach and delete the temporary volume. Reads are slow at first because the volume loads lazily from the snapshot.

### Real recovery and its limits
- A full restore replaces **everything on the root disk** with the state at snapshot time: the OS, Docker, the repository, all Splunk volumes **and other people's data written since** (the replay loop's data and logs, notebooks). Prefer the file-level path from the rehearsal volume for single items.
- Replacing the root volume means **stopping the instance**: detach the old root, attach the restored volume as the root device (`/dev/sda1`), start. The new volume has a **new ID**; set `DeleteOnTermination` as wanted; the instance's role needs KMS access to the same key. **Because there is no Elastic IP, the public address changes**, so security-group sources are unaffected but bookmarks, `AGENTSEC_PUBLIC_HOST` and learner URLs break.
- Keep the old root volume until the restore is verified.

## Part 2: expand the root volume to 150 GB (online, no downtime, no reboot)
Prerequisite: Part 1 verified. Charges above. **A volume cannot be shrunk**; "undo" means leaving it larger, or restoring the snapshot onto a new 100 GB volume (the full-restore limits apply). After a modification, AWS blocks another one on that volume for 6 hours.

1. From the operator machine:
   ```bash
   aws ec2 modify-volume --region $REGION --volume-id $VOL --size 150
   until [ "$(aws ec2 describe-volumes-modifications --region $REGION --volume-ids $VOL --query 'VolumesModifications[0].ModificationState' --output text)" != modifying ]; do sleep 15; done
   ```
   The volume is usable once the state is `optimizing` (it can take hours to reach `completed`; the OS does not wait for it).
2. On the host, in this order:
   ```bash
   lsblk                                    # nvme0n1 shows 150G; nvme0n1p1 is still about 98.9G
   sudo growpart /dev/nvme0n1 1             # partition 1 is the last partition; prints CHANGED
   sudo resize2fs /dev/nvme0n1p1            # ext4, grows while mounted
   df -h /                                  # about 145G total, about 55G free
   ```
3. Verify: `df` shows at least 15 GB free on `/`; `python3 scripts/preflight_disk.py --root <repo> --docker-root /var/lib/docker` reports PASS; `dmesg | grep -i -E 'ext4|nvme'` shows no errors; `docker volume ls -q | wc -l` is unchanged; the repository `HEAD` and the `.env` checksum are unchanged. Containers need no restart.
4. **Stop and ask the owner** if `growpart` reports anything other than `CHANGED`, `resize2fs` errors, or `df` does not grow. The snapshot is the safety net; do not improvise with `fdisk`.

## What this runbook deliberately does not do
It deletes nothing: no volumes, images, files or snapshots. It does not restart Docker, change the security group, pull a model or switch deployment mode. Reclaiming the empty AgentSec-era Splunk volumes is a separate decision (see `SHUTDOWN_INVESTIGATION.md`, section 5), and the July and August volumes belong to other work.
