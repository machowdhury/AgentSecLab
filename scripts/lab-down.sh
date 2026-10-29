#!/bin/sh
# Pause or remove the lab. The DEFAULT is a pause: `docker compose stop`.
#
#   (no flag)            PAUSE   docker compose stop        containers, Splunk config and indexed events all untouched
#   --remove-containers  REMOVE  docker compose down        containers and network go; NAMED volumes (Splunk etc/var, models,
#                                                            app, telemetry) stay. Refused if Splunk still uses ANONYMOUS volumes.
#   --purge --yes-delete-all-lab-data
#                        PURGE   docker compose down -v     DELETES every lab volume, including indexed Splunk events
#
# Why this matters: Splunk's data used to live in anonymous Docker volumes. `down` then `up` replaced them with empty
# ones and left the old data orphaned (still on disk, not attached). Stop/start never does that.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

MODE=stop
YES_DELETE=0
ALLOW_ORPHAN=0
for arg in "$@"; do
  case "$arg" in
    --remove-containers) MODE=remove ;;
    --purge) MODE=purge ;;
    --yes-delete-all-lab-data) YES_DELETE=1 ;;
    --allow-orphan-splunk-data) ALLOW_ORPHAN=1 ;;
    -h|--help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf '[lab-down] unknown argument: %s (try --help)\n' "$arg" >&2
      exit 1
      ;;
  esac
done

if [ ! -f "$ROOT/.env" ]; then
  printf '[lab-down] ERROR: %s/.env is missing.\n' "$ROOT" >&2
  exit 1
fi

. "$ROOT/scripts/lab-compose.sh"
COMPOSE="$LAB_COMPOSE"

# none | named | anonymous : how the Splunk container keeps /opt/splunk/var
splunk_var_state() {
  name="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/splunk/var"}}{{.Name}}{{end}}{{end}}' "$(svc_id splunk)" 2>/dev/null || true)"
  case "$name" in
    '') echo none ;;
    *splunk_var) echo named ;;
    *) echo anonymous ;;
  esac
}

if [ "$MODE" = purge ] && [ "$YES_DELETE" -ne 1 ]; then
  printf '[lab-down] REFUSED: --purge deletes every lab volume, including indexed Splunk events, Splunk users and models.\n' >&2
  printf '[lab-down] If that is really what you want, take a backup first (docs/ops/SPLUNK_VOLUME_MIGRATION.md), then add --yes-delete-all-lab-data.\n' >&2
  exit 2
fi

if [ "$MODE" = remove ] && [ "$(splunk_var_state)" = anonymous ] && [ "$ALLOW_ORPHAN" -ne 1 ]; then
  printf '[lab-down] REFUSED: Splunk is using ANONYMOUS data volumes (the legacy layout).\n' >&2
  printf '[lab-down] Removing the container would orphan your indexed events: the next start would create new EMPTY volumes.\n' >&2
  printf '[lab-down] Pause instead (./scripts/lab-down.sh), or migrate to named volumes first (docs/ops/SPLUNK_VOLUME_MIGRATION.md).\n' >&2
  printf '[lab-down] To remove anyway and keep the old volumes for a later manual recovery: add --allow-orphan-splunk-data.\n' >&2
  exit 3
fi

"$ROOT/scripts/loan_desk_verifier.sh" stop || true

case "$MODE" in
  stop)
    printf '[lab-down] PAUSING the lab (docker compose stop). Nothing is removed.\n'
    $COMPOSE stop
    printf '[lab-down] Paused. Containers, Splunk configuration and indexed events are untouched.\n'
    printf '[lab-down] Resume: ./scripts/lab-up.sh   (or: docker compose ... start)\n'
    printf '[lab-down] Remove containers but keep data: ./scripts/lab-down.sh --remove-containers\n'
    ;;
  remove)
    printf '[lab-down] REMOVING containers and the network (docker compose down). Named volumes are kept.\n'
    $COMPOSE down
    printf '[lab-down] Removed. Named volumes (Splunk etc/var, models, app, telemetry) remain and are reattached by ./scripts/lab-up.sh.\n'
    ;;
  purge)
    printf '[lab-down] PURGING: docker compose down -v. Every lab volume, including indexed Splunk events, is deleted.\n'
    $COMPOSE down -v
    printf '[lab-down] Purged. The next ./scripts/lab-up.sh starts from nothing.\n'
    ;;
esac
