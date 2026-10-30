# Sourced by the lab scripts (POSIX sh). Project-scoped service discovery: containers are found by their Compose labels (project + service), never by a
# fixed container name, so the same scripts work for the legacy agentsec_* names and for installer-generated <project>-<service> names.
# Requires ROOT to be set by the caller. Only reads from Docker.

lab_env_value() {  # lab_env_value KEY: KEY=value from $ROOT/.env, empty when absent
  [ -f "$ROOT/.env" ] || return 0
  sed -n "s/^$1=//p" "$ROOT/.env" | head -n 1 | tr -d '\r' | sed "s/^[\"']//; s/[\"' ]*\$//"
}

lab_project() {
  p="${COMPOSE_PROJECT_NAME:-$(lab_env_value COMPOSE_PROJECT_NAME)}"
  # Compose's own default: the directory name, lowercased, without characters outside [a-z0-9_-]
  [ -n "$p" ] || p="$(basename "$ROOT" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')"
  printf '%s' "$p"
}
LAB_PROJECT="$(lab_project)"

# svc_id <service>: id of the project's container for that Compose service (running or not), empty when there is none.
svc_id() {
  docker ps -aq --filter "label=com.docker.compose.project=$LAB_PROJECT" --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -n 1
}

# lab_compose_cmd: the docker compose invocation for starting/stopping. An installer-generated configuration (.agentsec/install.json) carries COMPOSE_FILE,
# COMPOSE_PROFILES and COMPOSE_PROJECT_NAME in .env; a legacy lab uses the fixed file list.
if [ -f "$ROOT/.agentsec/install.json" ]; then
  LAB_COMPOSE="docker compose --env-file .env"      # relative: the scripts run from $ROOT, and a path with spaces would be split
  LAB_APP_SERVICES=""                                  # installer layouts may have no bundled ollama service: start what the configuration defines
else
  LAB_COMPOSE="docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env"
  LAB_APP_SERVICES="ollama otel_collector acmebank attack_service"
fi

# lab_expects <service>: is that service part of this lab? Always true for a legacy lab; for an installer layout it comes from the generated state
# (the services array is the only place a line holds just the quoted service name).
lab_expects() {
  [ -f "$ROOT/.agentsec/install.json" ] || return 0
  grep -Eq "^ *\"$1\",?$" "$ROOT/.agentsec/install.json"
}
