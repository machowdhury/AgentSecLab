#!/bin/sh
# Opt-in unified HTTPS gateway. Subcommands: init | validate | up | down | ctf-enable | ctf-disable.
# Touches only the gateway service (and recreates attack_service/acmebank with no host ports). Never touches Splunk, volumes, .env or secrets
# outside the gateway directory. LOCAL_DEV material is generated for testing only; ORG_CERT uses files you supply.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
GDIR="${AGENTSEC_GATEWAY_DIR:-$ROOT/.gateway}"; export AGENTSEC_GATEWAY_DIR="$GDIR"
PY="${PYTHON:-python3}"
CTF_OVL=""   # set by `up` only when CTF-through-gateway is enabled
# the installer's override (project-scoped container names) goes last, as in its COMPOSE_FILE, which -f here replaces
dc() { OVL=; [ -f .agentsec/compose.override.yml ] && OVL="-f .agentsec/compose.override.yml"; docker compose -f docker-compose.yml -f docker-compose.gateway.yml $CTF_OVL $OVL --profile gateway "$@"; }
# CTF gateway secret: 32 random bytes (hex) in $GDIR/ctf-gateway-secret, plus $GDIR/ctf-secret.conf (the nginx include that sets $gw_secret). Both 0600 (umask 077), written by
# redirection so the value is never in argv, logs or output. Idempotent: an existing secret is kept (rotate = delete both files, run ctf-enable, then `gateway.sh down` and `up`: the containers bind-mount single files, so a plain `up` keeps serving the old secret).
ctf_secret_ok() {   # the secret is written into nginx syntax: only 64 lowercase hex characters, never a symlink; readable only by the user the Attack Service will run as
  for f in "$GDIR/ctf-gateway-secret" "$GDIR/ctf-secret.conf" "$GDIR/gateway.env.new"; do [ ! -L "$f" ] || { echo "refusing: $f is a symbolic link"; return 1; }; done
  [ -f "$GDIR/ctf-gateway-secret" ] && [ "$(tr -d '\n' < "$GDIR/ctf-gateway-secret" | grep -Ec '^[0-9a-f]{64}$')" = 1 ] || { echo "refusing: $GDIR/ctf-gateway-secret is missing or is not 64 hex characters (delete it and run ctf-enable to create a new one)"; return 1; }
  u=$(id -u)
  [ "$u" != 0 ] || { echo "refusing: the CTF secret is for the unprivileged user that installs the lab; run this without sudo (the user must be in the docker group)"; return 1; }
  for f in "$GDIR/ctf-gateway-secret" "$GDIR/ctf-secret.conf"; do
    [ "$f" = "$GDIR/ctf-secret.conf" ] && [ "${1:-}" = pre ] && continue      # `pre`: the nginx include is rewritten right after, so only the secret itself is checked
    [ -n "$(find "$f" -user "$u" -perm 600 2>/dev/null)" ] || { echo "refusing: $f must be owned by uid $u (you) with mode 0600; it is not. Delete .gateway/ctf-gateway-secret and .gateway/ctf-secret.conf and run ctf-enable as the installing user"; return 1; }
  done
}
ctf_material() {
  umask 077
  for f in "$GDIR/ctf-gateway-secret" "$GDIR/ctf-secret.conf" "$GDIR/gateway.env.new"; do [ ! -L "$f" ] || { echo "refusing: $f is a symbolic link"; exit 1; }; done
  [ -s "$GDIR/ctf-gateway-secret" ] || openssl rand -hex 32 > "$GDIR/ctf-gateway-secret"
  ctf_secret_ok pre || exit 1
  mkdir -p "$GDIR/ctf-state"; chmod 700 "$GDIR/ctf-state"      # bind-mounted into the Attack Service: persistent CTF ledger and key, owned by the same user
  # `set` alone is invisible to proxy_set_header in a location that has auth_request (seen on real nginx): auth_request_set re-assigns it after the check, so the POST locations send it
  { v=$(tr -d '\n' < "$GDIR/ctf-gateway-secret"); printf 'set $gw_secret "%s";\nauth_request_set $gw_secret "%s";\n' "$v" "$v"; } > "$GDIR/ctf-secret.conf"
  chmod 600 "$GDIR/ctf-gateway-secret" "$GDIR/ctf-secret.conf"
  ctf_secret_ok || exit 1
}
ctf_flag() {   # idempotently set AGENTSEC_CTF_GATEWAY=$1 in gateway.env
  umask 077; { grep -v '^AGENTSEC_CTF_GATEWAY=' "$GDIR/gateway.env" 2>/dev/null || true; printf 'AGENTSEC_CTF_GATEWAY=%s\n' "$1"; } > "$GDIR/gateway.env.new" && mv "$GDIR/gateway.env.new" "$GDIR/gateway.env"
}
load_env() {   # gateway.env supplies defaults only: variables already set in the environment win
  [ -f "$GDIR/gateway.env" ] || return 0
  while IFS='=' read -r k v; do [ -n "$k" ] || continue; eval "[ -n \"\${$k+x}\" ]" || export "$k=$v"; done < "$GDIR/gateway.env"
}
validate() { PYTHONPATH="$ROOT/src" "$PY" -m agentsec.gateway_config validate; }

case "${1:-}" in
  init)   # LOCAL_DEV: disposable CA + server certificate + two users. Refuses to overwrite an existing directory.
    # The CA is name-constrained to the public host and localhost, and its private key exists only while the server certificate is signed: it is
    # removed on every exit path (success or failure). Renewal = move the directory away and run init again. Operator-supplied (ORG_CERT) CA keys are never touched.
    [ ! -e "$GDIR" ] || { echo "refusing: $GDIR already exists (move it away first)"; exit 1; }
    HOST="${AGENTSEC_PUBLIC_HOST:-localhost}"; PORT="${AGENTSEC_PUBLIC_PORT:-${AGENTSEC_HTTPS_PORT:-443}}"
    umask 077; mkdir -p "$GDIR/tls"
    trap 'rm -f "$GDIR/tls/ca.key" "$GDIR/tls/ca.srl" "$GDIR/tls/s.csr" "$GDIR/tls/ext.cnf"' EXIT
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=agentsec-local-dev-ca" -keyout "$GDIR/tls/ca.key" -out "$GDIR/tls/ca.pem" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "nameConstraints=critical,permitted;DNS:$HOST,permitted;DNS:localhost" 2>/dev/null
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$HOST" -keyout "$GDIR/tls/server.key" -out "$GDIR/tls/s.csr" 2>/dev/null
    printf "subjectAltName=DNS:%s,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$HOST" > "$GDIR/tls/ext.cnf"
    openssl x509 -req -in "$GDIR/tls/s.csr" -CA "$GDIR/tls/ca.pem" -CAkey "$GDIR/tls/ca.key" -CAcreateserial -days 90 -extfile "$GDIR/tls/ext.cnf" -out "$GDIR/tls/server.pem" 2>/dev/null
    rm -f "$GDIR/tls/s.csr" "$GDIR/tls/ext.cnf" "$GDIR/tls/ca.srl"
    cat "$GDIR/tls/server.pem" "$GDIR/tls/ca.pem" > "$GDIR/tls/fullchain.pem"   # the compose file mounts it; without it a plain `compose up` makes a directory of that name
    L=$(openssl rand -hex 12); O=$(openssl rand -hex 12)
    printf 'learner:%s\noperator:%s\n' "$(openssl passwd -apr1 "$L")" "$(openssl passwd -apr1 "$O")" > "$GDIR/htpasswd"
    printf 'learner=%s\noperator=%s\n' "$L" "$O" > "$GDIR/credentials.txt"
    printf 'AGENTSEC_TLS_MODE=LOCAL_DEV\nAGENTSEC_PUBLIC_HOST=%s\nAGENTSEC_PUBLIC_PORT=%s\n' "$HOST" "$PORT" > "$GDIR/gateway.env"
    [ "$(id -u)" = 0 ] || ctf_material; ctf_flag disabled   # secret exists but CTF-through-gateway stays OFF until `gateway.sh ctf-enable`
    chmod 644 "$GDIR/htpasswd"   # the nginx container reads it; it holds hashes only
    echo "LOCAL_DEV gateway material written to $GDIR (test-only; credentials in credentials.txt, mode 0600)."
    echo "Trust $GDIR/tls/ca.pem in your browser yourself if you want a green padlock; this script never changes a trust store."
    echo "That CA can only vouch for $HOST and localhost (name constraints), and its signing key has already been deleted." ;;
  validate) load_env; validate ;;
  up)
    load_env; AGENTSEC_CHECK_PORT_FREE=1 validate
    CERT="${AGENTSEC_TLS_CERT_FILE:-$GDIR/tls/server.pem}"; CHAIN="${AGENTSEC_TLS_CHAIN_FILE:-$GDIR/tls/ca.pem}"
    if [ "${AGENTSEC_CTF_GATEWAY:-disabled}" = enabled ]; then
      [ -s "$GDIR/ctf-gateway-secret" ] && [ -s "$GDIR/ctf-secret.conf" ] || { echo "refusing: CTF gateway enabled but its secret is missing (run: scripts/gateway.sh ctf-enable)"; exit 1; }
      ctf_secret_ok || exit 1
      export AGENTSEC_CTF_SECRET_FILE="$GDIR/ctf-gateway-secret" AGENTSEC_CTF_SECRET_CONF="$GDIR/ctf-secret.conf" AGENTSEC_CTF_GATEWAY=enabled AGENTSEC_CTF_UID="$(id -u)" AGENTSEC_CTF_GID="$(id -g)" AGENTSEC_CTF_STATE_HOST="$GDIR/ctf-state"; CTF_OVL="-f docker-compose.gateway-ctf.yml"
    fi
    mkdir -p "$GDIR/tls"; cat "$CERT" "$CHAIN" > "$GDIR/tls/fullchain.pem"
    export AGENTSEC_TLS_KEY_FILE="${AGENTSEC_TLS_KEY_FILE:-$GDIR/tls/server.key}" AGENTSEC_AUTH_FILE="${AGENTSEC_AUTH_FILE:-$GDIR/htpasswd}"
    dc up -d --no-deps gateway attack_service acmebank
    echo "Canonical learner URL: https://${AGENTSEC_PUBLIC_HOST:-localhost}:${AGENTSEC_PUBLIC_PORT:-${AGENTSEC_HTTPS_PORT:-443}}/learn" ;;
  ctf-enable) [ -d "$GDIR" ] || { echo "no gateway directory: run init first"; exit 1; }; ctf_material; ctf_flag enabled
    echo "CTF through the gateway ENABLED (secret in $GDIR/ctf-gateway-secret, not printed). Needs AGENTSEC_ATTACK_TIER=enabled. Apply with: scripts/gateway.sh up" ;;
  ctf-disable) [ -d "$GDIR" ] || { echo "no gateway directory: run init first"; exit 1; }; ctf_flag disabled; echo "CTF through the gateway DISABLED. Apply with: scripts/gateway.sh up" ;;
  down) load_env; dc stop gateway; dc rm -f gateway ;;   # gateway only: no volumes, no other services
  *) echo "usage: gateway.sh init | validate | up | down | ctf-enable | ctf-disable"; exit 2 ;;
esac
