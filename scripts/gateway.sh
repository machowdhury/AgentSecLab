#!/bin/sh
# Opt-in unified HTTPS gateway. Subcommands: init | validate | up | down.
# Touches only the gateway service (and recreates attack_service/acmebank with no host ports). Never touches Splunk, volumes, .env or secrets
# outside the gateway directory. LOCAL_DEV material is generated for testing only; ORG_CERT uses files you supply.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
GDIR="${AGENTSEC_GATEWAY_DIR:-$ROOT/.gateway}"; export AGENTSEC_GATEWAY_DIR="$GDIR"
PY="${PYTHON:-python3}"
dc() { docker compose -f docker-compose.yml -f docker-compose.gateway.yml --profile gateway "$@"; }
load_env() {   # gateway.env supplies defaults only: variables already set in the environment win
  [ -f "$GDIR/gateway.env" ] || return 0
  while IFS='=' read -r k v; do [ -n "$k" ] || continue; eval "[ -n \"\${$k+x}\" ]" || export "$k=$v"; done < "$GDIR/gateway.env"
}
validate() { PYTHONPATH="$ROOT/src" "$PY" -m agentsec.gateway_config validate; }

case "${1:-}" in
  init)   # LOCAL_DEV: disposable CA + server certificate + two users. Refuses to overwrite an existing directory.
    [ ! -e "$GDIR" ] || { echo "refusing: $GDIR already exists (move it away first)"; exit 1; }
    HOST="${AGENTSEC_PUBLIC_HOST:-localhost}"; PORT="${AGENTSEC_HTTPS_PORT:-8443}"
    umask 077; mkdir -p "$GDIR/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=agentsec-local-dev-ca" -keyout "$GDIR/tls/ca.key" -out "$GDIR/tls/ca.pem" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$HOST" -keyout "$GDIR/tls/server.key" -out "$GDIR/tls/s.csr" 2>/dev/null
    printf "subjectAltName=DNS:%s,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$HOST" > "$GDIR/tls/ext.cnf"
    openssl x509 -req -in "$GDIR/tls/s.csr" -CA "$GDIR/tls/ca.pem" -CAkey "$GDIR/tls/ca.key" -CAcreateserial -days 90 -extfile "$GDIR/tls/ext.cnf" -out "$GDIR/tls/server.pem" 2>/dev/null
    rm -f "$GDIR/tls/s.csr" "$GDIR/tls/ext.cnf" "$GDIR/tls/ca.srl"
    L=$(openssl rand -hex 12); O=$(openssl rand -hex 12)
    printf 'learner:%s\noperator:%s\n' "$(openssl passwd -apr1 "$L")" "$(openssl passwd -apr1 "$O")" > "$GDIR/htpasswd"
    printf 'learner=%s\noperator=%s\n' "$L" "$O" > "$GDIR/credentials.txt"
    printf 'AGENTSEC_TLS_MODE=LOCAL_DEV\nAGENTSEC_PUBLIC_HOST=%s\nAGENTSEC_HTTPS_PORT=%s\n' "$HOST" "$PORT" > "$GDIR/gateway.env"
    chmod 644 "$GDIR/htpasswd"   # the nginx container reads it; it holds hashes only
    echo "LOCAL_DEV gateway material written to $GDIR (test-only; credentials in credentials.txt, mode 0600)."
    echo "Trust $GDIR/tls/ca.pem in your browser yourself if you want a green padlock; this script never changes a trust store." ;;
  validate) load_env; validate ;;
  up)
    load_env; validate
    CERT="${AGENTSEC_TLS_CERT_FILE:-$GDIR/tls/server.pem}"; CHAIN="${AGENTSEC_TLS_CHAIN_FILE:-$GDIR/tls/ca.pem}"
    mkdir -p "$GDIR/tls"; cat "$CERT" "$CHAIN" > "$GDIR/tls/fullchain.pem"
    export AGENTSEC_TLS_KEY_FILE="${AGENTSEC_TLS_KEY_FILE:-$GDIR/tls/server.key}" AGENTSEC_AUTH_FILE="${AGENTSEC_AUTH_FILE:-$GDIR/htpasswd}"
    dc up -d --no-deps gateway attack_service acmebank
    echo "Canonical learner URL: https://${AGENTSEC_PUBLIC_HOST:-localhost}:${AGENTSEC_HTTPS_PORT:-443}/learn" ;;
  down) load_env; dc stop gateway; dc rm -f gateway ;;   # gateway only: no volumes, no other services
  *) echo "usage: gateway.sh init | validate | up | down"; exit 2 ;;
esac
