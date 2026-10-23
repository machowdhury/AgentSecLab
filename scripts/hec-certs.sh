#!/bin/sh
# Prepare HEC TLS material under .certs/ (git-ignored) for the bundled Splunk.
# LOCAL_SELF_SIGNED: create once, reuse on later runs. Never touches the OS trust store.
# EXTERNAL_CERT: validate admin-supplied files only; never writes or regenerates them.
# Exit 0 = ready, 1 = invalid. Prints no key material.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${AGENTSEC_CERT_DIR:-$ROOT/.certs}"
MODE="${AGENTSEC_HEC_TLS_MODE:-LOCAL_SELF_SIGNED}"
DAYS="${AGENTSEC_HEC_CERT_DAYS:-365}"
REQUIRED_SANS="DNS:agentsec_splunk DNS:localhost IP:127.0.0.1"

log() { printf '[hec-certs] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found"

# validate CERT KEY CA : readable, key matches cert, not expired, SANs present, chains to CA.
validate() {
  cert="$1"; key="$2"; ca="$3"
  for f in "$cert" "$key" "$ca"; do
    [ -r "$f" ] || die "not readable: $f"
  done
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || die "certificate expired or unparsable: $cert"
  c_pub="$(openssl x509 -in "$cert" -noout -pubkey | openssl sha256)"
  k_pub="$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl sha256)" || die "private key unreadable or encrypted: $key"
  [ "$c_pub" = "$k_pub" ] || die "certificate and private key do not match"
  sans="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null || true)"
  for s in $REQUIRED_SANS; do
    case "$s" in
      DNS:*) openssl x509 -in "$cert" -noout -checkhost "${s#DNS:}" | grep -q 'does match' || die "certificate SAN missing ${s}" ;;
      IP:*)  openssl x509 -in "$cert" -noout -checkip "${s#IP:}" | grep -q 'does match' || die "certificate SAN missing ${s}" ;;
    esac
  done
  [ -n "$sans" ] || die "certificate has no subjectAltName"
  openssl verify -CAfile "$ca" "$cert" >/dev/null 2>&1 || die "certificate does not chain to CA bundle $ca"
}

case "$MODE" in
  LOCAL_SELF_SIGNED)
    CERT="$CERT_DIR/hec.crt"; KEY="$CERT_DIR/hec.key"; CA="$CERT_DIR/hec-ca.crt"
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
      log "generating lab-local HEC certificate in $CERT_DIR (first install)"
      mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
      umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$KEY" -out "$CERT" -days "$DAYS" -subj "/CN=agentsec_splunk" \
        -addext "subjectAltName=DNS:agentsec_splunk,DNS:localhost,IP:127.0.0.1" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || die "openssl generation failed"
      cp "$CERT" "$CA"
    fi
    chmod 600 "$KEY"; chmod 644 "$CERT" "$CA"
    # Splunk reads one PEM: certificate then key. Rebuilt from the sources each run.
    ( umask 077; cat "$CERT" "$KEY" > "$CERT_DIR/hec.pem" )
    chmod 644 "$CERT_DIR/hec.pem"  # the Splunk container runs as another uid; 0600 crash-loops it on Linux. .certs/ itself stays 0700.
    validate "$CERT" "$KEY" "$CA"
    log "LOCAL_SELF_SIGNED certificate ready (reused if present)"
    ;;
  EXTERNAL_CERT)
    : "${AGENTSEC_HEC_CA_FILE:?AGENTSEC_HEC_CA_FILE is required in EXTERNAL_CERT mode}"
    if [ -n "${AGENTSEC_HEC_CERT_FILE:-}" ] || [ -n "${AGENTSEC_HEC_KEY_FILE:-}" ]; then
      : "${AGENTSEC_HEC_CERT_FILE:?set both AGENTSEC_HEC_CERT_FILE and AGENTSEC_HEC_KEY_FILE}"
      : "${AGENTSEC_HEC_KEY_FILE:?set both AGENTSEC_HEC_CERT_FILE and AGENTSEC_HEC_KEY_FILE}"
      validate "$AGENTSEC_HEC_CERT_FILE" "$AGENTSEC_HEC_KEY_FILE" "$AGENTSEC_HEC_CA_FILE"
      # Splunk wants one PEM. Build a private copy in .certs/; the supplied files stay untouched.
      mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
      ( umask 077; cat "$AGENTSEC_HEC_CERT_FILE" "$AGENTSEC_HEC_KEY_FILE" > "$CERT_DIR/hec.pem" )
      chmod 644 "$CERT_DIR/hec.pem"  # readable by the Splunk container's uid (see LOCAL_SELF_SIGNED above)
      log "EXTERNAL_CERT: bundled Splunk will serve the supplied certificate (files unmodified)"
    else
      [ -r "$AGENTSEC_HEC_CA_FILE" ] || die "not readable: $AGENTSEC_HEC_CA_FILE"
      openssl x509 -in "$AGENTSEC_HEC_CA_FILE" -noout >/dev/null 2>&1 || die "CA bundle has no parsable certificate"
      log "EXTERNAL_CERT: client-only (remote HEC); trusting CA bundle, no server key required"
    fi
    ;;
  *) die "AGENTSEC_HEC_TLS_MODE must be LOCAL_SELF_SIGNED or EXTERNAL_CERT (got: $MODE)" ;;
esac
