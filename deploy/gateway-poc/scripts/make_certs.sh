#!/bin/sh
# TEST-ONLY certificates for the disposable POC. Writes keys ONLY under the given directory (git-ignored .runtime/).
# Never touches any OS or browser trust store. Usage: make_certs.sh <out-dir>
set -eu
OUT="${1:?usage: make_certs.sh <out-dir>}"; mkdir -p "$OUT"; umask 077
SANS="DNS:learn.poc.test,DNS:bank.poc.test,DNS:splunk.poc.test"
ca() { # ca <dir> <cn>   self-signed CA
  mkdir -p "$1"; openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$2" -keyout "$1/ca.key" -out "$1/ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null; }
leaf() { # leaf <dir> <issuer-pem> <issuer-key> <sans> [extra x509 args...]   -> <dir>/server.{key,pem}
  d=$1; ip=$2; ik=$3; sans=$4; shift 4
  printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$sans" > "$d/ext.cnf"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=agentsec-poc-server" -keyout "$d/server.key" -out "$d/s.csr" 2>/dev/null
  openssl x509 -req -in "$d/s.csr" -CA "$ip" -CAkey "$ik" -CAcreateserial -days 30 -extfile "$d/ext.cnf" "$@" -out "$d/leaf.pem" 2>/dev/null; }

# A. LOCAL_DEV: one disposable CA signs the server certificate.
ca "$OUT/local" "agentsec-poc-local-ca"
leaf "$OUT/local" "$OUT/local/ca.pem" "$OUT/local/ca.key" "$SANS"; cp "$OUT/local/leaf.pem" "$OUT/local/server.pem"

# B. ORG_CERT simulation: root -> intermediate -> server, delivered as separate files (cert+chain, key, CA).
ca "$OUT/org" "agentsec-poc-org-root"
mkdir -p "$OUT/org/int"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=agentsec-poc-org-intermediate" -keyout "$OUT/org/int/ca.key" -out "$OUT/org/int/i.csr" 2>/dev/null
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > "$OUT/org/int/ext.cnf"
openssl x509 -req -in "$OUT/org/int/i.csr" -CA "$OUT/org/ca.pem" -CAkey "$OUT/org/ca.key" -CAcreateserial -days 30 -extfile "$OUT/org/int/ext.cnf" -out "$OUT/org/int/ca.pem" 2>/dev/null
leaf "$OUT/org" "$OUT/org/int/ca.pem" "$OUT/org/int/ca.key" "$SANS"
cat "$OUT/org/leaf.pem" "$OUT/org/int/ca.pem" > "$OUT/org/server.pem"      # server cert + intermediate; the client trusts only org/ca.pem (root)

# Negative sets (issued like ORG_CERT, each with exactly one defect).
mkdir -p "$OUT/bad-expired" "$OUT/bad-hostname" "$OUT/bad-mismatch"
leaf "$OUT/bad-expired" "$OUT/org/int/ca.pem" "$OUT/org/int/ca.key" "$SANS" -not_before 20200101000000Z -not_after 20200102000000Z
cat "$OUT/bad-expired/leaf.pem" "$OUT/org/int/ca.pem" > "$OUT/bad-expired/server.pem"
leaf "$OUT/bad-hostname" "$OUT/org/int/ca.pem" "$OUT/org/int/ca.key" "DNS:other.poc.test"
cat "$OUT/bad-hostname/leaf.pem" "$OUT/org/int/ca.pem" > "$OUT/bad-hostname/server.pem"
cp "$OUT/org/server.pem" "$OUT/bad-mismatch/server.pem"                    # valid cert ...
openssl genrsa -out "$OUT/bad-mismatch/server.key" 2048 2>/dev/null        # ... with somebody else's key
# Active set for the main gateway (LOCAL_DEV)
mkdir -p "$OUT/active"; cp "$OUT/local/server.pem" "$OUT/local/server.key" "$OUT/active/"
echo "certs written under $OUT (test-only; keys never leave this directory)"
