#!/bin/sh
# Local-only PoC: real Attack Service + AcmeBank on 127.0.0.1, nginx in Docker published on 127.0.0.1:8443/8080 only.
# Runs the checks, then removes everything. Needs docker, openssl, curl, python3 with the project installed.
set -eu
cd "$(dirname "$0")"; W=$(mktemp -d); PY=""
trap 'docker rm -f agentsec-https-poc >/dev/null 2>&1 || true; [ -n "$PY" ] && kill $PY 2>/dev/null || true; rm -rf "$W"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=agentsec-poc-ca" -keyout "$W/ca.key" -out "$W/ca.pem" 2>/dev/null
printf "subjectAltName=DNS:learn.lab.test,DNS:bank.lab.test,DNS:splunk.lab.test\n" > "$W/san"
openssl req -newkey rsa:2048 -nodes -subj "/CN=learn.lab.test" -keyout "$W/server.key" -out "$W/s.csr" 2>/dev/null
openssl x509 -req -in "$W/s.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 1 -extfile "$W/san" -out "$W/server.pem" 2>/dev/null
PW=$(openssl rand -hex 8); printf "learner:%s\n" "$(openssl passwd -apr1 "$PW")" > "$W/htpasswd"
PYTHONPATH=../../src python3 poc_backends.py & PY=$!; sleep 3
docker run -d --name agentsec-https-poc -p 127.0.0.1:8443:8443 -p 127.0.0.1:8080:8080 \
  -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$PWD/attack-tier.conf:/etc/nginx/attack-tier.conf:ro" \
  -v "$W/htpasswd:/etc/nginx/htpasswd:ro" -v "$W/server.pem:/etc/nginx/tls/server.pem:ro" -v "$W/server.key:/etc/nginx/tls/server.key:ro" nginx:1.27-alpine >/dev/null
sleep 2; docker exec agentsec-https-poc nginx -t
CA="$W/ca.pem" PW="$PW" sh ./checks.sh
