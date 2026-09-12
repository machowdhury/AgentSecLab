#!/bin/sh
# Stage the repository AgentSec Splunk app into a writable destination.
# Used by the local compose splunk_app_init service. Do not chown here:
# Splunk Ansible will own the named volume. Never write back to the repo bind.
set -eu

SRC="${SPLUNK_APP_SRC:-/src}"
DEST="${SPLUNK_APP_DEST:-/dest}"

log() { printf '[splunk-app-init] %s\n' "$*"; }

if [ ! -d "$SRC" ]; then
  log "ERROR: source app directory missing: ${SRC}"
  exit 1
fi
if [ ! -f "${SRC}/default/app.conf" ]; then
  log "ERROR: ${SRC}/default/app.conf missing"
  exit 1
fi
if [ ! -f "${SRC}/default/indexes.conf" ]; then
  log "ERROR: ${SRC}/default/indexes.conf missing"
  exit 1
fi
if [ ! -f "${SRC}/default/data/ui/views/ws_lab_pi_001.xml" ]; then
  log "ERROR: ${SRC}/default/data/ui/views/ws_lab_pi_001.xml missing"
  exit 1
fi
if [ ! -f "${SRC}/default/data/ui/views/ws_lab_mcp_001.xml" ]; then
  log "ERROR: ${SRC}/default/data/ui/views/ws_lab_mcp_001.xml missing"
  exit 1
fi

mkdir -p "$DEST"
log "Clearing previous staged files in ${DEST}"
# Avoid find -exec (sandbox ARG_MAX / busybox). GLOBIGNORE-style: remove all dest children.
if [ -d "$DEST" ]; then
  set -- "$DEST"/* "$DEST"/.[!.]* "$DEST"/..?*
  for path in "$@"; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    rm -rf "$path"
  done
fi
log "Copying ${SRC} -> ${DEST}"
cp -a "${SRC}/." "${DEST}/"

test -f "${DEST}/default/app.conf"
test -f "${DEST}/default/indexes.conf"
test -f "${DEST}/default/data/ui/views/ws_lab_pi_001.xml"
test -f "${DEST}/default/data/ui/views/ws_lab_mcp_001.xml"
test -f "${DEST}/default/data/ui/nav/default.xml"

log "Staged AgentSec app (writable volume). Splunk may chown this copy."
