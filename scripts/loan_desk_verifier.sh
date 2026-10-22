#!/bin/sh
# Start/stop/status for the host-side Loan Desk evidence verifier. No port, no credential, stdlib python only.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="${AGENTSEC_ARTIFACTS_HOST_DIR:-$ROOT/artifacts}"
DIR="$ART/loan_desk"
PIDFILE="$DIR/verifier.pid"
LOG="$DIR/verifier.log"
PY="${PYTHON:-python3}"
alive() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
case "${1:-status}" in
  start)
    mkdir -p "$DIR"
    if alive; then echo "[loan-desk-verifier] already running (pid $(cat "$PIDFILE"))"; exit 0; fi
    command -v docker >/dev/null 2>&1 || { echo "[loan-desk-verifier] docker not found; evidence stays NOT VERIFIED"; exit 0; }
    nohup "$PY" "$ROOT/scripts/loan_desk_verifier.py" --artifacts "$ART" >>"$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    echo "[loan-desk-verifier] started (pid $(cat "$PIDFILE"))" ;;
  stop)
    if alive; then kill "$(cat "$PIDFILE")" && echo "[loan-desk-verifier] stopped"; else echo "[loan-desk-verifier] not running"; fi
    rm -f "$PIDFILE" ;;
  status)
    if alive; then echo "[loan-desk-verifier] running (pid $(cat "$PIDFILE"))"; else echo "[loan-desk-verifier] not running"; exit 1; fi ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
