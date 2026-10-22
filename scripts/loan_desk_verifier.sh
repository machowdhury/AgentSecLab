#!/bin/sh
# Start/stop/status for the host-side Loan Desk evidence verifier. No port, no credential, stdlib python only.
# State (key, lock, pidfile, log) lives in the host-only state dir, never in a directory a container can see.
# `stop` and `status` trust a pid only if its command line is this verifier, so a stale pidfile can never
# cause an unrelated process to be signalled.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="${AGENTSEC_ARTIFACTS_HOST_DIR:-$ROOT/artifacts}"
STATE="${AGENTSEC_VERIFIER_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agentsec/loan_desk}"
PIDFILE="$STATE/verifier.pid"
LOG="$STATE/verifier.log"
PY="${PYTHON:-python3}"
is_verifier() { ps -p "$1" -o command= 2>/dev/null | grep -q "loan_desk_verifier\.py"; }
live_pid() { [ -f "$PIDFILE" ] || return 1; p="$(cat "$PIDFILE" 2>/dev/null)"; case "$p" in ''|*[!0-9]*) return 1;; esac; is_verifier "$p" && echo "$p"; }
case "${1:-status}" in
  start)
    mkdir -p "$STATE" "$ART/loan_desk/requests" "$ART/loan_desk/receipts"; chmod 700 "$STATE"
    if p="$(live_pid)"; then echo "[loan-desk-verifier] already running (pid $p)"; exit 0; fi
    command -v docker >/dev/null 2>&1 || { echo "[loan-desk-verifier] docker not found; evidence stays NOT VERIFIED"; exit 0; }
    AGENTSEC_VERIFIER_STATE_DIR="$STATE" nohup "$PY" "$ROOT/scripts/loan_desk_verifier.py" --artifacts "$ART" >>"$LOG" 2>&1 &
    i=0; while [ $i -lt 25 ]; do if p="$(live_pid)"; then echo "[loan-desk-verifier] started (pid $p)"; exit 0; fi; i=$((i+1)); sleep 0.2; done
    echo "[loan-desk-verifier] did not report a pid; see $LOG"; exit 1 ;;
  stop)
    if p="$(live_pid)"; then
      kill "$p"; i=0
      while [ $i -lt 50 ] && is_verifier "$p"; do i=$((i+1)); sleep 0.2; done
      if is_verifier "$p"; then echo "[loan-desk-verifier] still running after 10s (pid $p); not forcing"; exit 1; fi
      echo "[loan-desk-verifier] stopped"
    else
      [ -f "$PIDFILE" ] && echo "[loan-desk-verifier] stale pidfile ignored (its pid is not the verifier)" || echo "[loan-desk-verifier] not running"
    fi
    rm -f "$PIDFILE" ;;
  status)
    if p="$(live_pid)"; then echo "[loan-desk-verifier] running (pid $p)"; else echo "[loan-desk-verifier] not running"; exit 1; fi ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
