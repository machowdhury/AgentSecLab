#!/bin/sh
# Learner name for ./scripts/lab-preflight.sh. Same checks. Same flags.
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$ROOT/lab-preflight.sh" "$@"
