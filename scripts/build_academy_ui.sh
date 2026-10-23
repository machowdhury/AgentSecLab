#!/bin/sh
# Build academy-ui in an isolated container and write the result to src/agentsec/static/learn/.
#   scripts/build_academy_ui.sh lock    regenerate academy-ui/pnpm-lock.yaml (resolve only, no scripts) for review
#   scripts/build_academy_ui.sh         build from the committed lockfile (frozen) into src/agentsec/static/learn/
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT/academy-ui"
if [ "${1:-}" = lock ]; then
  docker build --target lockfile --output "type=local,dest=$ROOT/academy-ui" .
  echo "wrote academy-ui/pnpm-lock.yaml: review it before committing"
  exit 0
fi
OUT="${ACADEMY_UI_OUT:-$ROOT/src/agentsec/static/learn}"
rm -rf "$OUT.tmp" && mkdir -p "$OUT.tmp"
docker build --target dist --output "type=local,dest=$OUT.tmp" .
rm -rf "$OUT" && mv "$OUT.tmp" "$OUT"
echo "built Academy UI into $OUT"
