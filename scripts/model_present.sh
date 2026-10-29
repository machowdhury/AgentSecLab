#!/bin/sh
# Exact model-name check for the host scripts: does the installed list contain THIS name, with `latest` assumed when no tag is given?
# Substring and family matches are not accepted (so "llama3.2" never matches "llama3.2:1b", and "llama3" never matches "llama3.2:1b").
#   ollama list | model_present.sh NAME            (skips the header line, reads the first column)
#   curl .../api/tags | model_present.sh --json NAME
# Exit 0 = present, 1 = absent. Reads stdin; never contacts anything itself.
mode=text
if [ "${1:-}" = "--json" ]; then mode=json; shift; fi
want="${1:-}"
[ -n "$want" ] || { echo "usage: model_present.sh [--json] NAME" >&2; exit 2; }
case "${want##*/}" in *:*) ;; *) want="$want:latest" ;; esac
if [ "$mode" = json ]; then
  names=$(grep -o '"name": *"[^"]*"' | sed 's/^"name": *"//; s/"$//')
else
  names=$(awk 'NR > 1 { print $1 }')
fi
printf '%s\n' "$names" | grep -Fxq -- "$want"
