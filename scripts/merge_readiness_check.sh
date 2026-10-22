#!/bin/sh
# Simulates merging the feature branch into develop in SCRATCH clones. Read-only on the real develop tree:
# it only reads its HEAD (through git objects) and copies its uncommitted files into the scratch clone.
# Usage: DEV=<develop worktree> SCRATCH=<empty scratch dir> BRANCH=feature/phase1-hardening sh merge_readiness_check.sh
set -eu
DEV="${DEV:?}"; SCRATCH="${SCRATCH:?}"; BRANCH="${BRANCH:-feature/phase1-hardening}"
case "$SCRATCH" in /private/tmp/*|/tmp/*|/var/folders/*) ;; *) echo "SCRATCH must be under a temp directory"; exit 2;; esac
[ -z "$(ls -A "$SCRATCH" 2>/dev/null)" ] || { echo "SCRATCH not empty"; exit 2; }
DIRTY="$(git -C "$DEV" status --short | awk '{print $2}')"
echo "develop HEAD: $(git -C "$DEV" rev-parse --short HEAD); dirty entries: $(echo "$DIRTY" | wc -l | tr -d ' ')"
mk() { # name -> prepared clone with develop HEAD + the uncommitted entries copied in
  git clone -q --no-hardlinks "$DEV" "$SCRATCH/$1" 2>/dev/null
  git -C "$SCRATCH/$1" fetch -q "$DEV" "$BRANCH:feature" 2>/dev/null
  git -C "$SCRATCH/$1" config user.email sim@example.invalid; git -C "$SCRATCH/$1" config user.name sim
  for f in $DIRTY; do mkdir -p "$SCRATCH/$1/$(dirname "$f")"; if [ -d "$DEV/$f" ]; then cp -R "$DEV/$f" "$SCRATCH/$1/$(dirname "$f")/"; else cp "$DEV/$f" "$SCRATCH/$1/$f"; fi; done
}
echo; echo "== S1: merge with the 19 uncommitted entries still uncommitted (what happens if nothing is done first)"
mk s1; (cd "$SCRATCH/s1" && git merge --no-edit feature 2>&1 | head -12; echo "exit=$?")
echo; echo "== S2: develop commits its 19 entries as-is, then merges"
mk s2; (cd "$SCRATCH/s2" && git add -A && git commit -q -m "wip: develop working tree as-is" && git merge --no-edit feature 2>&1 | tail -4; echo "conflicts: $(git diff --name-only --diff-filter=U | wc -l | tr -d ' ')"; git diff --name-only --diff-filter=U)
echo; echo "== S3: stash the 19 entries, fast-forward merge, then drop the stash (content is already in the branch)"
mk s3; (cd "$SCRATCH/s3" && git stash push -u -q -m pre-merge && git merge --ff-only feature 2>&1 | tail -2; echo "stashed entries identical to the branch tree?"; for f in $DIRTY; do [ -d "$DEV/$f" ] && continue; git show "feature:$f" 2>/dev/null | cmp -s - "$DEV/$f" || echo "  DIFFERS $f"; done; echo "  (no DIFFERS lines above means identical); stash retained until the branch is verified: $(git stash list | wc -l | tr -d ' ') stash")
echo; echo "== S4: after S2 the three files you asked about"
(cd "$SCRATCH/s2" && for f in scripts/lab-up.sh docker-compose.yml docs/QUICKSTART.md; do git diff --quiet feature -- "$f" && echo "  $f == branch version"; done; git status --short | head -3; git log --oneline -3)
