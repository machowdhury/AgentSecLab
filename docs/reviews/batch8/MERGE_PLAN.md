# Merge readiness: `feature/phase1-hardening` into `develop` (plan only; nothing was merged, committed, stashed, reset or discarded)

## Facts (measured, read-only)
- `develop` HEAD is `b86accc`. It is the **merge base**: it is an ancestor of the branch, which is 33+ commits ahead. There is no divergent history on `develop`.
- `develop`'s 19 uncommitted entries (14 modified, 5 untracked) are the HEC-TLS and Ollama-provider work. **Every one of them is byte-identical to the same file in the branch's baseline commit `d415c93`** (checked with `cmp` file by file, including `splunk_app/agentsec/local/inputs.conf`). The branch already contains that work in its history; it is not lost, and it does not conflict in content.
- Against that baseline the branch changes only three of those files, and **only by addition** (no line removed):
  | File | Branch adds | Conflict character |
  |---|---|---|
  | `scripts/lab-up.sh` | `mkdir` of the receipts/requests dirs; start of the host verifier after READY and in the no-wait path; seeding of the scanner/garak REPLAY specimens | pure additions in separate hunks |
  | `docker-compose.yml` | the read-only `receipts` bind mount on `acmebank` and on `attack_service` (2 lines + comment) | additions only |
  | `docs/QUICKSTART.md` | a "Loan Desk mission" section (4 lines) | addition at the end |
  (`scripts/lab-down.sh` gains one `stop` line; `develop` has no uncommitted change to it.)
- Also changed on the branch and not touched by `develop`'s dirty tree: `docker/Dockerfile.attack` (ships `framework_refs.json`), the Splunk app, the Academy, the Loan Desk, specimens and docs.

## What git does with it (simulated in scratch clones; `scripts/merge_readiness_check.sh`; output `merge_simulation.txt`)
| Strategy | Result |
|---|---|
| **S1 merge with the 19 entries left uncommitted** | **Blocked by git**: "Your local changes to the following files would be overwritten by merge". Not a content conflict: git protects uncommitted files the merge would touch |
| **S2 commit the 19 entries as they are, then merge** | **0 conflicts.** Both sides changed those files identically, so git resolves them; `lab-up.sh`, `docker-compose.yml` and `QUICKSTART.md` come out equal to the branch's versions |
| **S3 `git stash push -u`, then `git merge --ff-only`** | Fast-forward succeeds. The stashed files differ from the branch's only in the three files above (the branch's additions). The stash is kept until you have checked the result |

## Recommended non-destructive sequence (for you to run; each step is reversible)
1. **Snapshot without touching the working tree.**
   `git -C <develop> stash create` prints a commit id of the tracked changes; record it with `git update-ref refs/backup/develop-dirty-<date> <id>`.
   Copy the five untracked entries: `tar czf ~/agentsec-backups/develop-untracked-<date>.tgz scripts/hec-certs.sh scripts/hec-scheme-check.sh splunk_app/agentsec/local tests/test_hec_transport_contract.py tests/test_ollama_provider_contract.py`.
   Neither command changes any file in `develop`.
2. **Prove the claim again at merge time.** For each dirty entry, `git show feature/phase1-hardening~N:path | cmp - path` against the baseline commit, or run `scripts/merge_readiness_check.sh` (it works on scratch copies). Continue only if every line says identical.
3. **Merge.** Preferred, linear: `git stash push -u -m pre-merge` then `git merge --ff-only feature/phase1-hardening`. Alternative that keeps your uncommitted work as your own commit: `git add -A && git commit -m "develop working tree as-is"` then `git merge feature/phase1-hardening` (this also tracks `splunk_app/agentsec/local/`, which the branch tracks too).
4. **Verify after the merge:** `git status` clean; `python3 scripts/learner_ready.py`; the full test suite (1,950+ tests).
5. **Do not drop the stash** until step 4 passes and you have confirmed the three files (`lab-up.sh`, `docker-compose.yml`, `QUICKSTART.md`) read correctly. Dropping is then optional, because the stash content is already in the history.
6. **Running lab:** the containers' bind mounts point at the `develop` tree. After the merge, `docker compose up -d acmebank attack_service` from `develop` recreates both with the merged compose file (receipts mount included); until then use `scripts/deploy_acmebank_attack.py`.

## Rollback
`git merge --abort` before commit; after a fast-forward, `git reset --keep <old HEAD b86accc>` and `git stash pop` restore the earlier state (nothing is lost because step 1 recorded it).

## Risks that remain
- An untracked `splunk_app/agentsec/local/` in `develop` makes a plain merge refuse ("untracked working tree files would be overwritten") if it is not stashed or committed first; both options above handle it.
- Someone who edits those 19 files in `develop` between now and the merge changes the premise: rerun step 2.
- The branch is large (about 390 files, 52k lines, mostly additive docs, tests, evidence and packs); review in the order: security-relevant code (`loan_desk/`, `verify_bridge.py`, `verifier.py`, deploy script), then Academy/Splunk assets, then packs and docs.
