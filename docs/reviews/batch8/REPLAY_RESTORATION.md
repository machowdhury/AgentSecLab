# Restoration of the eight REPLAY labs' original specimens (Batch 8)

**Result: 8 of 8 RESTORED. 0 UNAVAILABLE.** Every run id these labs offer in their run selectors, and every other run id their dashboards, searches and incident files cite, was recovered from the original Splunk index. Nothing was invented, rewritten, deleted or re-stamped; existing evidence in the lab was not altered (the restoration only added events).

## 1. Where the specimens were, and why they were "missing"
- The eight dashboards offer 19 run ids (plus 2 scanner scan ids and 1 garak evaluation id) that were measured on this machine between **2026-09-12 and 2026-09-25** during the phase 4C to 9E validations. The repository committed event packs only for LAB-MCP-001 (3 runs); for the others the events lived only in Splunk and in the gitignored `artifacts/` tree. The validation documents (`docs/PHASE4C ... PHASE8D`, `MCP005/006_SPLUNK_VALIDATION`, `L9_LIVE_SPLUNK_VALIDATION`, `BLUE_TEAM_LIVE_SPLUNK_VALIDATION`) recorded their counts and outcomes but not their event bodies.
- The Splunk that holds the current lab was built on **2026-10-20** (volume `f2323678...`, project `agentseclab`). Its index never contained the September runs, and `scripts/splunk_hec_init.sh` seeds only committed packs, so the eight dropdowns pointed at nothing (Batch 7 measured 3 of 56 offered ids present).
- The original index was **not lost**: the earlier Splunk's `var` volume (`0aa27f8fe380...`, created 2026-09-12, anonymous, mounted by no container) still holds it, with 60 buckets, 2,036 events, 2026-09-12 to 2026-10-09. A hot-bucket fragment is also in `~/AgentSecLab-backups/20261020T173136/` (3 runs; not the specimens). Nothing else on the machine held event bodies: the develop tree's `artifacts/` has none of the ids, no tracked file in the repository holds them (the only `.jsonl` event packs ever committed are the three LAB-MCP-001 ones; no packs were deleted from history), and Splunk's other indexes are empty.

## 2. How they were recovered (isolated; the original volume was only read)
1. The original volume was mounted read-only to copy it into a new scratch volume (`agentsec_recover_var`, labelled).
2. A throwaway Splunk 10.2 container (own name, no published ports, never on the lab's network) opened the copy; the index definition was recreated (`splunk add index`) so Splunk would read the existing buckets.
3. **Method check before exporting anything:** the three LAB-MCP-001 packs already committed in the repository were re-exported from this index and compared: **byte-identical** (`method_check` in `specimen_recovery.json`). So an export is the exact `_raw` the original run produced.
4. Each pack is the verbatim `_raw` of every event of one `agentsec.run.id`, ordered by `agentsec.sequence`. Scanner and garak evidence has its own sourcetypes, so it is stored as recorded HEC envelopes (original time, host, source, sourcetype and event text) one directory deeper.
5. The scratch container and volume were removed afterwards. Reproduce with `scripts/recover_specimens.py`.

## 3. Integrity and schema (every pack)
`agentsec.replay_specimens.validate` returns no problem for all 34 packs: every event carries the run id its file name claims, an event name and a timestamp; `agentsec.sequence` is contiguous from 1; each pack is one run; all events are `LIVE` / `OBSERVED` originals (REPLAY labelling is the lab's presentation, kept); no duplicates (`dc(_raw)` equals the count in the original index and again after seeding). Schema versions recovered are the ones the original phases wrote: 1.1.0 (MCP-003), 1.2.0 (MCP-004), 1.3.0 (MCP-005), 1.4.0 (MCP-006), 1.5.0 (CATALOG, SCANNER), 1.9.0 (incident). They were **not** migrated. SHA-256 of every pack is in `specimen_recovery.json`; `tests/test_batch8_specimens.py` fails if one changes.
**Outcomes match the original validation documents** (mode, profile, event counts, handler executions): BASELINE and vulnerable ATTACK execute the handler (1, or 2 for the follow-on labs), RETEST and unknown-scope/resource runs do not; MCP-005 8/13/12 events, MCP-006 10/10/6, CATALOG 8/13/12, incident 11 and 10, as the documents state. MCP-003 and MCP-004 counts (7/6/7/6 each) are as recovered; their documents recorded handler outcomes, not event totals.

## 4. Per lab
| Lab | Specimens | Roles and event counts (offered runs) | Schema | First event | Verification in the isolated stack | Status |
|---|---|---|---|---|---|---|
| LAB-MCP-003 | 4 offered / 4 total recovered | ATT 7ev; ATT 6ev; BAS 7ev; RET 6ev | 1.1.0 | 2026-09-12… | 40 bound queries, 0 errors, 34 with rows | RESTORED |
| LAB-MCP-004 | 4 offered / 7 total recovered | ATT 6ev; ATT 7ev; BAS 7ev; RET 6ev | 1.2.0 | 2026-09-13… | 44 bound queries, 0 errors, 38 with rows | RESTORED |
| LAB-MCP-005 | 3 offered / 4 total recovered | ATT 13ev; BAS 8ev; RET 12ev | 1.3.0 | 2026-09-14… | 33 bound queries, 0 errors, 30 with rows | RESTORED |
| LAB-MCP-006 | 3 offered / 3 total recovered | ATT 10ev; BAS 10ev; RET 6ev | 1.4.0 | 2026-09-14… | 27 bound queries, 0 errors, 23 with rows | RESTORED |
| LAB-MCP-CATALOG | 3 offered / 3 total recovered | ATT 13ev; BAS 8ev; RET 12ev | 1.5.0 | 2026-09-16… | 27 bound queries, 0 errors, 24 with rows | RESTORED |
| LAB-BLUE-TEAM-INCIDENT-001 | 2 offered / 7 total recovered | ATT 11ev; RET 10ev | 1.9.0 | 2026-09-20… | 2 bound queries, 0 errors, 2 with rows | RESTORED |
| LAB-MULTI-STAGE-INCIDENT-001 | 2 offered / 10 total recovered | ATT 11ev; RET 10ev | 1.9.0 | 2026-09-20… | 2 bound queries, 0 errors, 2 with rows | RESTORED |
| LAB-SCANNER-RUNTIME-EVIDENCE | 3 offered / 3 total recovered | ATT 13ev; BAS 8ev; RET 12ev | 1.5.0 | 2026-09-16… | 18 bound queries, 0 errors, 18 with rows | RESTORED |

Supporting packs beyond the dropdown (cited by the labs' searches or incident files and also recovered): LAB-MCP-004 `9ea63448`, `ccd13a5f`, `ffafb62e`; LAB-MCP-005 `6fe7370c`; the incident labs' write/retrieve runs `2a248113`, `348c8f18`, `3f8d6305`, `db514fd8`, `f9015037` (BLUE-TEAM), plus `3d2b66a1`, `5a15fe04`, `5dd71f94` (MULTI-STAGE); scanner scans `7ae3ea64` (2 events) and `b3061c4e` (1 event); garak evaluation `aeb05718` (2 events). Packs cited by two labs are byte-identical copies (the seeder is idempotent, so a shared pack is indexed once).
The scanner evidence is the **original Phase 9C ingest** (source `agentsec-scanner-hec`, 2026-09-16). The recovered index also holds later re-ingests of the same scans (two other sources, 2026-09-25) with a newer event contract; they were **not** restored, because the lab text (NORMAL finding_count 0, MALICIOUS 1) describes the original and the copies would multiply every count.

## 5. Restore and verification
| Step | Result |
|---|---|
| Seeding mechanism | otel packs: the existing `splunk_hec_init.sh` seeder, unchanged, additive and idempotent ("VERIFIED searchable (n/n)" per run). Scanner/garak envelopes: new `scripts/seed_envelope_specimens.py` (HTTPS with explicit CA and verification on, refuses a partial pack, proves searchability by search not by HTTP 200, idempotent; wired into `lab-up.sh`) |
| Isolated stack (`scripts/cold_start_disposable.sh`) | 44 canonical specimens seeded and searchable; **0 mismatches** between every restored event's `_raw` and its recorded original (44 otel packs by multiset; 3 envelope packs by time, host, source, sourcetype and event text); second run of both seeders did nothing |
| Run selectors and queries (every data source that uses the run token, for every offered specimen) | 193 bound searches, **0 errors**; zero-row panels are the designed negative evidence ("tool after deny", "tool executed" for runs where nothing executed), identical in both environments |
| Splunk Web, every offered specimen | 24 view/specimen states rendered: 0 search errors, 0 "No results found", the selected run shown. The incident labs' evidence tabs show ALLOW+OBSERVE for the ATTACK candidate and DENY+OBSERVE for the RETEST candidate. Screenshots: `views_cold/`, `views_live/` |
| Live lab | seeded additively (index 2,473 to 2,714 events); 34 of 34 packs present with count equal to the pack and no duplicates; **the same 193 queries and 24 views pass in the live Splunk with panel row counts identical to the isolated stack**; no container recreated, volumes identical |
| Instructional outcome | the labs' outcome statements hold on the restored evidence: BASELINE ALLOW with handler, vulnerable ATTACK fail-open ALLOW with handler, defended RETEST DENY with no handler; METADATA/RESULT/MEMORY controls OBSERVE; ERROR for unknown scope/resource; scanner finding counts 0 and 1 |
| Labelling | the labs remain REPLAY; packs are recordings, shown as such. No restored run is presented as a live run |

## 6. Limits
- Restored events are the originals; this machine could not re-measure them. Their event bodies carry the identifiers of the September stack (run ids, trace ids), as the committed MCP-001 packs already do.
- The original volume remains in Docker, unmounted, and is now the only copy of the **whole** September index (2,036 events). Do not delete it until the repository has a copy you trust (back it up: `docker run --rm -v <vol>:/v:ro -v ~/agentsec-backups:/b busybox tar czf /b/splunk-var-sept.tgz -C /v .`).
- Evidence recovered for labs outside the eight (for example PI-001, RAG, MEMORY, GOAL, DELEGATION, CAPSTONE run ids in their dropdowns) still depends on the same volume; they are LIVE labs, so a learner generates fresh runs, but their specimen dropdowns point at September runs that are not committed. Recoverable the same way if wanted.
