# Q-SCANNER-FINDINGS

| Item | Value |
|------|--------|
| Query ID | `Q-SCANNER-FINDINGS` |
| Security question | Did this scan execute, and were scanner-native findings produced? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-16 |
| SPL file | `Q-SCANNER-FINDINGS.spl` |
| Bind token | `__SCAN_ID__` |

## Required fields (indexed names)

Always on scan events: `event.name`, `scan_id`, `scan.finding_count`.

On MALICIOUS scan events only: `scan.classification`.

On finding events only: `finding.native_rule_id`, `finding.native_category`, `finding.native_severity`, `finding.title`, `finding.tool_name`, `finding.analyzer`.

Not indexed (absent from Phase 9B source): `finding.native_confidence`.

## SPL

See `Q-SCANNER-FINDINGS.spl`. Display helper `finding_state` is not a detector.

## Line-by-line explanation

1. Scope scanner sourcetype and one `scan_id` with **no** event.name filter so both scan summaries and findings appear.
2. Collapse scalars.
3. `finding_state` distinguishes `scan_executed_zero_findings`, `scan_executed_with_findings`, and `finding_present`. It does not emit PASS/FAIL.
4. Native severity is copied as-is (`HIGH`). It is not mapped to AgentSec severity or DENY.

## Expected result

NORMAL: one row, `scan_executed_zero_findings`, finding_count 0, empty native fields, empty classification.

MALICIOUS: two rows — scan summary `scan_executed_with_findings` / `DETECTED_BY_SCANNER` / finding_count 1, plus finding row `PROMPT INJECTION` / `HIGH` / `lookup_policy` / `yara_analyzer`.

## Actual result

**VALIDATED** (Splunk CLI CSV, 2026-09-16). Expected states and native fields matched. `finding.native_confidence` was empty because it was not in the 9B finding object.

## Validated run.id / test data

Same Phase 9B packs. Scanner HIGH did not appear as `agentsec.control.decision`.

## Performance notes

Index + sourcetype + scan_id. Lab-cheap. `earliest=0` is lab-only.

## Known limitations

`finding_state` is a display helper. Classification is omitted when the pack value is null. This search does not authorize.

## No-data semantics

| Observation | Meaning |
|-------------|---------|
| 0 rows | No indexed scanner evidence for that `scan_id` (missing / unknown) |
| 1 scan row, finding_count=0 | Scanner executed, zero findings |
| Scan row + finding rows | Scanner executed and reported native findings |
| Empty confidence | Field absent in source, not a hidden PASS |
