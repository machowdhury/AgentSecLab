# UI / UX Review — Blue-Team Incident

Classification: rendering `OBSERVED`; accessibility `PARTIAL`.

Command:

```bash
uv run --extra test python scripts/capture_blue_team_incident.py
```

Evidence: `docs/screenshots/blue-team-incident/final_validation.json`.

## Learner journey

PASS:

```text
Academy Home → L6 Blue Team → Incident → Investigate → Evidence Workbench
→ Hypothesis / conclusion → Path B review → report
```

Academy Home lists the REPLAY incident and states that Capstone remains the last LIVE launcher. All four workbench tabs rendered. INCIDENT does not disclose the attack family, decision, handler count, root cause, or solution. Hints progress direction → source → fields → SPL. Path B is separate.

## Viewports

No document-level horizontal overflow was observed at 1920, 1440, 1280, or 1024 pixels.

At the 1024-pixel / 200%-zoom reflow equivalent (512 CSS pixels), horizontal overflow remains. The measured sources are native Splunk chrome (`layout-header-container` and navigation with a 960-pixel minimum), not the AgentSec Studio grid. Classification remains `PARTIAL`; this is not claimed fixed or screen-reader certified.

## Keyboard and focus

OBSERVED: focus moved from INCIDENT to INVESTIGATE with ArrowRight. The native tab received a visible blue focus indicator. Full keyboard traversal of every native Splunk control was not performed.

## Status, copy, and errors

- Status is textual; meaning does not rely only on color.
- Custom copy control is not applicable; this REPLAY dashboard has no custom run-ID copy widget. Native table text remains selectable.
- NO EVIDENCE guidance rendered on the Evidence tab.
- Dependency-outage injection was not performed in the browser. Splunk/HEC/pack/external-plane failure guidance is present in learner text and offline contracts.

## Answer leakage

PASS by offline contract and browser inspection. Candidate selector labels are neutral (`Candidate 01`, `Candidate 02`). Final ALLOW/DENY, execution, and root-cause interpretation are confined to evidence investigation and Path B.

## Screen reader

`NOT TESTED`. No certification claim.

## Verdict

PASS for bounded local learner use with accessibility classification `PARTIAL` because native Splunk chrome overflows at the 200%-zoom reflow equivalent and screen-reader testing was not performed.
