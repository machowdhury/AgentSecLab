# Splunk Design System

**Status:** APPLIED to LAB-PI-001 (`ws_lab_pi_001`). Parent tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

All new dashboards use Dashboard Studio unless a documented technical limitation requires classic Simple XML. Default layout: **GRID**. Absolute layout only with a written justification.

---

## Color

| Token | Hex | Use |
|-------|-----|-----|
| Background | `#F6F8FB` | Page |
| Primary text | `#17202A` | Body |
| Secondary text | `#3D4654` | Captions (AA). Do not use `#5B6573`. |
| Primary navy | `#0B1F33` | Headers, chrome |
| Accent teal | `#007F86` | Links, focus |
| Success | `#2E7D32` | ALLOW / pass **with label** |
| Warning | `#B7791F` | OBSERVE / warn **with label** |
| Critical | `#C62828` | DENY / fail **with label** |
| Information | `#3568A8` | Neutral info |
| Advanced / ML | `#6B46C1` | MLTK track only |
| Borders | `#D9E0E7` | Panels |

Calm professional appearance. No neon, no extra gradients, no crowded pages, no tiny text, no random panel sizes.

**Severity is never color alone.** Always include a text label (and icon when available): DENY, ALLOW, SANITIZE, OBSERVE, ERROR, SIMULATED, LIVE, BASELINE.

---

## Typography and density

- Readable default font size; do not shrink to fit 51 rows on one screen without tabs or pagination.
- Consistent panel heights in a row.
- Long narrative in markdown panels with wrapping; no overflow.

---

## Workshop page skeleton

HEADER  
WHAT YOU WILL LEARN  
ARCHITECTURE / TRUST BOUNDARY  
BASELINE  
QUERY + EXPLANATION  
EXECUTE ATTACK  
WHAT HAPPENED  
HUNT  
QUERY + EXPLANATION  
BUILD DETECTION  
QUERY + EXPLANATION  
ENABLE CONTROL  
RETEST  
WHAT CHANGED  
BEFORE / AFTER  
EVIDENCE  
FRAMEWORK MAPPING  
KNOWLEDGE CHECK  

---

## Action result block

ACTION  
RUN ID  
STATUS  
WHAT HAPPENED  
AGENTS INVOLVED  
CONTROL DECISION  
IMPORTANT TELEMETRY  
WHY IT MATTERS  
NEXT STEP  

“What happened?” is derived from actual telemetry. Never fabricated prose.

---

## Empty and mode states

- No events: explain baseline not running / HEC not ready — not a fake zero that looks like “all clear.”
- Attack vs defended profile: both must be designed; labels visible.
- SIMULATED: badge on the panel, not a green “blocked” KPI.

---

## Completion checks (when a dashboard is built)

JSON parses; dataSources exist; visualizations exist; tokens exist; searches validated; dashboard loads; layout readable; no overflow; empty states; attack mode; defended mode; screenshot reviewed.

---

## Major decisions

### Decision: Studio GRID, AgentSec palette, no color-only severity

**DECISION:** As specified above. Rebrand away from AgentWatch ACME naming in chrome.

**ALTERNATIVES:** Classic XML dark theme (legacy app); neon “cyber” palette.

**WHY CHOSEN:** Project rule 30. Accessibility and teaching clarity.

**SECURITY CONSEQUENCE:** SIMULATED vs DENY cannot be the same red tile without words.

**LEARNING VALUE:** SOC dashboards should look like work, not a game.

### Decision: MLTK purple is a track cue, not a default accent

**DECISION:** `#6B46C1` only on MLTK/advanced views.

**ALTERNATIVES:** Purple everywhere for “AI.”

**WHY CHOSEN:** Core labs are navy/teal. Advanced track should be recognizable, not noisy.

**SECURITY CONSEQUENCE:** None directly; reduces implying ML is always on.

**LEARNING VALUE:** Optional track is visually optional.
