# AgentSec UI Design System

**Status:** IMPLEMENTED for first-lab surfaces (AcmeBank, Attack Service, LAB-PI-001 Dashboard Studio)  
**Applies to:** Learner-facing UI. Not Splunk’s own chrome (app bar, login), which we do not restyle.  
**Companions:** `docs/SPLUNK_DESIGN_SYSTEM.md` (Studio application), `docs/SPLUNK_UX_DESIGN.md` (interaction), `.cursor/skills/ui-review/SKILL.md`

This is the **parent** visual contract. Splunk-specific layout rules stay in the Splunk docs. Do not invent a second palette.

---

## What it is

A small, calm, professional system so AcmeBank, the Attack Service, and Splunk workshops look like the same lab — not a game, not a vendor marketing page.

## Principles

1. **Work, not theater.** No neon, no extra gradients, no vanity KPIs.
2. **Labels with color.** Severity is never color alone (ALLOW, DENY, SIMULATED, LIVE, BASELINE, ATTACK, RETEST).
3. **Readable first.** Do not shrink type to fit more panels.
4. **Empty is not all-clear.** Zero rows need an explanation.
5. **Splunk does not authorize.** UI copy must not imply the dashboard DENYs the loan.
6. **Telemetry, not narrative.** “What happened?” comes from fields.

---

## Color tokens

| Token | Hex | Contrast note | Use |
|-------|-----|---------------|-----|
| `bg.page` | `#F6F8FB` | — | Page background |
| `bg.panel` | `#FFFFFF` | — | Cards, Studio panels |
| `text.primary` | `#17202A` | ≥7:1 on white / page | Body, markdown |
| `text.secondary` | `#3D4654` | ≥4.5:1 on page (AA) | Captions. Do **not** use `#5B6573` for small text (fails AA on `#F6F8FB`). |
| `chrome.navy` | `#0B1F33` | White text ≥7:1 | Headers, table headers |
| `accent.teal` | `#007F86` | White text on teal is AA for large/bold controls; body links on white: prefer navy + underline |
| `state.success` | `#2E7D32` | With the word ALLOW / success | Pass |
| `state.warning` | `#B7791F` | With OBSERVE / warn | Incomplete |
| `state.critical` | `#C62828` | With DENY / fail; Attack Service primary action | Attack / deny |
| `state.info` | `#3568A8` | With OBSERVED | Neutral info |
| `track.ml` | `#6B46C1` | MLTK/advanced **only** | Not first lab |
| `border.default` | `#D9E0E7` | — | Cards, tables |

Focus ring: `2px solid #007F86` with `2px` offset on interactive controls.

---

## Type

| Role | Spec |
|------|------|
| UI / workshop | `system-ui, "Segoe UI", sans-serif` |
| Telemetry / `run.id` | `ui-monospace, Menlo, Consolas, monospace` |
| Body | ≥16px equivalent; line-height ≥1.4 |
| Captions | ≥14px; `text.secondary` only if AA |

Splunk Dashboard Studio uses Splunk’s font; we still set markdown `fontColor` to `text.primary` and table header navy/white.

---

## Layout

- **Flask apps:** one column, max width ~760px, navy header, white cards, teal (AcmeBank) or labeled critical (Attack) primary button ≥44px tall.
- **Dashboard Studio:** GRID, 12-column canvas 1440 wide, tabs for workshop steps. Absolute layout only with a written justification.
- Consistent panel height in a row. Long copy wraps in markdown; no overflow.

---

## Components (first lab)

| Surface | Primary action | Must include |
|---------|----------------|--------------|
| AcmeBank | Submit loan (teal) | profile label, `run.id` in result |
| Attack Service | Launch ATTACK (LIVE) (critical **with words**) | attack id, untrusted-client copy, predict-before-launch |
| WS-001 | Submit tokens | Hunt `run.id` defaults to the BASELINE specimen; COMPARE specimen defaults; SIMULATED labeled |

---

## Accessibility (minimum)

- `lang` on HTML.
- Visible labels (not placeholder-only).
- Keyboard reachable primary actions; visible focus.
- Contrast AA for body text.
- Do not rely on color for ALLOW vs DENY vs SIMULATED.
- Empty tables stay visible (`hideWhenNoData` off).
- Motion: none required for first lab.

---

## Empty and mode states

- No Hunt match: “Zero rows is not all-clear and is not DENY.” Hunt `run.id` defaults to the BASELINE specimen so Studio tables run instead of the empty-token error.
- SIMULATED fixture: the word **SIMULATED** in the panel title.
- BASELINE / ATTACK / RETEST labeled as `testbed.mode`, never as `LIVE`.

---

## Out of scope

MLTK purple dashboards, MCP/A2A/RAG chrome, Cisco branding, dark “hacker” theme.

## Review

Run `/ui-review` (`.cursor/skills/ui-review/SKILL.md`) before calling a learner UI complete. Studio completion also requires a screenshot pass (`docs/PHASE2C3_DASHBOARD.md`).
