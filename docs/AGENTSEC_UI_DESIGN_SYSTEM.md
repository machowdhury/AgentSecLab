# AgentSec UI Design System (product)

**Status:** Pre-Phase-14 UI/UX remediation (2026-09-18); still authoritative in Phase 14A and 14B  
**Parent palette:** `docs/AGENTSEC_DESIGN_SYSTEM.md`  
**Studio application:** this file + `docs/AGENTSEC_WORKSHOP_UI_STANDARD.md`  
**Review:** `.cursor/skills/ui-review/SKILL.md`

Phase 14A/14B do **not** change this palette, type scale, or Studio GRID contract. Attack launch remains Attack Service Flask, not a new Splunk visual identity. PortSwigger is pedagogical inspiration only — do not clone it. See `docs/PHASE14A_LEARNING_EXPERIENCE_DESIGN.md` and `docs/PHASE14B_ATTACK_SERVICE_IMPLEMENTATION.md`.

This is not a consumer website. The visual language is enterprise security, SOC investigation, technical learning, and evidence analysis.

---

## Palette (unchanged)

| Role | Hex | Rule |
|------|-----|------|
| Page | `#F6F8FB` | Studio GRID background |
| Card | `#FFFFFF` | Markdown and tables |
| Text | `#17202A` | Body |
| Secondary | `#3D4654` | Captions only if AA |
| Navy | `#0B1F33` | Section headers, table headers |
| Teal | `#007F86` | Focus / accent, not rainbow status |
| Border | `#D9E0E7` | Cards |
| Success / warning / critical | `#2E7D32` / `#B7791F` / `#C62828` | Always with words |

Color is never the only semantic channel.

---

## Typography

LEVEL 1 — Human workshop title (`Direct Prompt Injection`, `Goal / Instruction Integrity`). Splunk XML `<label>` and Studio `title`.

LEVEL 2 — One-sentence purpose (Studio description + header markdown).

LEVEL 3 — Metadata: lab id, LIVE/SIMULATED, schema.

LEVEL 4 — Workshop progression (Studio tabs).

LEVEL 5 — Evidence content (cards, tables).

Technical identifiers are monospace-equivalent in markdown (`run.id`, hashes). Do not truncate the only visible authoritative value. Wrap hashes with `fingerprint_block` where used.

Markdown `fontSize`: `large`. Table headers: navy / white.

---

## Spacing and cards

GRID 1440 / 12. Gutter 8. Cards exist to group a security concept:

- short title
- one purpose
- white background
- consistent padding via Studio markdown
- no nested card overload
- no decorative gradients or random icons

---

## Status vocabulary (text + optional color)

LIVE · SIMULATED  
OBSERVE · ALLOW · DENY · ERROR  
CONTEXT · HUNT · DETECTION · FUTURE · REJECTED  
COMPLETE · PARTIAL · NOT IMPLEMENTED  
INTENTIONALLY VULNERABLE LAB PROFILE

Do not silently redefine these terms. Empty tables are not SAFE, TRUSTED, BLOCKED, or PREVENTED.

---

## Run identifiers

- Learner mode: dropdown labels, not editable UUIDs
- Full UUID remains in evidence cards
- Distinguish RUN ID, CONTENT HASH, TASK HASH
- Hashes are identity, not verdicts

---

## Empty state

Standard: `No indexed event matched this evidence question.` plus the domain-specific not-SAFE sentence already used by each workshop.

---

## Accessibility

Contrast: body `#17202A` on white / page. Status always has words. Heading hierarchy via markdown `#`. Studio tabs are the keyboard path we get from Splunk. We do not claim WCAG certification.

---

## Responsive

Primary: 1440px desktop. Also review 1280 and 1024. 768 may stack via Studio auto-scale; do not claim fully responsive design unless validated.

---

## Dashboard Studio limitations

- Cannot restyle native tab chrome into a custom stepper
- Cannot hide inputs that still need to exist as tokens unless searches use literals
- Dropdown + custom text cannot share one hunt token safely
- Native empty-state graphic may still appear; explanatory copy sits nearby
- GitHub-flavored markdown tables (`| col |`) render as raw pipes in `splunk.markdown`. Use labeled lists for specimen/COMPARE cards.
