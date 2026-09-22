# UI review — MCP reference pre-build

**Date:** 2026-09-22
**Evidence:** DOCUMENTED / code-and-definition review. No new runtime or browser claim is made here.
**Surfaces:** Attack Service `LAB-MCP-001`; Dashboard Studio `ws_lab_mcp_001`.

## Roles

- **Splunk architect:** existing data sources are bound and existing Q-MCP searches are preserved.
- **SOC analyst:** run.id and the investigation handoff exist, but the primary reasoning chain is fragmented.
- **UX designer:** the Attack page is a narrow documentation column; the HUNT tab is a very tall stacked notebook.
- **Technical instructor:** security distinctions are accurate but repeated so often that the main experiment is obscured.

## Findings

### HIGH — Attack execution is buried in documentation

The shared Attack Service template presents orientation, scope, two prediction sections, specimen detail, execution, handoff, comparison, and raw response as vertically stacked cards. On MCP the learner must scroll through substantial prose before reaching the security decision and comparison.

**Required fix:** create an MCP-only desktop workbench with the security question, closed request context, primary ATTACK/RETEST controls, decision chain, run.id, investigation handoff, and side-by-side comparison above progressive disclosure.

### HIGH — Request, authorization, execution, and evidence lack a single visual chain

The current facts list is semantically careful, but the learner must assemble the sequence from unrelated list rows.

**Required fix:** display `PRINCIPAL → AGENT → REQUEST → AUTHORIZATION → EXECUTION → EVIDENCE`, using runtime handler count for execution and explicitly labeling Splunk as observation.

### HIGH — Path B competes with Path A

The Studio HUNT layout renders every question, both hints, complete solution SPL, and result tables in one long page. The learner cannot reveal Path B; the answer key is visually unavoidable.

**Required fix:** keep existing searches but make the central investigation story concise. Make Path A primary and move hints/solutions to a separate optional Studio area/tab rather than displaying them alongside the mission.

### MEDIUM — ATTACK/RETEST comparison is list-based

The Attack Service comparison reports SAME/DIFFERENT accurately but does not provide aligned ATTACK and RETEST evidence columns.

**Required fix:** aligned comparison rows for fingerprint, request, profile, control, decision, reason, handler count, outcome, and evidence readiness.

### MEDIUM — Raw response disclosure is too narrow

Only the response body is disclosed. Request contract, HTTP status, and starter SPL are not grouped as advanced evidence.

**Required fix:** one `Evidence / Advanced` disclosure containing request contract, response JSON, HTTP/runtime details, and starter SPL.

### LOW — Academy-wide density remains

Home and non-MCP Attack pages retain their existing design. This build intentionally does not propagate the reference pattern.

## Accessibility pre-check

- Existing skip link, labels, focus ring, 44px actions, semantic headings, and non-color status labels are retained.
- New workbench must preserve keyboard order, visible focus, wrapping identifiers, 200% zoom safety, and status text.

## Initial verdict

**REVISE.** Resolve HIGH findings in the MCP reference only, then run rendered browser review at 1920, 1440, 1280, and 1024.
