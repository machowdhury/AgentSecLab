# AGENTSEC — Phase 1 final acceptance

**Phase 1 verdict: PHASE 1 ACCEPTED WITH LIMITATIONS**

**P1.6 verdict: CONDITIONAL GO — READY WITH DISCLOSED LIMITATIONS** (see `AGENTSEC_P1_6_OCT15_RELEASE_CANDIDATE_QUALIFICATION.md`)

Assessed 2026-10-09 on `develop`, starting from `f227708`. Earlier stage verdicts are quoted exactly as recorded and are not changed. The "Phase 1 assessment" column is this report's judgement, as of P1.6, using the evidence available now. Owner acceptance is a separate act and is listed under owner decisions.

This is not a production-readiness assessment.

---

## Stage table

Assessment labels: **Stage execution complete** (work done; no acceptance concluded) · **Accepted** · **Accepted with limitations** · **Not accepted**.

| Stage | Report | Recorded verdict (unchanged) | Phase 1 assessment | Basis |
|-------|--------|------------------------------|--------------------|-------|
| P0 (pre-P1) learner UX | `AGENTSEC_PHASE1_LEARNER_UX_P0_IMPLEMENTATION.md` | "CONDITIONAL — P0 REMEDIATION INCOMPLETE", later "CONDITIONAL — LIVE QUALIFICATION INCOMPLETE" | Stage execution complete | Its LIVE gap was later closed by a measured qualification at `b616af9` (ATTACK 7/ALLOW, RETEST 6/DENY) and by P1.4–P1.6 LIVE runs |
| P1.0 learner experience | `AGENTSEC_P1_LEARNER_EXPERIENCE_IMPLEMENTATION.md` | "P1 IMPLEMENTED — READY FOR OWNER EXPERIENCE REVIEW" | Stage execution complete | Implemented and deployed to EC2 (`49de0f8`); no owner experience-review outcome recorded |
| P1.1 bounded remediation | `AGENTSEC_P1_1_BOUNDED_REMEDIATION.md` | "P1.1 CONDITIONAL — ACCESSIBILITY DECISION REQUIRED" | Stage execution complete | CTA, contrast and deep-link fixes measured; Studio 400% decision deferred to P1.2 |
| P1.2 Studio 400% qualification | `AGENTSEC_P1_2_ACCESSIBILITY_QUALIFICATION.md` | "P1.2 CONDITIONAL — ACCESSIBILITY LIMITATION REQUIRES OWNER DECISION" | Stage execution complete | Owner chose the Option A trial (P1.3). The Studio limitation remains. |
| P1.3 400% Option A trial | `AGENTSEC_P1_3_400_PERCENT_ACCESSIBILITY_REMEDIATION.md` | "Acceptance: CONDITIONAL. Promotion: NO." | Not accepted (candidate not promoted; decision stands) | Mouse gate failed at 400% normal view; accepted dashboard unchanged |
| P1.4 Figma Academy | `AGENTSEC_P1_4_FIGMA_ACADEMY_FINAL_QUALIFICATION.md` | "CONDITIONAL — FUNCTIONAL WITH DOCUMENTED LIMITATIONS" | Accepted with limitations | Its genuine-zoom gap was closed by P1.5 and re-measured on the deployed build in P1.6. VoiceOver remains UNTESTED. |
| P1.5 reliability and accessibility close-out | `AGENTSEC_P1_5_ACADEMY_RELIABILITY_ACCESSIBILITY_CLOSEOUT.md` | "P1.5 CONDITIONAL — FUNCTIONAL WITH REMAINING QUALIFICATION GAPS" | Accepted with limitations | Its durable LIVE index introduced the LIVE-launch lock found in P1.6 (now fixed). HEC routing and persistence were re-measured in P1.6. |
| P1.6 Oct 15 readiness | `AGENTSEC_P1_6_OCT15_RELEASE_CANDIDATE_QUALIFICATION.md` | "CONDITIONAL GO — READY WITH DISCLOSED LIMITATIONS" | Accepted with limitations | Rehearsal, 7/7 Splunk reconciliation, regression and accessibility automation MEASURED on the deployed build |

Phase 1 is accepted with limitations because its central learning outcome now works end to end and is evidence-backed: a beginner can run one MCP authorization experiment through all nine steps, in REPLAY or LIVE, and reconcile it with Splunk. The open items are qualification gaps, not broken functionality.

---

## The ten questions

### 1. Is the demonstration ready?

Yes, with disclosed limitations. Both REPLAY and LIVE were rehearsed on the deployed image `e5dc7f88…` (MEASURED). A LIVE blocker found in rehearsal was fixed and re-rehearsed. The presenter conditions are in RC report §16.

### 2. Is the beginner Academy functional and evidence-backed?

For LAB-MCP-001, yes:

- Nine steps from START to EXPLAIN.
- Every OBSERVED claim cites an event number in a real record.
- Inferences are labelled INFERRED.
- Missing evidence shows as UNAVAILABLE, never as SAFE.
- 0 axe violations, and clean genuine zoom at 400%.

No other lab has an Academy workshop.

### 3. Which controls are validated?

**CTRL-MCP-001 (INV-001).** Validated on fresh LIVE runs in P1.6 and reconciled with Splunk:

- Defended profile: DENY `tool_not_granted` before the handler (`mcp.started` = 0, `pipeline.stopped` = 1).
- Vulnerable profile: intentional fail-open ALLOW, handler started.

Platform guards (MEASURED in P1.6):

- launch allowlist (rejects unknown fields and specimens);
- read-only Academy (405 on writes);
- run-id validation (400/404);
- CSP and security headers.

Controls in other labs were not re-validated in Phase 1's final stage.

### 4. Which labs are operational?

- **Measured operational in P1.6:** LAB-MCP-001, in the Academy, with LIVE and REPLAY.
- **Documented, not re-measured:** the six other LIVE-capable labs (LAB-PI-001, RAG-CONTEXT, MEMORY-001, GOAL-INTEGRITY-001, DELEGATION-001, CAPSTONE-001), plus the REPLAY Studio labs.
- **Degraded:** model-dependent LIVE paths, because the lab model is absent on this host.

See `AGENTSEC_P1_6_CURRICULUM_COVERAGE.md`.

### 5. What is the state of accessibility?

**Flask Academy:**

- genuine Chrome zoom 100/200/400% and 1024×768: clean;
- axe WCAG 2.x A/AA tags: 0 violations;
- keyboard path, skip link and visible focus: working.

All MEASURED.

**Not done:**

- VoiceOver is UNTESTED, so no WCAG conformance claim is made.
- The Splunk Studio view `ws_lab_mcp_001` keeps the P1.2/P1.3 limitation: mouse use at 400% in normal view does not work. Keyboard use works.

### 6. Which enterprise integrations are real?

- **Live:** Splunk Enterprise (lab container), and AgentSec runtime/MCP telemetry via OpenTelemetry → collector → HEC.
- **Validated samples:** scanner findings and garak evaluation packs.
- **Not supported (no product integration):** EDR, NDR, firewall, IdP, cloud audit, Kubernetes, DLP, threat intel, SaaS, HR, and other SIEMs.

### 7. What is incomplete?

- VoiceOver testing.
- Clean empty-stack recovery.
- Re-running `scripts/academy-restart.sh`.
- Restoring the lab model.
- Academy workshops for the other 17 labs.
- Durable progress.
- Enabled or revised detections (DET-MCP-001 is disabled).
- Studio mouse use at 400%.
- Re-measuring the other LIVE labs.
- Verifying the EC2 deployment, which P1.6 did not inspect.

### 8. What is needed before production?

Production is out of scope for this educational range, and this report claims no production readiness. Any production-like use would need, at minimum:

- authentication and authorization on the Attack Service and Academy;
- a deployment threat model and hardened network exposure;
- TLS verification on the collector path;
- secrets management;
- signed and attested evidence;
- multi-user isolation;
- verified backup and restore;
- a screen-reader-tested UI;
- an independent security review.

### 9. What are the Phase 2 priorities?

This is a recommendation for the owner to decide; Phase 2 was not started.

1. Restore the lab model, then re-run and reconcile every LIVE-capable lab with `scripts/p1_6_reconcile_live_evidence.py`.
2. Make a detection-engineering decision for DET-MCP-001, so detection can see fail-open ALLOW.
3. Run human VoiceOver testing on the Academy.
4. Extend the Academy pattern to the next lab, LAB-PI-001 being the natural candidate.
5. Add identity samples correlated to `agentsec.principal.id`.
6. Correlate scanner findings with CTRL-MCP-001 decisions.
7. Rehearse clean-stack recovery on a disposable host.

### 10. Which owner decisions are required?

1. Accept the P1.6 CONDITIONAL GO and its presenter conditions for 15 October.
2. Accept Phase 1 with limitations, and record the owner experience-review outcome left open since P1.0.
3. Accept, or schedule work on, the standing Studio 400% mouse limitation (P1.2/P1.3).
4. Decide whether to restore the lab model before the demo. It is not required for LAB-MCP-001.
5. Decide on DET-MCP-001: keep it disabled, revise it, or enable it in the lab.
6. Decide whether the EC2 deployment should be brought to this commit.
7. Authorise any `main` merge, tag or release. None was done.
8. Approve the start of Phase 2 and its priorities, including whether PyRIT is in scope. Not started.
9. MCP-005 publication stays restricted unless separately authorised.

---

## Boundary

Phase 1 stops here. No merge to `main`, tag, release, Phase 2 work or PyRIT work was performed.
