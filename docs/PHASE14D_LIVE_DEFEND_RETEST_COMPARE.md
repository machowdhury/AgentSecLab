# Phase 14D — LIVE DEFEND / RETEST / COMPARE (LAB-PI-001)

**Date:** 2026-09-19  
**Mode:** ARCHITECTURE CORRECTION + IMPLEMENTATION + LIVE VALIDATION + GUIDED LEARNING  
**Reference lab:** LAB-PI-001 / Direct Prompt Injection  
**Schema:** **1.9.0** unchanged. No bump.  
**Do not start Phase 14E from this file.**

---

## Purpose

Complete the first closed-loop AgentSec experiment:

LEARN → PREDICT → BASELINE → ATTACK → INVESTIGATE → UNDERSTAND → DEFEND → RETEST → INVESTIGATE AGAIN → COMPARE → PROVE

Phase 14C provided LIVE BASELINE and ATTACK plus Path A/B investigation. RETEST was blocked because `AGENTSEC_SECURITY_PROFILE` and `AGENTSEC_TESTBED_MODE` were process-global. Mutating them per request would leak between concurrent experiments.

14D introduces a server-owned immutable `ExperimentContext` so ATTACK and RETEST are independent experiments:

SAME adversarial input + DIFFERENT server-owned security configuration = DIFFERENT security outcome.

RETEST is not faked. Canonical REPLAY ids remain Path B answer keys, not this launch.

---

## Process-env root cause

`Settings` is frozen and cached from environment. `inspect_input` and event `agentsec.security.profile` read `settings.security_profile`. `resolve_testbed_mode` prefers `AGENTSEC_TESTBED_MODE` when set. Attack Service 14B required `/health` profile match and refused RETEST so it would not mutate env.

That made concurrent ATTACK (vulnerable) + RETEST (defended) impossible without leaking configuration.

---

## Per-run experiment architecture

```text
LaunchCatalog
    ↓
Server-owned ExperimentDefinition
    ↓
Immutable ExperimentContext
    ↓
AcmeBank /process (experiment_id)
    ↓
dataclasses.replace(settings, security_profile=ctx.profile)
    ↓
CTRL-INPUT-001 → LLM (only if ALLOW) → telemetry
```

Browser JSON is `lab_id`, `specimen_id`, `mode`, `execution` only. Profile is not a launch field.

`POST /process` accepts optional `experiment_id` from the closed set. Payload and `user_id` must match the definition. Unknown or mismatched ids are ERROR — never a silent vulnerable fallback.

Direct `/process` without `experiment_id` keeps the AcmeBank UI auto-mode path.

Process environment is not mutated.

---

## Attack Service security boundary

Selection is metadata. It is not authorization. Rejected: profile, grants, tools, scope, policy, SPL, Python, shell, env, duplicate JSON keys.

`POST /api/compare-handoff` accepts two UUID `run.ids` and returns a server-built Search URL. It does not execute learner SPL.

---

## Evidence classes (do not mix)

| Class | What 14D claims |
|-------|-----------------|
| OFFLINE | pytest of ExperimentContext, launch contract, concurrency, fingerprint, injection |
| LOCAL runtime | Flask `/process` + `/api/launch` with stub LLM |
| LIVE ATTACK / RETEST | restaged containers, fresh `run.id` |
| LIVE SPLUNK | independent `dc(_raw)` on each run.id |
| UI / Playwright | Studio + Attack Service viewports |

HEC 200 is not EVIDENCE READY. Missing Splunk rows are not prevention.

---

## Live results (MEASURED separately from pytest)

| Check | Class | Result |
|-------|-------|--------|
| LIVE ATTACK `7eb9176a-5270-441f-a48a-cf15643e98fc` | OBSERVED | `experiment_id=LAB-PI-001:ATTACK`, profile=vulnerable, hop 0 ALLOW fail-open, 4 LLM, 22 local events, schema 1.9.0 |
| LIVE RETEST `397f10ac-0946-41bd-8441-b66b3b3fab28` | OBSERVED | `experiment_id=LAB-PI-001:RETEST`, profile=defended, hop 0 DENY `input_pattern_matched`, 0 LLM, 6 local events |
| Hop-0 `agentsec.content.hash` | MEASURED | `sha256:88a1ceab989683389193e0aa5f27e7d5ba34fb64a8dd2b5f4af8e4a6caf4b5a5` on both |
| Concurrent ATTACK `bc81644f-…` + RETEST `cb3f09f0-…` | OBSERVED | distinct ids; vulnerable vs defended; no profile leak |
| AcmeBank `/health` after pair | OBSERVED | `security.profile=defended`, `testbed.mode.override=null` (process-global unchanged) |
| Attack Service in-container Splunk probe | OBSERVED | `WAITING_FOR_EVIDENCE` / `evidence_timeout=true` / `splunk_count=null` (`docker_not_available` inside the attack container) |
| Host Splunk CLI ATTACK | LIVE SPLUNK | `dc(_raw)=22`, schema 1.9.0, Q-CONTROL 4 ALLOW, Q-LLM 8, Q-LLM-AFTER-DENY 0 |
| Host Splunk CLI RETEST | LIVE SPLUNK | `dc(_raw)=6`, schema 1.9.0, Q-CONTROL 1 DENY, Q-LLM 0, Q-LLM-AFTER-DENY 0 |
| Offline pytest | OFFLINE | **752 passed, 3 deselected** |

HEC 200 is not EVIDENCE READY. The in-container probe timeout is not a failed attack.

---

## Verdict

**PASS** for LAB-PI-001 LIVE DEFEND / RETEST / COMPARE. RETEST is genuine LIVE. Per-run `ExperimentContext` replaces process-env mutation. ATTACK and RETEST can run concurrently without profile leakage. Splunk remains observability.

**Do not start Phase 14E.**
