# Incident AI-2026-001 Analyst Report

## Executive Summary

State what happened, what was affected, whether an unauthorized action executed, what control stopped or failed to stop it, planned changes, and remaining uncertainty. Do not exaggerate severity.

## What Happened

Separate FACT, INFERENCE, HYPOTHESIS, and UNKNOWN.

## Timeline

List time, source, observation, and evidence identifier. Do not pre-populate the answer.

## Evidence Ledger

For each claim record evidence, qualitative confidence with reason, alternative explanation, and missing evidence.

## Authorization Analysis

Requested authority, coded authority, PDP, decision, reason, and limitations.

## Execution Analysis

Request, authorization, invocation begin, completion/failure, and outcome are separate.

## Root Cause or Likely Contributing Factor

Use `ROOT CAUSE` only if the evidence establishes it. Otherwise use `LIKELY CONTRIBUTING FACTOR`.

## Evidence Gaps

Include `NOT MODELED`, `NOT OBSERVED`, and `NOT PROVEN` items.

## Control Recommendations

Tie each recommendation to an observed gap. Do not propose Splunk as the runtime PDP.

## Residual Risk

State what one ATTACK/RETEST comparison cannot establish.

## Confidence / Limitations

Use HIGH / MEDIUM / LOW with explanation, not false numerical precision.

## Technical Communication

Write for SOC/security engineering with evidence identifiers and SPL.

## Executive Communication

Write for a security leader: what happened, impact, execution status, control behavior, change, and uncertainty.

## Threat-Model Bridge

Asset, actor, entry point, trust boundary, authority, control, observability, missing telemetry, residual risk.
