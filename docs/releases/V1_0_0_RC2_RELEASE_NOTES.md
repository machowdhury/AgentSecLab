# AgentSec v1.0.0-rc2 — release notes

AgentSec v1.0.0-rc2 is a **local educational** agentic security academy. It is not final `v1.0.0` and not a production security product.

Splunk is the investigation workbench. AcmeBank runs the lab controls. The Attack Service is a closed localhost launcher and does not authorize tools. Schema **1.9.0**. ExternalEvidence **1.0.0**. Package **1.0.0rc2**. Splunk app **1.0.0-rc2**.

`main` and annotated tag `v1.0.0-rc1` remain the earlier baseline (peeled commit `e6115b6d1c03a1672b4364e84748c7840671fbfc`). That tag does not contain L6–L10. This candidate is `develop` and tag `v1.0.0-rc2`.

## What changed since RC1

RC1 taught through the L5 LIVE Capstone and an unscored Mastery Check. RC2 keeps that path and adds the later academy that was already built on `develop`, then aligns the README and lab matrix with it.

| Area | How a learner meets it | What it is not |
|------|------------------------|----------------|
| Learner entry | README, Quickstart, and the lab matrix name L0–L10 | A new runtime |
| RAG, memory, goal, identity | LIVE labs already in RC1, still LIVE | Tool authorization. CTRL-MCP-001 remains the tool PDP |
| L5 Capstone | LIVE Lending Assistant Investigation. Last launcher | The L10 case |
| External evidence | REPLAY workshops for Cisco mcp-scanner (Cisco AI Defense) and garak (NVIDIA) | A second PDP. HIGH is not DENY. A pass is not safe |
| Blue team and threat hunting | REPLAY incident AI-2026-001 | A fresh attack |
| Threat modeling | Static reasoning. The workshop adds no attack | A compliance score |
| Privacy | REPLAY incident PRIV-2026-001 | A privacy certification |
| Multi-stage incident | REPLAY incident AGENT-2026-009 | Proof that goal or identity failed. Those controls are not observed in that packet |
| Advanced Capstone | REPLAY MASTER-2026-001 | A certificate. Mastery Check stays a separate unscored self-check |

The seven LIVE labs are unchanged. No new detector was installed. DET-MCP-001 stays disabled.

## LIVE labs

Direct Prompt Injection, Tool Authorization, RAG / Retrieved Context, Persistent Memory, Goal / Instruction Integrity, Agent Identity / Delegation, L5 Capstone (Lending Assistant Investigation).

## Not LIVE

Scope Escalation, Parameter / Resource Authorization, Tool Result Trust, Tool Catalog, Scanner + Runtime Evidence, External Security Toolbox (garak), Confused Deputy, Blue Team, threat modeling, privacy, L9, and L10. L0, L4, and Mastery Check are reasoning or self-check, not launches.

## Limitations

See [../KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md). Clean-room installation is not proven. Screen-reader coverage is not a WCAG claim. Path B is visible. Early mission cards may show an expected ATTACK outcome. Empty search results are not safe.

## Where to start

[../../README.md](../../README.md) and [../QUICKSTART.md](../QUICKSTART.md). Do not use `docs/PHASE*.md` as the install path.
