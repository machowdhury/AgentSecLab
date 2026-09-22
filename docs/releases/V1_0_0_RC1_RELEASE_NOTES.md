# AgentSec v1.0.0-rc1 — release notes

AgentSec is a **local educational** agentic-security learning range. Splunk is the investigation workbench. AcmeBank enforces lab controls. The Attack Service is a closed localhost launcher. Schema **1.9.0**. Product **1.0.0-rc1**.

## Learning capabilities

Academy (Dashboard Studio): Home, Foundations, Context Security, Agent Intent, Capstone, Mastery Check. Path A is Splunk Search. Path B is a review key.

## LIVE domains

Direct Prompt Injection, Tool Authorization, RAG / Retrieved Context, Persistent Memory, Goal / Instruction Integrity, Identity / Delegation, integrated Capstone.

## REPLAY domains

Scope Escalation, Parameter / Resource Authorization, Tool Result Trust, Tool Catalog, Scanner + Runtime Evidence, Confused Deputy.

## Attack Service

Unauthenticated educational localhost service. Launch JSON allows only `lab_id`, `specimen_id`, `mode`, `execution`. Authority-like fields return ERROR `unknown_fields`.

## Controls / detection

CTRL-MCP-001 is the tool PDP. Other CTRL-* as in the ownership matrix. Only DET-MCP-001 exists (disabled). Hunts reconstruct; silence is not SAFE.

## Limitations / reproducibility / disclaimer

See `docs/KNOWN_LIMITATIONS.md` and `V1_0_0_RC1_REPRODUCIBILITY.md`. Intentionally vulnerable educational behavior. Do not expose to untrusted networks.

## Upgrade from development phases

Follow README/QUICKSTART, not `docs/PHASE*.md`. Rebuild images: `./scripts/lab-up.sh --build`. Restage Studio: `--refresh-app`.
