# AgentSec v1.0.0-rc1 — detection review

Implemented detector: **DET-MCP-001** only (disabled saved search). Invariant: authorization DENY then later `mcp.started` for the same run/tool.

Academy language (17C/17D) states no DET-RAG, DET-MEMORY, DET-GOAL, DET-A2A, DET-CAPSTONE. Pytest forbids those names in `savedsearches.conf`.

0 detector rows ≠ SAFE. MCP ATTACK is overlay ALLOW so DET-MCP-001 is expected silent.

SIMULATED positive-control SPL files exist for teaching; they are not live detectors.
