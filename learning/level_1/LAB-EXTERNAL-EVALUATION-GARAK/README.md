# LAB-EXTERNAL-EVALUATION-GARAK

**Tool:** garak 0.17.0, integrated—not built—by AgentSec
**Official project:** https://github.com/NVIDIA/garak
**License metadata:** repository pin records Apache-2.0; current upstream text is `NEEDS_EXTERNAL_VALIDATION`
**Evidence class:** `evaluation`
**Sourcetype:** `agentsec:external:evaluation`
**Runtime schema:** 1.9.0 — unchanged
**Mode:** local execution instructions plus a MEASURED canonical specimen

This bounded Tool Lab teaches how to operate and interpret an adversarial model
evaluation. It is not a garak certification course.

## Architecture

```text
local Ollama model
      ↑
garak probe → native detector → JSONL report
                              ↓
                      garak adapter
                              ↓
               ExternalEvidence evaluation
                              ↓
                  pack → HEC → Splunk
```

The model evaluation path is separate from AgentSec runtime authorization:

```text
AgentSec request → CTRL-MCP-001 → execution / outcome
```

garak is not CTRL-MCP-001, Splunk, or AgentSec.

## Learning outcomes

You should be able to:

1. Explain why adversarial evaluation is negative security testing.
2. Run a bounded garak probe against your own local model.
3. Read native `attempt`, `eval`, and `probe_summary` JSONL rows.
4. Distinguish a garak PASS from universal model safety.
5. Explain why model output is not runtime tool execution.
6. Trace normalized evidence back to raw JSONL by SHA-256.
7. Use identity-tuple correlation without inventing an AgentSec run ID.
8. Compare static findings, model evaluations, runtime controls, detections, and outcomes.

See `workshop.md` for the guided flow and `knowledge-check.md` for review.
