# Component provenance

A name on an inventory is not trust. `ollama/ollama:latest` is still unpinned because this workshop did not measure a digest and did not invent one. `flask==3.0.3` is a pin. `pytest>=8.3.0` is a floor.

ATTACK and RETEST ask for `lookup_customer_tier` beside the unpinned image. Only the labeled teaching row treats that as an ALLOW. RETEST denies it. BASELINE allows `lookup_policy` and says the Flask pin did not authorize the tool.

Cisco mcp-scanner remains a finding. garak remains an evaluation. Neither is CTRL-MCP-001.

## What I should now be able to explain

1. Why is a known component not trusted?
2. Why is a scanned component not safe?
3. Why was the Ollama tag not pinned in this change?
4. What is the same in ATTACK and RETEST?
5. Why does a pin not authorize a tool?
