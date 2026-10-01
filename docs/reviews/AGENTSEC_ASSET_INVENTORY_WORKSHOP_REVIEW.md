# Asset inventory workshop — implementation and independent review

Educational DOCUMENTED packet. Not Cisco AI-BOM output. Compatibility NOT CLAIMED.

Components include the configured model name, the unpinned Ollama image, a fixture agent id, `lookup_policy`, the teaching MCP, the package version strings, mcp-scanner, and garak. Trust is not established on any row. Scanner and evaluation rows say they are not authorization.

Focused contracts including academy view registration: 51 passed. Full offline suite: 1058 passed, 3 deselected, 9.83s.

Browser and screen reader: NOT TESTED.

## Independent review

The packet does not invent an AI-BOM schema and does not bump ExternalEvidence. Ollama remains `ollama/ollama:latest` in compose; this workshop records that debt and does not pretend to pin it. Schema 1.9.0 unchanged.

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured. LOW 2: mcp-scanner pin was not re-read in this packet; the row says NOT RE-MEASURED.

Verdict: GO — ASSET INVENTORY WORKSHOP VALIDATED AS A DOCUMENTED LIST.
