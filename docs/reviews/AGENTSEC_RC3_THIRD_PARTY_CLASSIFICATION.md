# Third-party and provenance classification (RC3 gate)

Classifications below were read from the repository during the RC3 gate. They are not new upstream measurements. No Ollama digest was invented. `ollama/ollama:latest` remains unpinned.

| Item | Class | What the repository actually says |
|------|--------|-----------------------------------|
| garak license | NEEDS_EXTERNAL_VALIDATION | `tools/garak/pin.json` records the string `Apache-2.0` for pin 0.17.0. `docs/EXTERNAL_TOOL_ATTRIBUTIONS.md` and `docs/EXTERNAL_VALIDATION_BACKLOG.md` item 1 say that string is not closed upstream license review. |
| garak probe semantics (`dan.Dan_11_0`, detector `dan.DAN`) | NEEDS_EXTERNAL_VALIDATION | Backlog item 2. The workshop treats a garak result as external evidence, not a runtime ALLOW or a safety proof. |
| garak Ollama generator protocol | NEEDS_EXTERNAL_VALIDATION | Backlog item 3. AgentSec consumes a report. It does not certify the generator protocol. |
| Cisco mcp-scanner role | EDUCATIONAL | Static specimen evidence. A scanner finding is not a tool DENY. Specimen version 4.8.4 is the pinned pack in `docs/phase9b-evidence`, not a re-measurement in this gate. |
| Cisco mcp-scanner JSON stability | NEEDS_EXTERNAL_VALIDATION | Backlog item 5. |
| Cisco AI-BOM | NEEDS_EXTERNAL_VALIDATION | The asset-inventory packet says compatibility is NOT CLAIMED. The inventory is a documented teaching list, not a Cisco AI-BOM and not a trust decision. |
| OWASP mappings | EDUCATIONAL | Teaching vocabulary. Backlog item 6. Not a conformance claim. |
| NIST mappings | EDUCATIONAL | Teaching vocabulary. Backlog item 6. Not a conformance claim. |
| MITRE ATLAS mappings | EDUCATIONAL | Attack Service HTML keeps `REQUIRES REVALIDATION` on ATLAS tags. Not a verified mapping. |
| Splunk TA/CIM | NEEDS_EXTERNAL_VALIDATION | Backlog item 4. No TA/CIM mapping is claimed. |
| Ollama image | NEEDS_EXTERNAL_VALIDATION | `docker-compose.yml` uses `ollama/ollama:latest`. No immutable tag or digest was obtained or tested in this gate. The provenance workshop states the pin is NOT RESOLVED. |

VALIDATED in this table means an upstream source was checked and a behavior was executed against that source in this gate. Nothing in the table is VALIDATED. DOCUMENTED means the repository records a pin or specimen without claiming that pin was re-verified here. EDUCATIONAL means the academy uses the name to teach a distinction and does not claim certification.
