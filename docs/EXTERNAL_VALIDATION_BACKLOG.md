# External validation backlog

**Boundary:** repository reconciliation and local AgentSec execution do not
validate external product, protocol, license, TA/CIM, or framework claims.

All open items below remain `NEEDS_EXTERNAL_VALIDATION`. Closing an item
requires a separately authorized review with an authoritative public source,
source URL, access date, version/date applicability, and a documented change to
the affected AgentSec claim.

1. **garak upstream license** — verify current upstream license text and its
   applicability to the pinned 0.17.0 artifact. Repository pin metadata is not
   the license itself.
2. **garak probe/detector fidelity** — verify the intended semantics of
   `dan.Dan_11_0` and `dan.DAN` against authoritative version-matched material.
3. **Ollama generator behavior/protocol** — verify the garak generator’s
   version-specific API behavior. AgentSec consumes the report; it does not
   implement or certify that protocol.
4. **Splunk TA/CIM mapping** — determine whether any supported TA or CIM model
   genuinely applies. Current AgentSec fields remain custom; no mapping is claimed.
5. **Cisco mcp-scanner native JSON stability** — verify the versioned upstream
   output contract and compatibility expectations beyond the pinned specimen.
6. **OWASP / MITRE ATLAS / MAESTRO / NIST semantics** — verify current terms
   before promoting educational vocabulary or upstream tags into formal mappings.

Until closed, these items must not be represented as VERIFIED, compliant,
certified, endorsed, complete coverage, or native protocol support.
