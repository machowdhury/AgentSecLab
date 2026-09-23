# Context Security experiment workbenches

## What is it?

Two compact experiment interfaces that teach how external context can influence an agent without becoming authority:

- RAG: `RETRIEVED != TRUSTED`
- Persistent Memory: `STORED != TRUSTED` and `RECALLED != AUTHORIZED`

They reuse the MCP workbench's visual grammar, not its security conclusion.

## Why does it exist?

RAG and Memory previously exposed correct evidence in long learner pages and ten-tab workshops. That made it easy to miss the domain-specific trust boundary. Context Security needs to show where bytes enter, how they retain provenance and trust labels, what influence follows, and which later control actually decides tool authority.

## How does it work?

RAG presents:

```text
SOURCE → RETRIEVAL → CONTEXT → CTRL-RAG-CONTEXT-001 OBSERVE
       → AGENT EFFECT → CTRL-MCP-001 AUTHORIZATION → EXECUTION → EVIDENCE
```

Memory presents:

```text
WRITE RUN → PERSIST → RECALL RUN → source_run_id
          → CTRL-MEMORY-CONTEXT-001 OBSERVE
          → INFLUENCED REQUEST → CTRL-MCP-001 AUTHORIZATION → EXECUTION
```

ATTACK and RETEST use the same canonical malicious bytes in each domain. The context controls remain OBSERVE. The intentionally vulnerable profile creates a labeled context-derived tool overlay; the defended profile does not. CTRL-MCP-001 therefore ALLOWs the ATTACK follow-on request and DENYs the RETEST request. The runtime handler count—not ALLOW or DENY alone—establishes execution in this deterministic lab.

## Where does it sit in AgentSec?

- Attack Service: closed LIVE launcher and evidence-oriented learner view
- AcmeBank runtime: retrieval/memory operations, controls, tool authorization, handlers
- OpenTelemetry: evidence transport
- Splunk Dashboard Studio: MISSION, Path A investigation, evidence, optional Path B answers

Splunk does not enforce the result.

## What is the trust boundary?

The browser may select only the allowlisted lab, specimen, mode, and LIVE execution. It cannot submit document or memory bytes, trust, profile, grants, policy, run IDs, control decisions, or execution outcomes.

RAG's boundary is where retrieved bytes enter agent context. Memory adds a time boundary: untrusted bytes are written in one run and recalled in a later run.

## What could an attacker control?

In these deterministic specimens, the modeled attacker influence is the canonical retrieved document or persisted memory content. The attacker does not control authoritative runtime metadata, policy, or correlation IDs.

## What can go wrong?

- Treating provenance as authority
- Treating persistence as trust
- Treating recall as authorization
- Treating a context OBSERVE as MCP ALLOW
- Treating ALLOW as execution
- Treating DENY or a missing Splunk row as proof of non-execution
- Combining Memory WRITE and RECALL event counts
- Describing equal content hashes as equal experiments

## What telemetry should exist?

RAG needs retrieval identity, content hash, provenance, context trust, context-control result, follow-on request, MCP authorization, handler evidence, run.id, sequence, profile, and mode.

Memory needs separate WRITE and RECALL run IDs, memory identity, content hash, provenance, trust, `source_run_id`, memory-control result, follow-on request, MCP authorization, handler evidence, and separate event counts for each run.

## How will Splunk show it?

Path A begins with the selected server-owned ID or Memory run pair. Validated Q-RAG, Q-MEMORY, and Q-MCP searches reconstruct context and tool evidence. Splunk event completeness is measured with unique raw-event counts; HEC acceptance alone is not completeness.

## What control could change the result?

The RAG and Memory controls classify context and emit OBSERVE. They do not decide tool authority. CTRL-MCP-001 decides the later tool request from server-owned grants. The vulnerable overlay exists only as a labeled educational mechanism.

## What test proves the logic?

Deterministic security tests prove trust classification, closed launch fields, source correlation, pre-handler authorization, and handler counts. Fresh LIVE pairs measure the running system. Splunk queries corroborate those runs only after local and indexed event completeness is compared.

## What I should now be able to explain

1. Why does retrieval not make content trusted?
2. Why does provenance not grant authority?
3. Why does persistence not make memory trusted?
4. How does `source_run_id` link Memory WRITE and RECALL?
5. Why must WRITE and RECALL event counts remain separate?
6. Why is OBSERVE not ALLOW?
7. Which control decides the follow-on tool request?
8. Which evidence establishes handler execution?
9. What exactly does fingerprint equality prove?
10. Why is Splunk evidence rather than enforcement?
