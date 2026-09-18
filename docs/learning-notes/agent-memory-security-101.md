# Agent memory security 101

**Status:** Phase 11A design. No runtime.

## What is it?

Agent **memory** is state the agent **keeps** so a later run can use it. A preference, a summary, a “remember this.” It is **not** the same as retrieving a document from a knowledge base (RAG). It is **not** `MemorySink`, which is only an in-process list of telemetry events.

## Why does it exist?

Without memory, every visit starts from zero. With memory, a poisoned sentence can still be there **tomorrow**.

## How does it work? (planned lab)

Two runs. Run 1 **writes**. Run 2 **recalls**. Recalled text may cause a **REQUEST**. **CTRL-MCP-001** still decides the **GRANT**.

## Where does it sit in AgentSec?

After RAG. RAG = one-run retrieve (INV-002). Memory = persist then later recall (INV-003). Catalog and scanners stay closed.

## What is the trust boundary?

The memory store. Provenance (`agentsec.memory.fixture`) is **who/where it came from**, not trust. Trust class stays `untrusted_data` until a **separate** promotion exists. This lab has no promotion.

## What could an attacker control?

The **body** of the stored record (lab fixture). Not the allow-list.

## What can go wrong?

Someone treats stored text as an instruction or as `allowed_tools`. Someone collapses write and recall into one run. Someone alerts on “AGENT MEMORY NOTE.” Someone lets ML decide grants.

## What telemetry should exist?

Memory id, hash, short preview, provenance, write run, recall run, OBSERVE, then the usual authz/execution fields. Not the full diary.

## How will Splunk show it?

After we have those fields. Today: **TELEMETRY GAP** for write↔recall joins. Follow-on ALLOW/DENY/start can already be asked **on the recall run** with existing Q-MCP questions.

## What control could change the result?

Deny the follow-on tool. Do not delete the memory and call that “authorization.”

## What test proves the logic?

Same malicious hash on ATTACK recall and RETEST recall. ATTACK executes. RETEST handler 0.

---

## What I should now be able to explain

1. What is the exact INV-003 sentence in this repository?
2. How is persistent memory different from RAG retrieved context?
3. Why does this lab need two `run.id` values?
4. Why is `MemorySink` not agent memory?
5. Why must write and recall be separate evidence?
6. Why is provenance not authority?
7. Why is a distinct CTRL-MEMORY-CONTEXT-001 justified instead of reusing RAG-CONTEXT-001?
8. What does `vulnerable_profile_fail_open:memory_derived_authority` do — and what must it never do?
9. Why is DET-MEMORY not justified in 11A?
10. Why must ML never grant or deny authority?
