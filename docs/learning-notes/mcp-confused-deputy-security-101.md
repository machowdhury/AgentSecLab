# Confused deputy / delegated authority — security 101

**Status:** Phase 7A design + Phase 7B runtime + Phase 7C Splunk (`docs/learning-notes/mcp-confused-deputy-splunk.md`).  
**Parents:** `docs/MCP006_DELEGATION_MODEL.md`, `docs/MCP006_LAB_SPECIFICATION.md`.

---

## WHAT IS IT?

A **confused deputy** is a component that **really is allowed** to do something — and then does it **for someone who is not allowed to ask**.

In AgentSec MCP-006 the deputy is the **Compliance Agent**. It may look up a harmless customer-tier fixture **for its own work**. That permission is **ambient authority**: power it has because of **who it is**, not because **this caller** handed it a ticket for this operation.

The **Credit Agent** may ask compliance to look up **lending policy**. That is **delegated authority**: an explicit, smaller permission for **this asking relationship**.

The bug is not “compliance cannot call tools.” The bug is “compliance used **its** tools because **credit** asked, without checking whether credit was allowed to ask.”

## WHY DOES IT EXIST?

AI systems increasingly have **more than one agent**. A helper with a wide tool grant is convenient. Convenience is how deputies get confused: the code checks “may **I** (the deputy) call this?” and skips “may **they** (the caller) have me call this?”

That is classic confused-deputy access control (capability systems called it this decades before LLMs). AgentSec must show it as **authorization logic**, not as a model that “got confused” by a prompt.

## HOW IS IT DIFFERENT FROM TOOL AUTHORIZATION?

LAB-MCP-001 asks: may **this agent** call **this tool**?

MCP-006 already assumes the **deputy** often **may**. The new question is **on whose behalf**.

## HOW IS IT DIFFERENT FROM SCOPE AUTHORIZATION?

LAB-MCP-003 asks: may this call use this **scope** (`policy:read` vs `policy:restricted:read`)?

MCP-006 can keep scopes honest and still fail if the **wrong grant set** (ambient vs delegated) is consulted.

## HOW IS IT DIFFERENT FROM RESOURCE AUTHORIZATION?

LAB-MCP-004 asks: may this call touch **this** `policy_id`?

MCP-006’s attack is not “wrong `customer_id`.” It is “credit asked for a **tool** compliance has and credit does not.”

## HOW IS IT DIFFERENT FROM MALICIOUS TOOL-RESULT TRUST?

LAB-MCP-005 asks: can **bytes returned by a tool** mint a new grant for the **same** agent?

MCP-006 does not need a malicious `summary`. The caller is authentic. The deputy is authentic. The request is explicit. The failure is **which authority** the deputy spends.

Same harmless tool `lookup_customer_tier` may appear in both labs. **Different invariant.** MCP-005 = INV-002 (data ≠ authority). MCP-006 = INV-001 (delegated ≠ ambient).

## WHAT IS AMBIENT AUTHORITY?

Power the deputy has **anyway**, for **its** jobs. Example: compliance’s coded set includes `lookup_policy` **and** `lookup_customer_tier`.

Ambient is not evil. Unscoped reuse of ambient **on behalf of others** is the risk.

## WHAT IS DELEGATED AUTHORITY?

Power the **caller is allowed to request** from this deputy, for this operation. Example: credit → compliance may request only `lookup_policy`.

Effective authority on defended path:

```text
effective = delegated set
```

not:

```text
effective = deputy ambient set
```

## WHY CAN A LEGITIMATE DEPUTY BECOME DANGEROUS?

Because it is **trusted**. Attackers prefer a privileged helper to a denied caller. If the helper does not bind the action to the **caller’s** grant, every extra tool on the helper becomes a confused-deputy gadget.

Identity is necessary and not sufficient. Knowing “credit sent this” does not answer “what may credit delegate?”

## WHAT TELEMETRY WOULD A SOC NEED?

Eventually (validated in Phase 7C on schema 1.4.0):

- caller agent vs deputy agent (AgentSec can reuse hop 0 / hop 1 + `delegator.agent.id`)
- CTRL-DELEGATION-001 decision and reason
- **authority source**: `delegated` vs `ambient_deputy`
- whether `mcp.started` happened after DENY (it must not)
- runtime handler counts as **proof** of execution

Splunk **can** see `CTRL-DELEGATION-001` and `authority.source`. It still cannot see `allowed_tools`. Do not pretend a hunt independently answers “what was delegated?” as a tool set. Hunt `Q-MCP-DELEGATION` answers who, source consulted, decisions, and indexed execution.

DET-MCP-001 looks for **MCP DENY then start**. The preferred confused-deputy **ATTACK is ALLOW**. That detector stays silent. That is a teaching point, not a bug in DET-MCP-001.

## WHERE DOES IT SIT IN AGENTSEC?

Designed and implemented as LAB-MCP-006 via `run_mcp_006_invoke`, coded Credit caller and Compliance deputy. CTRL-DELEGATION-001 **before** CTRL-MCP-001 **before** the handler. Schema **1.4.0**. Splunk **validated** in 7C (hunt, not detector). Workshop not started.

## WHAT IS THE TRUST BOUNDARY?

Caller → deputy at CTRL-DELEGATION-001, then the existing MCP authorize boundary.

The model does not authorize. Splunk does not authorize. HTTP JSON must not name the deputy or inject grants.

## WHAT COULD AN ATTACKER CONTROL?

The **requested tool / scope / arguments** on the lab invoke (same as other MCP labs). They cannot set profile, coded grants, caller id, or deputy id via extra JSON fields (existing extra-field reject).

## WHAT CAN GO WRONG?

- Checking only “may the deputy call this tool?”
- Turning authorization **off** and calling that a confused deputy
- Trusting `I am compliance` in the body
- Letting the LLM decide the grant
- Mutating global grants so the next run is contaminated
- Checking after the handler already ran
- Treating identity spoof as the whole lab (too small; that is a negative test)
- Copying AgentWatch prompt regex / DID / global used-scope
- Mapping MITRE techniques from A2A theater without execution

## HOW WILL SPLUNK SHOW IT?

Live Phase 7C: index `agentsec_telemetry`, sourcetype `otel:agentic:json`. Hunt **Q-MCP-DELEGATION** reconstructs caller, deputy (when hop 1 exists), `authority.source`, CTRL-DELEGATION-001, downstream CTRL-MCP-001, and whether `mcp.started` was indexed.

What Splunk **can** prove from the copy: who initiated (hop 0 agent), who acted as deputy on ALLOW paths (hop 1 agent), what tool was requested, what source the control consulted (`delegated` vs `ambient_deputy`), what each control decided, and whether execution-start events arrived.

What Splunk **cannot** prove: the delegated tool set membership (no `allowed_tools`); that the handler never ran (runtime counter is authoritative); that DET-MCP-001 silence means no attack.

Runtime vs telemetry: runtime decides and counts handler invokes. Splunk is a copy for investigation. Duplicate JSON extraction is not duplicate decisions.

A detector is **not** justified yet: `authority.source` is indexed, but grant lists are not. An enum-only notable would be a lab-label detector.

See `docs/MCP006_SPLUNK_VALIDATION.md`.

## SOC LESSON (Phase 7C)

Deputy authority is not caller authority. Compliance may be allowed to look up a customer tier **for itself**. That does not mean Credit may ask Compliance to do it.

Execution does not prove authorization. On ATTACK the handler ran and Splunk shows `mcp.completed`. The caller still was not delegated that tool. The control consulted **ambient deputy** authority (`authority.source=ambient_deputy`) and labeled fail-open.

Runtime and telemetry have different jobs. Runtime enforces CTRL-DELEGATION-001 and counts handler invokes. Splunk stores a copy so a SOC can reconstruct who asked, who acted, what was consulted, and what was decided. Splunk does not block the call.

Splunk **can** prove: caller vs deputy on ALLOW paths, `authority.source`, both control decisions, and whether start/complete events were indexed on a complete copy.

Splunk **cannot** prove: the delegated tool allow-list (not indexed); that a handler never ran (need the runtime counter); that zero DET-MCP-001 rows mean the attack failed.

A new detector is not justified: the important missing fact is still grant membership. `ambient_deputy` is a structured lab label of what the control consulted, not an independent proof that the caller lacked the tool.

---

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-DELEGATION-001: defended consults **delegated** authority. Vulnerable is labeled fail-open: `vulnerable_profile_fail_open:ambient_deputy_authority`. Same request; different profile.

## WHAT TEST PROVES THE LOGIC?

When implementation exists: same ATTACK/RETEST payload; defended handler count 0; vulnerable 1; coded grants unchanged after ATTACK; extra identity fields rejected; no Ollama in the security tests.

---

## What I should now be able to explain

1. What is a confused deputy in one sentence, without mentioning prompts?
2. What is ambient authority vs delegated authority in this lab?
3. Why “the deputy is allowed to call the tool” is the wrong authorization question?
4. How MCP-006 differs from MCP-001, MCP-003, MCP-004, and MCP-005?
5. Why knowing the caller’s identity is necessary but not sufficient?
6. What BASELINE, ATTACK, and RETEST each prove, and why ATTACK/RETEST share one request?
7. Where CTRL-DELEGATION-001 sits relative to CTRL-MCP-001 and the handler?
8. Why DET-MCP-001 will not catch the preferred ATTACK?
9. Why AgentWatch A2A/DID strings are not this control?
10. What Splunk can prove from `authority.source` vs what still requires the runtime grant snapshot?
