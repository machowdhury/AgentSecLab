# Request-scoped handler evidence

## What is it?

A count of tool-handler begins that belongs to one run. It answers "did this request start `lookup_customer_tier`?" It does not answer "did any request in this process start that tool while I was running?"

## Why does it exist?

AgentSec treats runtime handler evidence as authoritative for "did the handler start?" A process-wide counter cannot support that claim when two labs run at the same time. Authorization stays with CTRL-MCP-001. The count is evidence after that decision. It does not make the decision.

## How does it work?

`McpServer.execute` returns `ServerExecution.began`. That flag is true only when that call entered `ToolRegistry.call_handler`. The pipeline copies it onto the hop for that call. `request_handler_counts` adds those hop flags. `ToolRegistry.invoke_counts` still increments, and it remains a process-wide diagnostic. Learner-facing `handler_invoke_count` and `lookup_customer_tier_handler_count` come from the hops, not from subtracting two snapshots of the process counter.

## Where does it sit in AgentSec?

It sits in the MCP server execution result and in the RAG, memory, identity, MCP, and delegation pipelines that publish runtime counts. Splunk still only observes. The tool policy decision point is unchanged.

## What is the trust boundary?

The boundary is `acmebank.mcp.authorize`, before the handler. The count is on the execution side of that boundary.

## What could an attacker control?

An attacker can send a tool request. The attacker cannot choose another run's handler count, and cannot turn a count into an ALLOW.

## What can go wrong?

A process-wide before/after snapshot can attribute another run's handler begin to this run. A lock around that snapshot would hide the race by stopping concurrent runs. It would still be the wrong question. `began == false` does not by itself prove a downstream resource was unchanged.

## What telemetry should exist?

Each run keeps its own `run.id`. `agentsec.mcp.started` is emitted for the call that is about to execute. The runtime count on the launch response is the request-scoped hop count.

## How will Splunk show it?

Search the `run.id`. A decision event and an `mcp.started` event are different events. Splunk does not authorize the tool.

## What control could change the result?

CTRL-MCP-001. On the defended RETEST teaching case, the ungranted tool is DENY and this request's handler count stays 0. On the vulnerable ATTACK teaching case, the labeled fail-open can ALLOW and this request's handler can begin. ALLOW is not execution. Execution is not a measured resource impact.

## What test proves the logic?

`test_concurrent_rag_attack_and_retest_do_not_leak_profile` still requires the RETEST handler count to be 0 while an ATTACK runs beside it. `test_concurrent_rag_attribution_is_request_scoped` checks ATTACK, RETEST, and mixed batches. The assertions were not weakened.

## What I should now be able to explain

1. Why a process-wide counter is not request evidence.
2. What `ServerExecution.began` means, and what it does not mean.
3. Why a lock around the old snapshot would not be the attribution fix.
4. Where CTRL-MCP-001 sits relative to the handler count.
5. Why a RETEST count of 0 does not prove a resource was unchanged.
6. Why an ATTACK ALLOW does not prove the handler ran.
7. Which counter is safe to use as a process diagnostic.
8. How two concurrent runs can invoke the same tool name without sharing a count.
