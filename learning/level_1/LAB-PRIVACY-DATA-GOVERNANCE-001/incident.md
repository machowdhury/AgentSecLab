# AcmeBank Incident PRIV-2026-001

## Report

A customer-support workflow appears to have exposed more customer information
than was required while completing a legitimate task:

> Confirm the synthetic customer's preferred support contact channel.

The tool request may have been correctly authorized. Investigate authorization
and data appropriateness as separate questions.

## Scope

The incident is a deterministic lab comparison:

- one full-record specimen;
- one minimized-record specimen;
- the same granted tool and scope;
- the same fixture-backed downstream handler;
- no LLM call;
- no RAG retrieval;
- no memory write or recall;
- no external provider;
- runtime telemetry copied to Splunk when OTLP is available.

## Questions

1. What data was required for the task?
2. What additional data entered the tool request?
3. Which boundary did it cross?
4. What did CTRL-MCP-001 decide?
5. Did execution start and complete?
6. Which values or field names appeared in telemetry?
7. What changed in the minimized specimen?
8. What remains `NOT MODELED`, `NOT OBSERVED`, or `NOT PROVEN`?

Do not call this a breach. All records are synthetic, and no production impact
is modeled.
