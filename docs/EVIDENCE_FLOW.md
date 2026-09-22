# Evidence flow

```text
experiment (Attack Service → AcmeBank)
    → runtime events (controls, tools, LLM, memory, RAG)
    → OpenTelemetry export
    → OTel collector
    → Splunk HEC
    → index agentsec_telemetry
    → Search / Q-* hunt
    → interpretation (Path A; Path B is a key)
```

A successful **launch** and successful **indexing** are separate facts.

## Failure points

1. Launch contract ERROR (never reached runtime policy).
2. Runtime DENY/ALLOW/OBSERVE (policy) — independent of Splunk.
3. Handler execution vs non-execution (runtime counts).
4. OTLP export failure (`otlp.ok` is not Splunk success).
5. Collector / HEC down.
6. Index delay.
7. Wrong run.id / index / sourcetype.
8. REPLAY id never present on this volume.

Zero Search rows follow **no-data** semantics. They are not prevention.
