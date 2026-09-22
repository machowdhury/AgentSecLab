# LAB-PI-001 knowledge checks

Not a scored LMS. Not certification. Answers use validated PI LIVE/REPLAY facts.

## Checks

### 1. Where is the trust boundary?

Untrusted HTTP becomes a pipeline request at AcmeBank (`acmebank.http_api`). The dangerous operation is Ollama generate (`acmebank.llm_call`). Splunk is observe-only.

### 2. Can Splunk DENY the LLM call?

No. CTRL-INPUT-001 runs inside AcmeBank before generate. Searches read a copy after the fact.

### 3. If DENY happens before invoke, what are attempted / executed / outcome?

`attempted=false`, `executed=false`, `outcome=prevented`. Validated on hop 0 of `78f05d1b-728e-4e70-8993-f5e365871f87`.

### 4. Does ALLOW mean the LLM executed?

No. ALLOW is a control decision. On BASELINE, Q-CONTROL-DECISION shows `executed=false` on ALLOW rows. Q-LLM-EXECUTED shows `executed=true` on `llm.started` / `llm.completed`.

### 5. If Ollama starts then fails, is that prevention?

No. That is `llm.started` + `llm.failed`, `executed=true`, `outcome=error`. It must not be labeled DENY.

### 6. Why is missing `llm.*` in Splunk not enough to prove prevention?

Export can be incomplete. Absence in a partial copy looks like DENY. You need runtime + local completeness, then Splunk as corroboration.

### 7. What does Q-LLM-AFTER-DENY returning zero rows mean on the defended run?

No DENY-then-`llm.*` sequence was observed in that **complete** Splunk copy. It does not independently prove the runtime never called Ollama.

### 8. Is the one-row positive control a real AgentSec incident?

No. It is **SIMULATED** `| makeresults`. It was not indexed (`stats count` = 0 for that synthetic `run.id`).

### 9. Why did `stats count by "agentsec.run.id"` show 66 and 18?

Each unique event has three identical copies of that field (JSON indexed extraction + JSON search-time KV + OTLP attribute). Unique `_raw` counts stay 22 and 6. Completeness is `dc(_raw)`, not a raw field count. Memorizing 66 is not the security skill — over-counting is the trap.

### 10. Is a defended Splunk copy with `testbed.mode=ATTACK` a RETEST?

No. Mode is a label. RETEST is the defended ExperimentContext with the same adversarial bytes. Do not infer RETEST from DENY alone.

### 11. Why is memorizing the ATK-002 string not the security skill?

The skill is: untrusted HTTP can influence the model; CTRL-INPUT-001 decides **before** generate; Splunk copies the decision. The catalog fixture is not a production IOC. Do not treat the payload text as the lesson.

### 12. What happens on the labeled vulnerable ATTACK specimen?

Hop 0 is fail-open ALLOW. Live Ollama **does** run. That is not “the model approved the loan.” ATTACK success is not universal prompt-injection vulnerability.

### 13. Who enforced the ATK-002 decision, and what did Splunk do?

AcmeBank / CTRL-INPUT-001 enforced it. Splunk observed a copy. Splunk did not ALLOW or DENY.

### 14. CTRL-INPUT-001 returned ALLOW. What additional evidence is required before claiming execution?

Runtime LLM invoke count (authoritative). Indexed `llm.started` / `llm.completed` corroborate a complete copy. ALLOW alone is not execution.

## Common wrong answers (do not teach these)

- “Zero Splunk rows means the bank is safe.”
- “ALLOW means four models ran.”
- “The makeresults row is OBSERVED runtime.”
- “Dashboard Studio proved INV-008.” (The view hunts a copy. Runtime remains authoritative.)
- “HEC 200 means EVIDENCE READY.”
- “BASELINE is SAFE.”
- “DENY alone proves the model never ran.”
- “Splunk blocked the loan.”
- “Knowing the ATK-002 wording proves you understand prompt injection.”
