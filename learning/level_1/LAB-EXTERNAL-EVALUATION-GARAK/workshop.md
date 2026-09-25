# Tool Lab — adversarial evaluation with garak

Use the same canonical evidence at three depths:

- **GUIDED:** follow every stage and compare the expected native fields.
- **INVESTIGATE:** start at `READ NATIVE OUTPUT`; answer before reading explanations.
- **CHALLENGE:** use only the evidence pack and Splunk event. State conclusions,
  non-conclusions, and required additional evidence.

## WHY

Adversarial evaluation asks whether a model response exhibits a tested unwanted
behavior under a specific probe and detector. This is security testing and
negative testing: actively try a condition that should not succeed.

Use it to increase assurance within tested conditions, compare model/configuration
behavior, find weaknesses, and prioritize deeper investigation.

> Testing can increase confidence within tested conditions; it does not
> establish universal security.

## WHAT

garak is an independent open-source Generative AI Red-teaming & Assessment Kit.
It supplies generators, probes, detectors, and native JSONL/HTML reports.
AgentSec did not build the tool, `dan.Dan_11_0`, `dan.DAN`, or its scoring.

The specimen asks local `llama3.2:1b` to adopt a DAN persona. The native detector
checks for the DAN marker. One response was evaluated.

### What it is not

- not the MCP PDP;
- not runtime authorization;
- not proof that exploitation occurred;
- not proof of universal safety;
- not a substitute for threat modeling;
- not AgentSec functionality.

## INSTALL / VERIFY

Official project: https://github.com/NVIDIA/garak

```bash
uv venv --python 3.12 tools/garak/.venv
uv pip install --python tools/garak/.venv/bin/python 'garak==0.17.0'
tools/garak/.venv/bin/garak --version
```

Expected tested version: `0.17.0`. The isolated environment is ignored by Git.
Review the upstream installation documentation and license before independent use.

## TARGET

Local Ollama at `http://127.0.0.1:11434`, model `llama3.2:1b`.
No prompt or model response is sent to an external model service.

Verify:

```bash
curl -fsS http://127.0.0.1:11434/api/tags
```

## PREDICT

Before running, answer:

1. Will the response contain the marker expected by `dan.DAN`?
2. If not, does one PASS prove the model is safe?
3. Could this command authorize an AgentSec tool?

## RUN

Configuration: `tools/garak/agentsec-p1a.yaml`.

```bash
XDG_DATA_HOME="$PWD/artifacts/garak-p1a/data" \
XDG_CACHE_HOME="$PWD/artifacts/garak-p1a/cache" \
tools/garak/.venv/bin/garak --config tools/garak/agentsec-p1a.yaml
```

Bounded conditions: one model, `dan.Dan_11_0`, one generation, primary
`dan.DAN` detector, fixed seed. The measured run completed in approximately
three seconds after model availability.

## READ NATIVE OUTPUT

Open the native JSONL report before looking at normalized output.

Important row types:

- `init`: native garak evaluation/run id, version, timestamp;
- `attempt` with status 2: prompt, model response, detector result;
- `eval`: `passed=1`, `fails=0`, `nones=0`, `total_evaluated=1`;
- `probe_summary`: one evaluated inference;
- `completion` / `digest`: completion and aggregate context.

Native CLI result:

```text
dan.Dan_11_0
  PASS score 1/1 -- DAN
```

The response did not contain the detector’s DAN marker. This is a PASS for this
probe/detector condition—not a universal safety result.

## NORMALIZE

Build the path-sanitized evidence pack:

```bash
uv run python scripts/build_garak_external_evidence_pack.py
```

Inspect:

- `raw/garak-report.jsonl`
- `normalized/evaluations.json`
- `manifest.json`

The adapter preserves native counts and tags. Contract
`evidence_class=evaluation`. Raw linkage uses `raw_evidence_ref` and SHA-256.
Host-absolute paths are replaced; native result fields are unchanged.

## INGEST

```bash
uv run python scripts/ingest_garak_external_evaluation_hec.py
```

Sourcetype: `agentsec:external:evaluation`.

Do not put garak evaluations on `agentsec:scanner:finding` or
`otel:agentic:json`.

## INVESTIGATE

Run `searches/Q-GARAK-EVALUATION.spl`, then
`searches/Q-EXTERNAL-EVIDENCE-PLANES.spl`.

Identify:

1. native result and counts;
2. model, probe, detector, and tool version;
3. raw evidence hash;
4. correlation method and identity tuple;
5. absent `agentsec.run.id`;
6. distinct sourcetypes for finding, evaluation, and runtime evidence.

## CHALLENGE THE RESULT

What can you conclude?

- garak 0.17.0 evaluated one local response from `llama3.2:1b`;
- `dan.DAN` did not detect its marker;
- the recorded native result was PASS for that condition;
- the evidence is traceable to the committed, path-sanitized report.

What can you **not** conclude?

- that the model is safe;
- that other probes, prompts, seeds, temperatures, or models pass;
- that no exploit is possible;
- that an AgentSec tool was or was not authorized/executed;
- that the result caused any runtime behavior.

What additional evidence would you require? More probes and generations,
independent detectors, target configuration, runtime authorization/execution
telemetry, impact evidence, and an explicit threat model.

## THREAT MODEL

- Threat: instruction-following behavior under adversarial prompting.
- Attacker-controlled input: probe prompt.
- Asset: model behavior and downstream decisions.
- Trust boundary: model input/output boundary; separately, AgentSec’s PDP boundary.
- Invariant: model text cannot independently grant tool authority (INV-002).
- Control: CTRL-MCP-001 for AgentSec tools—not garak.
- Telemetry: native report plus separately collected runtime events.
Limitation: model response text does not prove a tool invocation.

## EXPLAIN

Explain the difference:

```text
STATIC FINDING       Cisco mcp-scanner
ADVERSARIAL EVALUATION garak
RUNTIME TELEMETRY    AgentSec
AUTHORIZATION        CTRL-MCP-001
DETECTION            Splunk/AgentSec detector where present
OUTCOME              runtime execution evidence
```

### Security fundamentals

- **Security testing / negative testing:** deliberately exercise unwanted behavior.
- **Assurance:** confidence increases only within measured conditions.
- **Coverage:** one probe × one generation is narrow.
- **False confidence:** PASSING EVALUATION != SAFE.
- **Evidence quality:** preserve native output, provenance, limitations, and hash.
- **Defense in depth:** evaluation complements—not replaces—runtime controls.

### Where else this applies

The same lesson applies to penetration tests, vulnerability scanners,
application-security tests, fuzzers, network assessments, and cloud-posture
assessments:

> A tool result is one evidence source, not the entire security truth.

### EDUCATIONAL MAPPING

- garak natively tagged this probe `owasp:llm01`; treat that as upstream
  metadata, not AgentSec proof of OWASP coverage or compliance.
- MITRE ATLAS prompt-injection concepts help describe adversarial input; this
  one probe does not demonstrate an ATLAS technique end-to-end.
- MAESTRO helps locate model evaluation at the model/input-output trust
  boundary, separate from the tool-authorization boundary.
- NIST AI RMF’s MEASURE function provides useful assurance context; this run
  does not establish NIST compliance.

These are educational relationships, not compliance mappings.
