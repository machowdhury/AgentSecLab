# AgentSec RC2 learner-entry and release-identity remediation

**Date:** 2026-09-26
**Mode:** documentation alignment only. No runtime, schema, contract, detector, UI, or tag change.
**Starting commit:** `7eece6ba719a60870e0c0cf08cb6729d4b7e3c67` (local audit commit on `develop`; not on `origin/develop` at the start of this phase)
**Reviewed product baseline:** `b750f189e129478c53cfa33389967e06fa35ee04`
**Audit:** [AGENTSEC_HOLISTIC_LEARNER_JOURNEY_RC2_READINESS.md](AGENTSEC_HOLISTIC_LEARNER_JOURNEY_RC2_READINESS.md)
**This commit:** the git object that adds this file. The SHA is recorded after the commit, in the phase response. It is not written here in advance.

## What changed

Learner-entry documents now describe the academy that exists on `develop`.

| File | Change |
|------|--------|
| `README.md` | Release identity, L0–L10 map, LIVE/REPLAY/static/simulated, L5 vs L10 vs Mastery Check, Splunk and external-evidence roles, non-claims, known limitations |
| `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` | Full exercise matrix for the current academy, including garak and L6–L10 |
| `docs/QUICKSTART.md` | Checkout is `develop`. After the first lab, continue past L5. Specimen ids are not this launch. |
| `docs/GETTING_STARTED.md` | Same ref distinction, still points at Quickstart |
| `docs/LIVE_VS_REPLAY.md` | Published lab list matches `develop`, including static reasoning and simulated data |
| `docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md` | Header distinguishes the RC1 tag from `develop`. The is/is-not list is unchanged in substance. |
| `docs/KNOWN_LIMITATIONS.md` | Limits still apply on `develop`. Screen-reader coverage called out as partial. |
| `docs/INSTRUCTOR_GUIDE.md` | One step clarified so “Capstone” is L5, not L10 or Mastery Check |

No application, test, dashboard, curriculum JSON, schema, or navigation file was edited.

## Release identity

MEASURED at the start of this phase:

| Ref | SHA | Meaning |
|-----|-----|---------|
| `HEAD` | `7eece6ba719a60870e0c0cf08cb6729d4b7e3c67` | Audit commit, local `develop` only |
| `origin/develop` | `b750f189e129478c53cfa33389967e06fa35ee04` | Last pushed product commit |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | RC1 baseline |
| `v1.0.0-rc1` object | `1aafacb02f4429f168fbdce61437dc37d4cfc74b` | Annotated tag (`git cat-file -t` = `tag`) |
| `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Peeled commit. Same as `main`. |

Classification of the tag: EXPECTED ANNOTATED-TAG BEHAVIOR. The tag was not moved.

`develop` is post-RC1 development containing L0–L10. It is not called RC1 in the learner entry. It is not called RC2. No RC2 tag was created. Package strings `1.0.0rc1` and Splunk `1.0.0-rc1` were left in place and explained as unbumped metadata.

## Curriculum alignment

DOCUMENTED from `learning/academy/curriculum.json` and OBSERVED from Academy Home.

| Level | Title used in the README |
|-------|--------------------------|
| L0 | Orientation |
| L1 | Input and tool authority |
| L2 | Context and evidence are data |
| L3 | Intent and identity |
| L4 | Investigation craft |
| L5 | Integrated purple team — L5 Capstone, Lending Assistant Investigation |
| L6 | Blue-team investigation and threat hunting |
| L7 | Threat modeling and security architecture |
| L8 | Privacy, data protection and agentic data governance |
| L9 | Multi-stage agentic attack, investigation and defense |
| L10 | Advanced capstone and mastery — MASTER-2026-001 |

Mastery Check remains the unscored view `ws_agentsec_mastery`.

## LIVE versus REPLAY

Seven LIVE labs verified from `known_lab_ids()` in this phase (MEASURED):

`LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`, `LAB-MEMORY-001`, `LAB-AGENT-GOAL-INTEGRITY-001`, `LAB-AGENT-DELEGATION-001`, `LAB-AGENTSEC-CAPSTONE-001`.

The count was not changed. REPLAY workshops are labeled not launchable. L7 is described as static reasoning. The curriculum file still stores that workshop’s mode as REPLAY because it is not a launcher; the matrix says so instead of pretending the JSON field changed.

LIVE dashboards may show canonical specimen ids. The README and quickstart tell the learner to use the `run.id` from the launch they just made. Dashboards were not edited.

## Semantics preserved

ATTACK, RETEST, and BASELINE stay bounded comparisons. OBSERVE is not authorization. ALLOW is not success. DENY is not safe. CTRL-MCP-001 remains the tool PDP in the explanation. Splunk and external evidence stay downstream. Cisco mcp-scanner is attributed to Cisco AI Defense. garak is attributed to NVIDIA. AgentSec does not claim to have built either tool. Garak license reconciliation was not started.

## Before / after consistency

| Claim | Before (DOCUMENTED) | After (DOCUMENTED) |
|-------|---------------------|--------------------|
| What `develop` is | README called the tree a v1.0.0-rc1 candidate | `develop` is post-RC1 and not RC2 |
| What RC1 is | Easy to confuse with the current academy | Tag peels to `main` at `e6115b6d…` |
| Academy length | README and matrix ended at L5 plus Mastery Check | README, matrix, quickstart, and instructor step name L0–L10 |
| Capstone | One word for three endings | L5 Capstone, L10 Advanced Capstone, Mastery Check |
| LIVE count | Seven, in code; matrix omitted later REPLAY rows | Seven, unchanged, and listed |
| garak | Missing from the matrix | REPLAY row, NVIDIA attribution |
| Clean-room | Unproven in known limitations | Still unproven |
| Certification | Not claimed | Still not claimed |
| Path B | Visible, disclosed in known limitations | Still visible; not gated |

Historical RC1 release notes and the prior audit were not rewritten.

## Preserved limitations

- Path B is visible pedagogical guidance, not access control.
- No certification.
- Clean-room install is not proven. This phase did not run one. Class: NOT PROVEN.
- Screen-reader coverage remains partial / not fully tested. This smoke check did not use a screen reader. Class: NOT TESTED. Not a WCAG claim.
- Production authentication and cryptographic delegation are not modeled.
- Universal effectiveness is not claimed.

## Deferred findings

Left untouched because they need UI, curriculum, or release-process work outside this phase:

- Early mission cards that state the expected ATTACK outcome. KNOWN — DEFERRED.
- Visible Path B as a UX change. Preserved on purpose.
- Splunk progression from pasted `run.id` to independently written search, and the L6 jump. Not redesigned.
- A full glossary merging the two evidence vocabularies. README has one short distinction only.
- GitHub default branch remains `main`. Documented. Not changed.
- Package and Splunk version strings remain `1.0.0rc1` / `1.0.0-rc1`. Documented. Not bumped.
- Clean-room measurement.
- Screen-reader pass.
- Ollama image pin and garak license versus the external-validation backlog.
- External-validation backlog items (framework identifier revalidation, scanner JSON stability, probe fidelity).
- Placeholder saved searches and historical PHASE discoverability.

## Future architecture horizon

Not implemented. Future curriculum may teach production topics as design input, not as current lab capability:

- Foundation security: input trust, RAG and vector authorization, output validation, data minimization.
- Agent execution security: non-human identity, JIT credentials, tool authorization, downstream authorization.
- Multi-agent security: agent-to-agent authentication, delegation, integrity, replay protection.
- Human control: human-in-the-loop, high-risk approval, blast-radius containment.
- Evidence architecture: stronger provenance, audit integrity, forensic traceability.

Current lab capability, educational model, simulated data, replayed evidence, not modeled, and not proven stay separate from that horizon.

## Tests

Focused documentation and compose-doc tests: `9 passed` in 0.02s (`tests/unit/test_phase17d_release.py`, `tests/splunk/test_local_compose_provisioning.py`).

Full offline suite:

```text
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
1027 passed, 3 deselected in 10.67s
```

Class: TESTED. Zero failures. Tests were not edited.

## Browser smoke

OBSERVED on the existing local lab (HTTP 200 for Splunk, Attack Service, and AcmeBank health). Not a clean volume. Not a clean room. Viewport 1440. UI was not modified.

| Surface | Result |
|---------|--------|
| Academy Home | Loaded. START text includes LIVE, REPLAY, Mastery Check, Advanced Capstone, Direct Prompt Injection, and the word Capstone. Literal `L0` / `L10` were not in the default tab text at 5 seconds. Those strings live on the PATH tab in the dashboard source. |
| Direct Prompt Injection | LIVE workshop. Tabs include BASELINE, ATTACK, RETEST. Path B text is present. |
| Blue Team | REPLAY. Incident id AI-2026-001. Answer tab label is `PATH B · ANSWERS`. |
| External Security Toolbox | garak text present. Path B is not a tab with that exact name. |
| L10 | MASTER-2026-001, Path B, and NOT PROVEN present. |

No horizontal overflow was observed at 1440 on these loads. That is not a 1024 or 200% retest.

## Links

Relative links from the README, Quickstart, Getting Started, and the release matrix were checked against the filesystem. They resolve. The README in-page link `#academy-l0-l10` matches the heading `Academy L0-L10`. Historical PHASE files were not crawled. Class: primary learner links VALID.

## Secret hygiene

The diff was scanned for passwords, tokens, API keys, and private-key blocks. No secret values were added. `.env` was not committed. A local password was read only to log into the existing Splunk for the smoke check and was not written into this record.

## Codeguard notes

No credentials, certificates, or cryptographic implementations were added. The credentials rule applies because the smoke check used the existing local lab password from `.env` and did not copy it into documentation. The certificate rule applies because no certificate was added. The crypto rule applies because no algorithm or key material was added.

## Acceptance

Release identity, learner map, LIVE/REPLAY wording, L5 versus L10 versus Mastery Check, Splunk as downstream evidence, external evidence outside authorization, Path B disclosure, clean-room non-claim, and certification non-claim are documented. Runtime, CTRL-MCP-001, schema 1.9.0, ExternalEvidence 1.0.0, detectors, and UI were not modified.
