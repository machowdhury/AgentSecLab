# AgentSec holistic learner journey and RC2 readiness

**Date:** 2026-09-26
**Mode:** read-only product audit. No application, test, dashboard, curriculum, schema, or tag change was made in order to produce this assessment.
**Reviewed commit:** `b750f189e129478c53cfa33389967e06fa35ee04` (`develop`, also `origin/develop`)
**Earlier review:** `docs/reviews/V1_0_0_RC2_HOLISTIC_LEARNER_JOURNEY_REVIEW.md` assessed `d38d33f` on 2026-09-24, before Blue Team through L10. That review is historical. This audit covers the tree that exists now.

Evidence classes used below: MEASURED, OBSERVED, TESTED, DOCUMENTED, REPLAYED, INFERRED, PARTIAL, NOT MEASURED, NOT PROVEN, NEEDS EXTERNAL VALIDATION.

---

## 1. Executive Summary

AgentSec on `develop` is a local agentic-security academy. A motivated learner can move from orientation through LIVE experiments, Splunk investigation, context, goal and identity, external evidence, blue-team work, threat modeling, privacy, a multi-stage incident, and an advanced capstone. The security vocabulary is unusually careful: Splunk is not the PDP, OBSERVE is not ALLOW, ALLOW is not execution, RETEST is not universal safety, and a missing row is not prevention.

That journey is not what a default clone currently delivers, and it is not what the main learner-entry documents describe.

`origin/HEAD` is `main` at the peeled RC1 commit. `develop` is many commits ahead and still versioned `1.0.0rc1`. `README.md` tells the learner to continue to Capstone and Mastery Check. `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` stops at Mastery Check and omits garak, Blue Team, threat modeling, privacy, L9, and L10. Academy Home on `develop` teaches the longer path. A learner who trusts the README or the matrix will not know the product they are in.

This is not a reason to rework the runtime. It is a reason not to tag RC2 until the ref a learner clones and the path the docs describe are the same path Home already teaches.

**Verdict:** GO TO BOUNDED RC2 REMEDIATION.
**BLOCKER:** 0. **HIGH:** 2. **MEDIUM:** 7. **LOW:** 10.
**Clean-room:** required before a final 1.0 claim. Not a reason to block a documentation-only remediation phase. Not proven in this audit.

---

## 2. Repository Truth

| Item | Value | Class |
| --- | --- | --- |
| Branch | `develop` | MEASURED |
| HEAD | `b750f189e129478c53cfa33389967e06fa35ee04` | MEASURED |
| origin/develop | same SHA | MEASURED |
| main / origin/main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | MEASURED |
| origin/HEAD | `main` (log decoration shows `origin/HEAD` on that commit) | OBSERVED |
| Working tree before this report | untracked `docs/plans/` only | MEASURED |
| v1 tags | `v1.0.0-rc1` only | MEASURED |
| Tag object `git rev-parse v1.0.0-rc1` | `1aafacb02f4429f168fbdce61437dc37d4cfc74b` | MEASURED |
| Tag type | annotated `tag` | MEASURED |
| Peeled commit `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | MEASURED |
| Tag target | same commit as `main` and `origin/main` | MEASURED |
| RC2 tag | absent | MEASURED |
| Product version | `pyproject.toml` `1.0.0rc1`; Splunk `app.conf` `1.0.0-rc1` | DOCUMENTED |
| Schema | 1.9.0 | DOCUMENTED |
| External contract | 1.0.0 | DOCUMENTED |

**Tag classification: EXPECTED ANNOTATED-TAG BEHAVIOR.**

The L10 report quoted `v1.0.0-rc1 = 1aafacb…` and `origin/main = e6115b6…`. Those differ because `1aafacb` is the annotated tag object. `git rev-parse v1.0.0-rc1^{}` peels it to `e6115b6`, which is `main`. The tag was not moved. `git show --no-patch --decorate v1.0.0-rc1` shows tagger date Mon Sep 21 23:19:13 2026 and commit message “Prepare AgentSec v1.0.0-rc1…”. This audit did not modify the tag.

`develop` is not RC1. It adds external-evidence follow-on work and L6 through L10 after the tagged commit. Calling that tree “v1.0.0-rc1” in the README is a release-identity error, not a tag error.

---

## 3. Product Inventory

| Surface | What exists now | Class |
| --- | --- | --- |
| Academy levels L0–L10 | `learning/academy/curriculum.json` | CURRENT |
| LIVE launchers | PI, MCP-001, RAG, Memory, Goal, Identity, Lending Capstone (`experiment_context.py`) | CURRENT |
| REPLAY workshops | MCP-003/004/005/006, catalog, scanner, garak, Blue Team, threat model, privacy, L9, L10 | CURRENT |
| Splunk nav | Foundations through Advanced Capstone, then Mastery Check, then Search | CURRENT |
| Attack Service | localhost launcher; this session showed the seven LIVE labs and version `1.0.0rc1` | CURRENT |
| External tools | Cisco mcp-scanner pin 4.8.4; garak pin 0.17.0 | CURRENT |
| Detector | `DET-MCP-001` in `savedsearches.conf`, `disabled = 1`, `enableSched = 0` | CURRENT |
| Placeholder saved searches | `Q-RUN`, `Q-DENY`, descriptions say not Splunk-validated in Phase 2 | LEGACY |
| Runtime PDP | `coded_policy()` / CTRL-MCP-001 | CURRENT |
| Goal, RAG, memory, identity controls | observe or constrain their own plane; comments state they do not mint AllowTicket | CURRENT |
| Schema / external contract | 1.9.0 / 1.0.0 | CURRENT |
| Mastery Check | unscored self-assessment, no persistence | CURRENT |
| `docs/PHASE*` | provenance; Getting Started says not to use them as the install path | HISTORICAL |
| `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` | stops at Mastery Check | STALE / QUESTIONABLE as a current map |
| `docs/plans/` | untracked, not part of the product | SUPPORTING, not shipped |
| Screenshots under `docs/screenshots/` | phase evidence, including L10 captures from the prior implementation | REVIEW / EVIDENCE |
| Prior RC2 review | `d38d33f` scope | HISTORICAL |

---

## 4. Actual Learner Journey

The learner-facing order is Academy Home and `default.xml`, not phase numbers.

| Stage | Learner goal | Concepts | Hands-on | Evidence | Prior knowledge | Next skill |
| --- | --- | --- | --- | --- | --- | --- |
| L0 Home | Know what the lab is | LIVE vs REPLAY, Splunk is not the PDP | Read | DOCUMENTED in Home XML | Basic cybersecurity, per L0 text | Launch PI |
| L1 | Input and tool authority | Request is not a grant | LIVE PI and MCP; REPLAY scope and resource | Runtime + Splunk | L0 | Context is data |
| L2 | Context and adjacent evidence | RAG, memory, tool results, catalog, scanner, garak | 2 LIVE, 4 REPLAY | Mixed | L1 LIVE | Goal and identity |
| L3 | Intent | Authorized tool is not authorized goal; claim is not authentication | 2 LIVE, 1 REPLAY | Runtime + Splunk | L2 | Integrated chain |
| L4 | Investigation craft | Practiced on Path A, not a separate workshop | Embedded | DOCUMENTED | Prior labs | Capstone |
| L5 | One LIVE chain | Capstone lending assistant | LIVE | Fresh run.id | L1–L3 | Blue team |
| L6 | Investigate without being handed the story | Hypothesis, timeline, hunt | REPLAY | Historical packet | Capstone | Architecture |
| L7 | Threat model | Assets through residual risk | REPLAY / architecture | Work product | L6 | Privacy |
| L8 | Data use vs authorization | Minimization | REPLAY | Synthetic privacy packet | L7 | Multi-stage |
| L9 | Integrated incident | False leads, containment, detection candidate | REPLAY | AGENT-2026-009 | L6–L8 | Mastery capstone |
| L10 | Independent investigation | Goal vs tool, NOT PROVEN | REPLAY | MASTER-2026-001 | L6–L9 | Transfer, unscored Mastery Check |

The sequence is pedagogically sound: do the thing, then investigate a thing you did not just launch, then model and bound data, then do it with less scaffolding. The failure is that README and the release matrix do not tell the learner this sequence exists.

Effort figures in curriculum.json sum to well over a day if taken literally (LIVE blocks plus 2.5–6 hour REPLAY blocks). That total was not timed in this audit. Class: DOCUMENTED estimates, NOT MEASURED.

---

## 5. Persona A — IT Practitioner New to Security

**READY WITH FRICTION.**

Home introduces DATA != AUTHORITY, REQUEST != GRANT, ALLOW != EXECUTION, and LIVE != REPLAY in plain language (DOCUMENTED, Home XML). Attack Service says the console does not authorize and that HEC accepted is not evidence ready (OBSERVED this session).

Friction: L0 prerequisites say “Basic cybersecurity.” Least privilege, defense in depth, and separation of duties are not named on Home. They are practiced later as tool scope and control placement, often without the transferable name. Splunk field syntax appears immediately in Path A starters. A person who has never seen a SIEM can follow a pasted query and still not know what they did. L6 then removes the answer. That cliff is real.

They can learn both security reasoning and agentic security if an instructor points them at Home rather than the release matrix, and if they accept a multi-day path. They will get lost if they treat every Studio table as the lab.

---

## 6. Persona B — Security Student

**READY WITH FRICTION.**

The ATTACK / RETEST / BASELINE loop, evidence states, and “do not write SAFE” language turn classroom CIA and IAM into a reconstruction habit. Blue Team, threat modeling, privacy, L9, and L10 are the practical half. They sit after the LIVE capstone and are missing from the release matrix, so a student who follows the README may stop before the part that matches their goal.

Splunk is taught as a notebook, not as a product certification. That is the right scope. Writing SPL from a blank search bar is late and partial; copying a starter is early and common.

---

## 7. Persona C — Experienced Practitioner New to AI Security

**READY WITH FRICTION.**

L1–L3 repeat authorization basics an experienced practitioner already has, in order to attach them to RAG, memory, tools, and goals. Some of that is necessary. Some of it is long: four MCP REPLAY grant labs before the thing that is actually different (retrieved context, persisted memory, goal versus tool).

The differentiated teaching is present: CTRL-MCP-001 remains the tool PDP; other controls observe or constrain a different boundary; scanner and garak do not authorize. L7–L10 are where this persona should spend time. The entry documents hide those levels.

---

## 8. Persona D — AI Security Expert

**READY WITH FRICTION.**

Useful depth is the evidence discipline, duplicate-index versus `dc(_raw)`, external evidence kept outside the PDP, goal OBSERVE versus tool ALLOW, and L10’s refusal to call customer impact proven. An expert who only opens early mission cards will see the conclusion already written (“ANSWER THE LAB DEFENDS: NO” on the RAG mission). That is introductory.

L10 does not start from a run identifier on the mission (TESTED by `tests/splunk/test_advanced_capstone_mastery.py`, and OBSERVED previously on the mission screenshot). Path B is still a visible tab. Mastery is self-assessed and not stored. An expert can get value. They cannot be examined by the product.

---

## 9. Installation and First-Run Experience

DOCUMENTED path: `lab-preflight.sh`, copy `.env.example` to `.env`, `lab-up.sh`, `lab-ready.sh`. Quickstart states first Splunk boot can take 10–20 minutes and that READY is service health, not searchable evidence.

This session: Splunk login, Attack Service, and AcmeBank health returned HTTP 200. Class: TESTED ON EXISTING MACHINE / TESTED WITH EXISTING VOLUMES. Not CLEAN VOLUME. Not TRUE CLEAN ROOM. `docs/releases/V1_0_0_RC1_REPRODUCIBILITY.md` already says PARTIALLY REPRODUCED. `docs/KNOWN_LIMITATIONS.md` still says clean-room was not fully proven. Those statements remain accurate.

Hidden assumptions: Docker Desktop, Compose v2, Apple Silicon emulation for `splunk/splunk:10.2` (`linux/amd64`), an Ollama image tagged `latest`, a lab Splunk password in `.env`, and a learner who knows not to publish the unauthenticated Attack Service.

**Time-to-first-value: NOT MEASURED** in this audit. The documented sequence is clone, configure, preflight, up, ready, Home, PI, Attack Service, copy run.id, one quoted Splunk search. Friction that is real without a stopwatch: Splunk boot time, HEC versus searchable delay, and the need to leave Studio to paste a fresh run.id into Search.

---

## 10. Fundamental Security Learning

| Principle | Where | Class |
| --- | --- | --- |
| Least privilege | Practiced as coded tools and scopes; the name is not on Home | PRACTICED, weakly named |
| Trust boundaries | L7 and throughout | INTRODUCED, PRACTICED, REINFORCED |
| Authorization | CTRL-MCP-001 | PRACTICED, ASSESSED in later labs |
| Authentication versus authorization | Identity lab and L7 invariants | PRACTICED |
| Defense in depth | Multiple planes; the phrase is rare | PRACTICED, weakly named |
| Separation of duties | Not a named lesson | Assumed / partial |
| Input trust | PI | PRACTICED |
| Data minimization | L8 | PRACTICED |
| Observability, logging, detection | Splunk labs; DET-MCP-001 disabled | PRACTICED |
| Containment and residual risk | L7, L9, L10 | PRACTICED, not persisted |
| Evidence quality | Evidence states from later labs | REINFORCED, ASSESSED only by self-report |
| Correlation versus causation | L7, L9, L10 | REINFORCED |
| Control placement | L7, L10 | PRACTICED |
| Prevention versus detection | Explicit inequalities | REINFORCED |

Transferable if the learner can say the principle without the lab name. The product is better at inequalities than at a short glossary that uses ordinary security words.

---

## 11. Agentic Security Learning

Home and the LIVE labs distinguish model output, agent, tool, MCP authorization, and Splunk. The risky collapse is still available to a skimming reader: “the agent allowed it.” The materials repeatedly say the runtime control allowed or denied, and Splunk did not.

RAG mission states the chain source, retrieval, untrusted data, influence, CTRL-MCP-001, execution. Memory mission separates write, persist, recall. Goal mission is a dedicated lab before L10. Identity says a claim is not authentication.

An expert will still see AcmeBank-specific fixture names. The inequalities survive outside those names. The product does not teach a general agent framework.

---

## 12. ATTACK / RETEST / BASELINE Semantics

Home: ATTACK success is not universal vulnerability; RETEST success is not universal security; BASELINE is not SAFE. Capstone predict text says do not assume BASELINE is SAFE. Known limitations say one RETEST is not universal security.

No learner-facing inversion of those meanings was found in the surfaces sampled. Early cards still narrate the expected ATTACK outcome before launch (RAG ATTACK markdown states the fail-open ALLOW and handler 1). That teaches the comparison. It also means the learner does not discover the result.

---

## 13. Authorization and Control Semantics

Code, not the UI label, is the source.

| Component | Role | Class |
| --- | --- | --- |
| CTRL-MCP-001 / `coded_policy()` | Tool authorization | AUTHORIZE |
| CTRL-GOAL-INTEGRITY-001 | Task expansion; can DENY that plane; does not mint a tool grant | ENFORCE OTHER BOUNDARY |
| CTRL-RAG-CONTEXT-001 | Retrieved context is data | OBSERVE |
| CTRL-MEMORY-CONTEXT-001 | Recalled memory is data | OBSERVE |
| CTRL-IDENTITY-001 | Claim is not a grant | OBSERVE |
| CTRL-INPUT-001 | Educational input inspection | ENFORCE OTHER BOUNDARY |
| Splunk | Index and search | INVESTIGATE |
| DET-MCP-001 | Disabled saved search for deny-then-start | DETECT, not installed as an active control |
| Cisco scanner, garak | Adjacent packs | ADJACENT EVIDENCE |

`goal/pipeline.py` states CTRL-MCP-001 remains the only tool PDP. Identity and RAG pipelines say observation does not mint AllowTicket. External adapters must not call CTRL-MCP-001 (`external_evidence/plugin.py`).

Searches of learner views found many sentences of the form “not SAFE”, “OBSERVE != ALLOW”, “ALLOW != EXECUTION”, and “zero rows is not SAFE”. This audit did not find a learner sentence that teaches OBSERVE == ALLOW, DENY == SAFE, or no detection == SAFE. The word SAFE appears mostly as a prohibition. That is a strength. It is also repetitive. Class: USEFUL REINFORCEMENT, occasionally NECESSARY RECAP, sometimes REDUNDANT inside a single dashboard that repeats the same no-data sentence on every table.

---

## 14. RAG

The LIVE workshop teaches retrieval, untrusted data, influence, request, CTRL-MCP-001, then execution. Provenance is `rag.local.fixture`, described as source identity, not trust. The lab does not call RAG inherently trusted. The mission also does not leave the core question open: it says the defended answer is NO. Retrieved content is treated as dangerous only when a vulnerable profile fail-opens the tool PDP. That is the right model, delivered with the conclusion on the first card.

---

## 15. Memory

Workshop text: persisted memory is data that survives into a later run; recall is not authorization; provenance on the baseline specimen is `agentsec.memory.fixture`. Write and recall are different run identifiers. `source_run_id` is not the recall run id.

The README attack line says “malicious persisted memory used as memory-derived authority.” The following sentences say it does not become a grant. A skimmer can take the first line. The fixture provenance means this is not evidence that a retrieved model output was written through as a causal chain. Class: DOCUMENTED fixture persistence. Direct retrieved-output-to-write causality: NOT PROVEN, and the specimen label does not claim it.

---

## 16. Goal Integrity

L3 teaches authorized tool != authorized objective before L10. L10’s incident is that distinction without a starting run id: MCP ALLOW on BASELINE, ATTACK, and RETEST; goal OBSERVE overlay versus goal DENY. Learners who skip L3 and open L10 still get concept help, but the nuance is not introduced for the first time at L10. Class: PREPARED EARLIER, ASSESSED LATER. KEEP.

---

## 17. Identity and Delegation

The lab records an identity claim and an OBSERVE result. Copy says the claim is not authentication, not a grant, and that who authenticated is not proven. There is no OAuth, OIDC, or SPIFFE. Known limitations say so. Production identity is not implied by the current workshop text sampled. KEEP.

---

## 18. External Security Evidence

| Tool | Vendor | Purpose | Integration | Mode | Evidence class | Lesson |
| --- | --- | --- | --- | --- | --- | --- |
| cisco-ai-mcp-scanner 4.8.4 | Cisco AI Defense; repo in `tools/cisco-mcp-scanner/pin.json` | Static YARA scan of a tool catalog | Normalized ExternalEvidence, Splunk sourcetype, not the PDP | REPLAY workshop | REPLAYED packs; license string in pin | A finding is not exploitation and not authorization |
| garak 0.17.0 | NVIDIA; `https://github.com/NVIDIA/garak` in `tools/garak/pin.json` | Adversarial evaluation | Same contract, separate sourcetype | REPLAY | REPLAYED; pin says Apache-2.0 | PASS is not safety |

The garak and scanner workshops say external evidence is not authorization. L9 and L10 classify the canonical HIGH scan and garak PASS as unrelated to those incidents. That lesson is clear.

**Attribution:** Cisco pin has repository, PyPI, version, and a license string. The short README does not repeat the upstream link; the pin does. Garak pin names NVIDIA and the repository. `docs/EXTERNAL_VALIDATION_BACKLOG.md` still marks the garak license, probe fidelity, and Cisco JSON stability as NEEDS EXTERNAL VALIDATION. The pin’s Apache-2.0 line is therefore stronger than the backlog. Do not treat the pin as a closed legal review.

**Extensibility:** `external_evidence/plugin.py` requires adapters not to call CTRL-MCP-001. A future scanner or evaluation tool can be normalized beside the runtime. This audit did not implement one. Whether a newcomer could do it from the contract alone is INFERRED from the module boundary, not MEASURED by a trial integration.

---

## 19. Blue-Team and Splunk Skills

Progression that exists:

- Early Path A: starter SPL with a pasted run.id (copying, then editing the id).
- Hints, then Path B full query (answer available).
- L6–L9: more reconstruction, still with substantial in-dashboard SPL.
- L10: window discovery, `dc(_raw)`, comparison, external sourcetypes, a hunt that does not embed the incident run id, and a detection candidate that is not installed.

That is a real progression toward investigating without a known id. It is not a curriculum where most hours are spent writing SPL from a blank page. Class: COPYING PROVIDED SPL dominates L1–L3; MODIFYING and interpreting dominate the middle; WRITING and investigating without a known id are concentrated in L6 and L10 and are not enforced.

Splunk curve: index, sourcetype, quoted run.id, then stats, `dc()`, `values()`, and multi-run comparison. The jump is at L6, when the starter run.id disappears. `dc(_raw)` versus indexed count is taught explicitly by L10 and in several earlier PROVE sections. HEC accepted is distinguished from searchable evidence in Quickstart, Home-adjacent Attack Service copy, and known limitations. This audit did not find a current learner sentence that says HEC accepted means the evidence is complete.

---

## 20. Threat Modeling

L7’s method matches system, assets, actors, flows, boundaries, authority, attack surface, threats, controls, telemetry, assumptions, gaps, and residual risk. The same list is reused as the L10 pre-search worksheet. The method is not AI-specific. The examples are. Transfer is plausible and unmeasured. Class: PRACTICED inside AgentSec, TRANSFERABLE by structure, NOT PROVEN outside it.

---

## 21. Privacy and Data Governance

L8 sits after threat modeling and before the integrated incident. The lesson authorized action != authorized data use is the point of that lab and is repeated as a question in L10. Minimization, purpose, logging, and what is not proven are in the L10 data section. Retention, deletion, and legal compliance are not established. Framework copy says educational mapping, not a legal determination. This audit did not find a certification claim in the privacy path. Overstatement risk is a learner treating a synthetic field exercise as a privacy-program assessment. The materials say not to.

---

## 22. L9 Integration

L9 is a REPLAY investigation of AGENT-2026-009. It asks for hypothesis, timeline, evidence states, controls, containment, remediation, a candidate detection, a hunt, and three audiences. It is not a fresh attack. Path B remains a tab. Searches exist in the dashboard, so a learner can still be led. Compared with L1, the learner is closer to an investigator. Compared with an unsupervised case, the product still supplies the searches. Class: MIXED. Hand-holding is reduced, not gone.

---

## 23. L10 Mastery

Verified in the product, not from the phase summary alone:

- Incident id MASTER-2026-001, not AGENT-2026-009 (TESTED).
- Mission markdown has no canonical run id (TESTED; prior UI review OBSERVED).
- Three hypotheses; H2 and H3 refuted in the reference packet.
- Customer outcome state is NOT PROVEN.
- Detection candidate is not in `savedsearches.conf` (TESTED).
- Expert mode is a section of the mission, not a separate product mode. Later tabs still contain discovery SPL.
- Path B is the last tab and is visible. Studio does not enforce “after you finish.”
- Mastery states are self-assessed. Nothing in the product checks that a ledger was written.

L10 assesses independence only if the learner cooperates. The design is honest about that. It should not be described as an exam.

---

## 24. Framework Usage

OWASP, MITRE ATLAS, CSA MAESTRO, NIST AI RMF, and NIST Privacy Framework appear as educational mappings. Known limitations: ATLAS labels require revalidation. The external-validation backlog leaves official semantics open. `docs/FRAMEWORK_MAPPING_MODEL.md` says a lookup must not imply certification.

Classification for current UI mappings: EDUCATIONAL MAPPING. ATLAS identifiers that have not been revalidated: NEEDS EXTERNAL VALIDATION. This audit did not correct any mapping.

Frameworks are used to name a lens after the investigation in later labs, not as the way the learner finds the answer. That is teaching, with a risk of decoration if a learner pastes a framework name into an executive note without the evidence state. The volume is high for Persona A and appropriate for Persona C if kept behind Path B. No compliance claim was found in the L10 reference text.

---

## 25. UI / UX

OBSERVED this session on the existing lab, after Splunk login, at 1440, 1280, and 1024 CSS pixels. Views: Home, MCP, RAG, Memory, Goal, Identity, garak, scanner, Blue Team, threat modeling, privacy, L9, L10. `documentElement` horizontal overflow was false on those loads. Home’s Studio body was not fully readable at a 700 ms wait (tab count 0). Other views exposed tabs. Do not treat the Home snapshot as proof the Home text is empty; the XML contains the curriculum.

Attack Service, OBSERVED: title AgentSec Lab, version `1.0.0rc1`, seven LIVE labs, “this console does not authorize,” “EVIDENCE READY — not merely HEC accepted,” “NOT PRODUCTION AUTHENTICATION.” That is a professional lab console, not a toy launcher. The original “attack UI” concern is in better shape than a phase-built demo.

The Studio workshops still feel like a family of phase-built dashboards that learned a shared grammar: MISSION / INVESTIGATE / EVIDENCE / PATH B on the LIVE workbenches; longer tab sets on L6–L10. Hierarchy is consistent. Information density is high. Path B is always a tab on the workbenches that use it (`PATH B · ANSWERS` on MCP, RAG, Memory, Goal, Identity). Scanner uses a different tab set and does not label a tab PATH B. Garak uses TOOLBOX / GUIDED / INVESTIGATE / CHALLENGE and puts Path B in the investigate prose, including a canonical scan id.

**Primary feel: AGENTIC SECURITY ACADEMY made of related Dashboard Studio workbenches, plus a separate Attack Service.** Not one visual system. Not a random pile.

---

## 26. Accessibility

| Check | Class |
| --- | --- |
| Keyboard and visible focus on L10 mission tab | OBSERVED in the prior L10 review (Arrow Right, blue inset outline) |
| 1024 CSS px overflow on sampled views this session | OBSERVED false |
| 1440 and 1280 overflow this session | OBSERVED false |
| 200% zoom | PARTIAL. Prior reviews, including L10, recorded overflow at 512 CSS px from Splunk chrome and tab wrap. Not re-measured on every workshop in this audit |
| Contrast | NOT TESTED as a measured contrast audit |
| Screen reader | NOT TESTED |
| WCAG | not claimed |

Splunk-native header and nav limits should stay separate from AgentSec grid issues. This audit does not claim conformance.

Mobile support: the product does not claim a phone layout. 1024 and 200% are accessibility checks already used in workshop reviews, not a mobile product requirement. Document them as partial. Do not invent a mobile requirement.

---

## 27. LIVE vs REPLAY

| Exercise | Class | Visible before start? |
| --- | --- | --- |
| PI, MCP-001, RAG, Memory, Goal, Identity, L5 capstone | LIVE, with REPLAY specimens on the dashboards | Attack Service says live launch. Dashboards also show canonical ids. A learner can confuse the specimen with the launch. Copy tells them not to. |
| MCP-003/004/005/006, catalog, scanner, garak | REPLAY | Nav and curriculum say REPLAY. Attack Service does not list them. |
| L6–L10 | REPLAY | Mission text says REPLAY workshop. |
| Threat model | STATIC REASONING plus REPLAY evidence | Labeled REPLAY / architecture |
| Mastery Check | STATIC REASONING | Not a launch |
| DET-MCP-001 simulated makeresults on some dashboards | SIMULATED, labeled | Copy says NOT INDEXED |

The remaining trap is a LIVE dashboard whose first data table is a canonical REPLAY id. The words are present. The table still looks like “the result.”

---

## 28. Evidence Semantics

The research-integrity rule and later workshops use MEASURED, OBSERVED, DOCUMENTED, REPLAYED, SIMULATED, INFERRED, NOT PROVEN, NOT MODELED. They are not defined once in a glossary a beginner must pass. Later labs use PROVEN, SUPPORTED, OBSERVED, INFERRED, REFUTED, NOT OBSERVED, NOT MODELED, NOT PROVEN. Two overlapping lists. Class: CONFUSING DUPLICATION if a learner treats PROVEN and MEASURED as the same word. They are not. A one-page glossary would fix this without a new subsystem.

---

## 29. Security Claims

README: not a production security product. Product boundary: not a gateway, not a production PDP, not a certification. Attack Service: not production authentication. Known limitations match the code: no OAuth, no durable vector store, no DET-CAPSTONE, Studio Path B visible, clean-room not proven.

This audit did not find a current claim that the lab is compliant, certified, or production-ready. The false claim that does exist is release identity: the develop tree is still labeled 1.0.0-rc1 while it is not the tagged RC1 commit.

---

## 30. Documentation

| Doc | Class |
| --- | --- |
| README, QUICKSTART, GETTING_STARTED | LEARNER PATH. Getting Started correctly points at Quickstart and away from PHASE files. README’s “what you will learn” and step 5 are stale relative to Home. |
| AGENTSEC_RELEASE_LAB_MATRIX | LEARNER PATH, STALE |
| AGENTSEC_V1_PRODUCT_BOUNDARY, KNOWN_LIMITATIONS, SECURITY_BOUNDARY | RELEASE / REFERENCE. Limitations looked accurate. |
| LIVE_VS_REPLAY, ARCHITECTURE | REFERENCE |
| EXTERNAL_VALIDATION_BACKLOG | RELEASE, still open |
| PHASE* | HISTORICAL PROVENANCE |
| docs/reviews and screenshots | REVIEW / EVIDENCE |
| Prior holistic review | HISTORICAL relative to L6–L10 |

Broken links: README targets checked for this audit exist (Quickstart, Getting Started, release matrix, architecture, security boundary, known limitations, local docker lab, operations, troubleshooting, instructor guide, changelog, RC1 notes, implementation status, license). A full link crawl of every PHASE file was not done. Class: learner-entry links VALID; historical docs not fully crawled.

Screenshots: L10 captures match the L10 review that produced them. Older screenshots are historical evidence. This audit did not regenerate images. Do not treat old PNGs as the current Attack Service; this session’s text observation supersedes them for that console.

---

## 31. Tests

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` on this commit: **1027 passed, 3 deselected** (MEASURED this session, 10.91s).

Those tests are mostly unit, contract, dashboard-structure, and security-semantic checks. They do not prove clean-room install, screen-reader behavior, true browser 200% zoom, live Ollama, or that a human resisted Path B. Test count is not quality. The suite is strong at stopping semantic regressions and weak as a release rehearsal.

Gaps, report only: clean-room boot, screen reader, 200% on every workshop, live model, live external-tool execution, duplicate ingest on a fresh volume, Path B use by a human, stale volume versus documented first boot.

---

## 32. Secret Hygiene

`.env` is gitignored and was not printed. `.env.example` contains localhost lab defaults for a Splunk admin password and an HEC token, with comments to rotate them if the bind is not localhost. Those values are example defaults, not a production tenant secret, and they are still credentials a copied lab will share until rotated. No private keys or customer data were found in the audit sample. Class: PASS for “no committed `.env`,” PARTIAL for shared lab defaults. This report does not repeat the default strings.

---

## 33. Dependency and Reproducibility

| Dependency | Pin | Risk |
| --- | --- | --- |
| splunk/splunk:10.2 | tag 10.2, not a digest | Medium; amd64 emulation on Apple Silicon is documented |
| ollama/ollama:latest | unpinned | Reproducibility risk |
| llama3.2:1b | name in compose | Model pull on first boot |
| cisco-ai-mcp-scanner==4.8.4 | pin plus wheel hash | Stronger |
| garak==0.17.0 | pin; license backlog open | Medium |
| Python packages | pyproject / uv | Not fully audited package-by-package in this pass |

No upgrade was performed.

---

## 34. Skill Transfer

A finisher can explain, in AgentSec’s words, why context is untrusted, why a tool grant is not a goal grant, why a SIEM row is not a control decision, and why a scanner hit is not the incident. That transfers to API authorization, IAM claims versus tokens, SOC evidence handling, incident reporting, data minimization, and AI agent designs that use tools.

It does not by itself produce a cloud engineer, a detection engineer, or a privacy counsel. Completing the workshop is not professional competence. Class: INFERRED from the curriculum, NOT MEASURED on an outside system.

---

## 35. Product Identity

**Primary: agentic security academy** (local learning range plus investigation workbench).

Also accurate: agentic security workshop, blue-team AI security lab for L6–L10, reference educational architecture for the control split.

Not the strongest label: “AI security demo” (the path is too long and too careful) or “production reference architecture” (fixtures, no identity protocol, disabled detector).

---

## 36. What AgentSec Is Not

It must not currently claim to be a production security platform, a production agent firewall, an AI governance product, a compliance validator, a universal attack simulator, a production identity system, or a certification. The product boundary and known limitations already say this. KEEP those pages. Update them only to stop calling the develop tree RC1.

---

## 37. Redundancy and Dead Weight

| Item | Class |
| --- | --- |
| Repeated “not SAFE” / OBSERVE != ALLOW | USEFUL REINFORCEMENT; redundant inside one dashboard’s empty states |
| L1–L3 grant anatomy before L6 | NECESSARY RECAP for Persona A; long for Persona C |
| PHASE docs | HISTORICAL. Getting Started already diverts learners. Do not delete. |
| Release lab matrix | STALE. It is dead weight if left linked from the README. |
| Disabled Phase 2 placeholder saved searches | LEGACY. Not learner-facing if disabled. |
| Two things named capstone | CONFUSING DUPLICATION: L5 “Capstone” nav versus L10 “Advanced Capstone,” plus Mastery Check |
| Prior RC2 review | HISTORICAL. Do not treat its “GO” as covering L6–L10. |

---

## 38. Top 20 Findings

### F-01
ID: F-01. SEVERITY: HIGH. AREA: release identity. PERSONAS: all. EVIDENCE: MEASURED SHAs; README and `pyproject.toml` still say 1.0.0-rc1; `develop` is not the tagged commit. WHY: a learner cannot tell whether they have the release or the unpublished academy. DISPOSITION: RC2 MUST FIX the words and the clone instructions. Do not tag RC2 in this audit. RC2 CLASS: RC2 MUST FIX.

### F-02
ID: F-02. SEVERITY: HIGH. AREA: learner map. PERSONAS: all. EVIDENCE: DOCUMENTED. README step 5 ends at Capstone and Mastery Check. Release matrix has no L6–L10 and no garak row. Home XML lists the full path. WHY: the cited curriculum is not the curriculum. DISPOSITION: RC2 MUST FIX. RC2 CLASS: RC2 MUST FIX.

### F-03
ID: F-03. SEVERITY: MEDIUM. AREA: default branch. PERSONAS: all. EVIDENCE: MEASURED. `main` is peeled RC1. Full journey is on `develop`. WHY: `git clone` of the GitHub default does not contain L6–L10. DISPOSITION: say so until a release ref exists. RC2 CLASS: RC2 MUST FIX (same remediation as F-01).

### F-04
ID: F-04. SEVERITY: MEDIUM. AREA: answer placement. PERSONAS: A, D. EVIDENCE: DOCUMENTED RAG mission “ANSWER THE LAB DEFENDS”; ATTACK card states handler outcome before launch. WHY: early UI does the thinking; L6 removes it without a bridge. DISPOSITION: KEEP early teaching; add a short L6 expectation note. RC2 CLASS: RC2 SHOULD FIX.

### F-05
ID: F-05. SEVERITY: MEDIUM. AREA: Path B. PERSONAS: all. EVIDENCE: OBSERVED tabs named PATH B · ANSWERS; known limitations already say Studio Path B is visible. WHY: pedagogical gating is not access control. Pretending otherwise would be a false claim. DISPOSITION: DO NOT FIX / INTENTIONAL. Keep the limitation. RC2 CLASS: RC2 DOCUMENT.

### F-06
ID: F-06. SEVERITY: MEDIUM. AREA: two capstones. PERSONAS: A, B. EVIDENCE: nav labels Capstone and Advanced Capstone; Mastery Check is a third surface. WHY: “finish the capstone” is ambiguous. DISPOSITION: name L5 and L10 differently in the entry docs. RC2 CLASS: RC2 SHOULD FIX.

### F-07
ID: F-07. SEVERITY: MEDIUM. AREA: evidence vocabulary. PERSONAS: A, B. EVIDENCE: research-integrity classes versus PROVEN/SUPPORTED/NOT PROVEN. WHY: two glossaries. DISPOSITION: one learner page. No schema change. RC2 CLASS: RC2 SHOULD FIX.

### F-08
ID: F-08. SEVERITY: MEDIUM. AREA: clean-room. PERSONAS: operators. EVIDENCE: DOCUMENTED partial reproducibility; this session used existing volumes. WHY: RC1’s known limit is still true. DISPOSITION: do not claim a clean install. RC2 CLASS: RC2 DOCUMENT. Required before final 1.0.

### F-09
ID: F-09. SEVERITY: MEDIUM. AREA: supply chain. PERSONAS: operators. EVIDENCE: `ollama/ollama:latest` unpinned. WHY: a later pull can change first boot. DISPOSITION: pin when reproducibility work is authorized. RC2 CLASS: POST-RC2 unless the remediation owner wants it in the same doc pass. Not required to fix the learner map.

### F-10
ID: F-10. SEVERITY: MEDIUM. AREA: external license. PERSONAS: D, operators. EVIDENCE: garak pin says Apache-2.0; backlog item 1 is still NEEDS EXTERNAL VALIDATION. WHY: the pin overstates closure. DISPOSITION: RC2 DOCUMENT the tension. Do not edit the pin in this audit. RC2 CLASS: RC2 DOCUMENT.

### F-11
ID: F-11. SEVERITY: LOW. AREA: guided external lab. PERSONAS: B, D. EVIDENCE: garak investigate text names `scan_id` and Q-GARAK files on Path A. WHY: less independent than L10. DISPOSITION: leave for a later pedagogy pass. RC2 CLASS: POST-RC2.

### F-12
ID: F-12. SEVERITY: LOW. AREA: named fundamentals. PERSONAS: A. EVIDENCE: least privilege and separation of duties are not on Home. WHY: transfer is harder. DISPOSITION: a glossary sentence, not a new control. RC2 CLASS: RC2 SHOULD FIX if the glossary in F-07 is written; otherwise POST-RC2.

### F-13
ID: F-13. SEVERITY: LOW. AREA: lab defaults. PERSONAS: operators. EVIDENCE: `.env.example` documents localhost defaults and says to rotate them. WHY: shared lab credentials if copied unchanged onto a non-local bind. DISPOSITION: KEEP the warning. RC2 CLASS: RC2 DOCUMENT. Do not publish the values.

### F-14
ID: F-14. SEVERITY: LOW. AREA: mastery enforcement. PERSONAS: D, instructors. EVIDENCE: assessments.json tracking is self-assessed, no persistence. Known limitations already say this. WHY: opening L10 is not mastery. DISPOSITION: DO NOT FIX / INTENTIONAL for RC2. RC2 CLASS: RC2 DOCUMENT.

### F-15
ID: F-15. SEVERITY: LOW. AREA: accessibility. PERSONAS: A. EVIDENCE: screen reader NOT TESTED; 200% PARTIAL from prior reviews and Splunk chrome. WHY: do not claim WCAG. DISPOSITION: keep the limitation. RC2 CLASS: POST-RC2 for a real screen-reader pass.

### F-16
ID: F-16. SEVERITY: LOW. AREA: historical docs. PERSONAS: A. EVIDENCE: many PHASE files; Getting Started diverts readers. WHY: search still finds them. DISPOSITION: do not delete. RC2 CLASS: DO NOT FIX / INTENTIONAL.

### F-17
ID: F-17. SEVERITY: LOW. AREA: placeholder searches. PERSONAS: operators. EVIDENCE: `Q-RUN` and `Q-DENY` disabled, described as unvalidated Phase 2 placeholders. WHY: dead weight in the app, not in the nav. DISPOSITION: POST-RC2 cleanup, not a learner blocker. RC2 CLASS: POST-RC2.

### F-18
ID: F-18. SEVERITY: LOW. AREA: memory skimming. PERSONAS: A. EVIDENCE: README attack line says memory-derived authority; body says it is not a grant; provenance is a fixture. WHY: the first line is stronger than the evidence. DISPOSITION: wording only, later. RC2 CLASS: POST-RC2.

### F-19
ID: F-19. SEVERITY: LOW. AREA: time. PERSONAS: A, B. EVIDENCE: curriculum effort strings; NOT MEASURED end-to-end. WHY: the path can look like a weekend and consume a week. DISPOSITION: publish the sum as an estimate, not a measurement. RC2 CLASS: RC2 DOCUMENT.

### F-20
ID: F-20. SEVERITY: LOW. AREA: prior review. PERSONAS: maintainers. EVIDENCE: 2026-09-24 review at `d38d33f` said GO FOR RC2 REMEDIATION with one HIGH about execution language, before L6–L10. WHY: that GO does not cover this tree. DISPOSITION: this report supersedes it for readiness. RC2 CLASS: DO NOT FIX / INTENTIONAL (leave the old file).

Severity counts: BLOCKER 0, HIGH 2 (F-01, F-02). F-03 is the same remediation as F-01 and is not a third high. MEDIUM: F-04 through F-10 (7). LOW: F-11 through F-20 (10).

The required summary counts in the closing response use HIGH 2, MEDIUM 7, LOW 10. Section 61 asked not to inflate. F-04 through F-10 are medium because they confuse or overstate, and they do not stop a learner who is already on Home.

---

## 39. Top 10 Learner Friction Points

1. README and the release matrix describe a shorter academy than Home.
2. Default `main` is RC1; the audited journey is `develop`, still labeled RC1.
3. “Capstone” means L5, L10, and sometimes the whole ending.
4. Early workshops print the conclusion and the expected ATTACK chain.
5. Path B is a tab, correctly disclosed and still one click from the answer.
6. LIVE dashboards show REPLAY specimen ids that look like the launch result.
7. Splunk starters teach paste-the-id before they teach writing a search.
8. L6 is a cliff after labs that supplied the answer.
9. Two evidence vocabularies.
10. First boot time and HEC-versus-search delay are documented but easy to miss when a table is empty. Empty is not SAFE; it is also frustrating. Time-to-first-insight was NOT MEASURED.

---

## 40. Top 10 Strengths

1. KEEP the control split: CTRL-MCP-001 authorizes tools; other planes do not mint grants.
2. KEEP ATTACK / RETEST / BASELINE as a comparison, with explicit non-universality.
3. KEEP “not SAFE” empty-state language.
4. KEEP HEC health distinct from searchable evidence.
5. KEEP `dc(_raw)` distinct from indexed row count.
6. KEEP external evidence outside the PDP.
7. KEEP L3 goal-versus-tool teaching before L10 uses it.
8. KEEP L10’s NOT PROVEN customer outcome and hidden mission run id.
9. KEEP Attack Service’s closed launcher and “does not authorize” copy.
10. KEEP known limitations that match the code, including visible Path B, no certification, and unproven clean-room install.

---

## 41. Curriculum Compression Opportunities

| Module | Class | Why |
| --- | --- | --- |
| L1 LIVE PI and MCP | KEEP SEPARATE | They teach different boundaries |
| L1 REPLAY scope and resource | POSSIBLE MERGE later | Same PDP, more parameters; not now |
| L2 scanner and garak | KEEP SEPARATE | Finding versus evaluation |
| L4 | KEEP SEPARATE as practice, not a workshop | Already not a lab |
| L5 LIVE capstone | KEEP SEPARATE from L10 | Fresh chain versus unfamiliar replay |
| L9 and L10 | KEEP SEPARATE | Different incidents and different scaffolding |
| PHASE docs | MOVE TO REFERENCE | Already the intent of Getting Started |
| Release matrix | MOVE TO REFERENCE only after it matches Home | Until then it is a bad primary path |
| Mastery Check | KEEP SEPARATE | Optional, unscored |

---

## 42. Curriculum Gaps

Missing names (least privilege, separation of duties) and a single evidence glossary can be solved with explanation. No new subsystem.

A persisted gradebook, a real identity provider, a production retriever, and an always-on detector are not required for the stated outcomes. Do not add them for RC2.

---

## 43. RC2 Readiness Scorecard

| Area | Status | Evidence |
| --- | --- | --- |
| Repository integrity | READY | SHAs and tag peel measured |
| Installation | PARTIAL | Documented; existing volumes only |
| Documentation | PARTIAL | Home current; README and matrix stale |
| Curriculum coherence | MIXED | Home sequence is strong; entry docs are not |
| Beginner experience | PARTIAL | Possible with friction |
| Practitioner experience | READY WITH REMEDIATION | Path exists; map does not |
| Expert value | READY WITH REMEDIATION | L9/L10 and semantics; early cards are introductory |
| Security semantics | READY | Inequalities match the code |
| Runtime integrity | READY | PDP unchanged; seven LIVE labs |
| Splunk investigation | READY WITH REMEDIATION | Real progression; paste-heavy early |
| External evidence | READY | Isolated; license backlog open |
| Threat modeling | READY | Reusable method, local examples |
| Privacy | READY | Bounded; not a legal program |
| Capstone | READY WITH REMEDIATION | Two capstones need names |
| Mastery | PARTIAL | Design is sound; enforcement is honor-system |
| UI/UX | READY WITH REMEDIATION | Coherent family, dense, Path B visible |
| Accessibility | PARTIAL | Keyboard sampled earlier; screen reader not tested |
| Tests | READY WITH REMEDIATION | 1027 offline passed; they are not a clean-room |
| Secret hygiene | READY WITH REMEDIATION | No committed `.env`; lab defaults in the example |
| Release hygiene | NOT READY | develop labeled RC1; default branch is the old tag |

---

## 44. RC2 Must-Fix List

1. State which git ref contains the academy a learner should use. Do not call `develop` RC1 while `v1.0.0-rc1` peels to `main`.
2. Make README “what you will learn,” the after-startup steps, and `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` match Home: L0–L10, garak, LIVE versus REPLAY, and the difference between L5, L10, and Mastery Check.
3. Keep the known-limitations sentences that are already true: visible Path B, no certification, clean-room not proven, HEC is not evidence. Do not delete them to look more finished.

---

## 45. Post-RC2 Backlog

1. Clean-room install measurement before any final 1.0 claim.
2. Screen-reader pass. Do not claim WCAG before that.
3. Pin `ollama/ollama` and close or explicitly downgrade the garak license line against the backlog.
4. Optional glossary and L6 bridge.
5. External validation backlog items that are not needed to describe the lab honestly.
6. Placeholder saved searches and PHASE-doc discoverability. Do not block a release on them.

---

## 46. Clean-Room Decision

**REQUIRED BEFORE FINAL 1.0.**

**RECOMMENDED before an RC2 tag**, and not required before the documentation remediation itself. This audit did not reset volumes. `docs/KNOWN_LIMITATIONS.md` and the RC1 reproducibility note remain the accurate statement: current-environment validation, not a clean room.

---

## 47. Recommended Next Phase

**Bounded RC2 remediation: learner-entry and release-identity alignment.**

IN SCOPE:

- README, Quickstart only if a ref sentence is required, release lab matrix, product-boundary version wording.
- A short statement of L5 versus L10 versus Mastery Check.
- No change to runtime, schema, external contract, detectors, nav structure, or tags.

OUT OF SCOPE:

- New labs, new tools, refactors, Path B access control, clean-room reset, screen-reader certification, dependency upgrades, RC2 tag, GitHub Release.

ACCEPTANCE CRITERIA:

- A reader of README can list the Home path through L10 and can tell `main`/`v1.0.0-rc1` from the branch that contains that path.
- The release matrix rows match `curriculum.json` levels and LIVE/REPLAY flags.
- Version strings are not still “this tree is RC1” if the tree is not the tagged commit.
- Known limitations that are still true remain in the doc.
- Offline pytest command from this audit still passes, because no product behavior was supposed to change. If docs-only edits touch tests that snapshot those docs, update only those assertions.

---

## 48. Final Verdict

**GO TO BOUNDED RC2 REMEDIATION**

Not GO TO RC2 VALIDATION: the release surface does not yet describe the product under review.
Not NO-GO: the academy on `develop` is coherent, the PDP story matches the code, and the uncomfortable gaps are documentation, gating honesty, and unproven clean-room install. They do not require a new architecture.

Where a beginner fails: they follow the README, stop at Mastery Check, or treat a REPLAY table as the attack they just ran.
Where an expert rolls their eyes: the RAG card answers itself, and the version still says RC1.
Where the UI thinks for the learner: early ATTACK cards and Path B tabs.
Where the learner copies SPL: L1–L3 Path A starters.
Where correlation is treated carefully: L9 and L10, better than the early cards.
Where REPLAY looks live: specimen tables on LIVE dashboards.
Where a control looks stronger than it is: nowhere systematic; the “not SAFE” copy holds.
Where the trick is AgentSec-specific: fixture ids. The inequalities are not.
Where history leaks: PHASE files and a stale matrix linked from the README.

Application code was not modified to perform this audit. The only new artifact is this report.
