# AgentSecLab v1.2.0 release notes (DRAFT: not tagged, not published)

**Academy, EVAL, Risk and Governance Centers.** A browser-based Academy for learning how AI agents fail and how to investigate, evaluate and govern them, served at `/learn`. Delivered from `feature/academy-react-shell`. Package metadata (`pyproject.toml`, `agentsec.__version__`, the Splunk app and its dashboard build panel) still says 1.1.0: a coordinated version bump touches the Splunk app and dashboards and is not part of this release candidate. No tag exists yet.

## Deployed build and traceability
- The validated, deployed build was commit `4d3c110` before a metadata-only history rewrite (a contributor email was replaced). After the rewrite the same tree is commit `6e311b227a48`. Every commit SHA changed; source trees are identical.
- The deployed build's health payload reports version 1.1.0, because the package version was not bumped.
- Instance acceptance, a 55-check browser smoke test and a 23-check learner-journey test ran against the deployed build; none ran against the version-bump commit.

## The six-stage learning journey
A **Workshop path** bar on lab, mission and Center pages links six steps:

| Step | Where | What you do |
|---|---|---|
| 1 Learn | `/learn/curriculum`, `/learn/lab/<id>` | Read a lab; predict, reveal and prove on its Practice and Prove tabs |
| 2 Attack | `/learn/loan-desk/attack` | The Loan Desk mission's live Attack stage (locked until you lock a prediction) |
| 3 Investigate | `/learn/loan-desk/investigate` and the recorded Splunk labs | Prove what happened from recorded Splunk evidence |
| 4 EVAL | `/learn/evals` | Read recorded and simulated experiments, findings, comparisons, and export a report |
| 5 Risk | `/learn/risk` | Assess source-backed risks yourself in a local, unapproved browser draft |
| 6 Governance | `/learn/governance` | See framework relationships, controls and gaps; export them |

The **Loan Desk mission** is separate and has seven stages of its own: Learn, Prepare, Attack, Investigate, Defend, Retest, Explain. Later stages unlock in order.

## Supported capabilities
- 32 labs with Learn, Practice and Prove tabs; recorded workbenches for checkpoint, study and Splunk-evidence labs.
- EVAL Center: 11 recorded or simulated experiments, findings, comparisons, Markdown report export.
- Risk Center: qualitative 3x3 method, four field origins (source, derived, analyst, missing), checksummed local drafts with strict import and export.
- Governance Center: eight distinctions (a mapping is never compliance), framework relationships, controls, gaps, deterministic Markdown and JSON export.
- Deterministic exporters with `--check` modes and validators that reject scores, invented owners and compliance claims.

## Known limitations
- **Live attack not verified.** The live Loan Desk Attack stage was not run or verified for this release; everything verified is recorded, replayed or simulated.
- **Recorded evidence is not independently verified.** No run has a verifier receipt; the Centers label it NOT_VERIFIED. A recorded run is one run, not a rate.
- **No compliance claim.** Framework relationships are educational. NIST AI RMF is listed as not verified in this repository and carries no items or mappings.
- **Testing.** Deployed-build checks were automated headless Chromium through a private tunnel (55 smoke and 23 journey checks), plus instance acceptance. No human browser pass, no screen-reader testing, Splunk not exercised through the tunnel.
- **No authentication or TLS.** Keep the lab on loopback or behind a tunnel. An HTTPS front door is proposed in `docs/HTTPS_INGRESS_PROPOSAL.md` and is not deployed.
- **Risk drafts** are browser-local with status `LOCAL_DRAFT_NOT_APPROVED`; the checksum is not a signature.
- **Branch scope.** These features are not on `main` until merged.
