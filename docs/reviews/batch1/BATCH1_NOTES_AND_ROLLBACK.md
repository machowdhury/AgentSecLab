# Batch 1: notes, limitations and rollback

Branch `feature/phase1-hardening`. Nothing here changes Splunk management-port TLS, certificates, Docker volumes, running containers or the corporate trust configuration. The running stack is NOT rebuilt by this work: its Attack Service image still contains the pre-Batch-1 code.

## What each change is and how to undo it

| Change | Rollback |
|---|---|
| **Framework references.** `framework_refs.json` and `framework_refs.py`; `technique_id_for` returns `None`; Attack Service shows verified references and retired labels. | `git revert` the commit. Specimens were never edited, so nothing else needs restoring. No schema change: `agentsec.technique.id` stays an optional field in schema 1.9.0. |
| **Evidence contract C1 and timeline C2** (`evidence_contract.py`, `timeline.py`, schemas). Additive modules, not wired into any route yet. | Delete the files or revert. Nothing imports them except tests. |
| **REST evidence probe.** `probe_splunk_count_rest`, behind `AGENTSEC_SPLUNK_PROBE_ENABLED` (default off, nothing sets it). Needs an explicit CA file and `https://`; hostname verification always on; no pinning, no skip-verify. | Leave the flag unset (the default). `select_probe()` then returns the original docker-exec probe unchanged. Revert to remove. |
| **Lab registry and workshop schema** (`lab_registry.py`, `taxonomy.json`, `lab_registry_data.json`, `workshop.json` for MCP-001, schemas). Not read by any page yet. | Delete or revert. The MCP-001 page still renders from its existing template. |
| **Shared tokens and shell** (`tokens.css`, `shell.css`, two partials, `shell.py`, a call in `agentsec-ui.js`, one include pair in 7 templates). | Revert, or delete the two `{% include %}` lines per template. Page CSS was not modified. |
| **Control inventory, axe capture, tests.** Scripts and tests only. `ui` extra added to `pyproject.toml`. | Revert. |

## Limitations and known issues

- **Figma fidelity is not claimed.** The reference is the Figma Make v2 export; the native Figma file was never accessed. `docs/design/figma_v2_tokens.json` records the snapshot and the declared additions.
- **Only the shell uses the new tokens.** Page CSS still has three variable vocabularies (`academy.css`, `agentsec.css`, `agentsec-workbench.css`/`agentsec-academy.css`) pinned by existing tests. Migrating them is Batch 2 work.
- **Academy now shows two header rows** (the surface bar and the Academy masthead). Intentional for Batch 1; consolidation needs a design decision.
- **The AcmeBank read-only view has no Splunk link in the bar** because existing security tests require that view to ship no script.
- **The shell bar is compact (34 px)** because the P1.1 contract keeps the primary action above the fold at 1920x1080 (measured: a 47 px bar pushed it 10 px off-screen).
- **Axe, pre-existing, not fixed here:** `color-contrast` (serious, 1 node each) on four LIVE workbench pages, and `region` (moderate) on every page. No new violation was introduced (compared against commit `0e51ac8`).
- **Viewport widths emulate a narrow screen.** Genuine browser zoom, a real device and a screen reader were NOT tested.
- **The control inventory is structural.** It records which controls have wiring; it is not behavioural proof. `HANDLER` means a listener exists, not that it works. Dynamic states after interaction were not crawled.
- **Domain calls marked `review`** (8 registry entries) need a human to confirm. D01 AI foundations has no curriculum entry.
- **Pillar status is conservative:** only P3 has implemented links (7 LIVE labs).

## Not done in Batch 1 (explicitly open)

Interactive AcmeBank portal; model-driven agent loop and its events (schema 1.10.0 is deferred until those events exist); the REST probe's TLS, credential and least-privilege design (pending separate approval); generic workshop engine; Control Plane Explorer; migrating page CSS to the shared tokens.
