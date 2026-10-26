# Governance Center (`/learn/governance`)

The Center keeps eight things separate: framework relevance, proposed control mapping, observed technical evidence, evaluation outcome, analyst assessment, control attestation, independent verification and formal compliance. **A mapping is never compliance.**

- Relationships between framework items and threats are **PROPOSED** or **RELATED**, taken from `framework_refs.json`.
- Owner, review, attestation, independent verification and compliance are shown as not assigned, not reviewed, none recorded, none, and no assertion. The Center does not invent them.
- NIST AI RMF is listed as `NOT_VERIFIED_IN_THIS_REPOSITORY`: it has no items or mappings here.
- Unmapped threats and missing evidence are listed as gaps, with counts and denominators.
- The Export view builds Markdown or JSON in your browser, deterministically.

Regenerate and check: `PYTHONPATH=src python scripts/export_governance.py --check`.
