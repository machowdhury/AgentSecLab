# Phase 15B — LIVE vs REPLAY (RAG)

**LIVE:** Attack Service launch. Fresh UUID `run.id`. Learner hunts in Splunk Search. Studio tokens are not that id.

**REPLAY:** Canonical Phase 10C specimens in the Investigate specimen dropdown. Used by Studio bound tables as reference material.

| Role | BASELINE | ATTACK | RETEST |
|------|----------|--------|--------|
| REPLAY run.id | `51f70fb9-994e-4dd4-9b36-cac6fb1e8232` | `3a43d24f-9281-42f6-8375-1fb2efaa80ac` | `bea97bae-491b-4b36-b52f-1417d2bad01b` |
| Document | NORMAL | MALICIOUS | SAME MALICIOUS bytes |

Do not silently mix LIVE tables with REPLAY labels. Do not call a REPLAY specimen a fresh launch.
