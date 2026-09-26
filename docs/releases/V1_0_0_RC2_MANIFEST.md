# AgentSec v1.0.0-rc2 — manifest

## How the commit identity is recorded

The release is two commits. The first is release preparation: version fields, notes, inventory, and validation. The second is this manifest stamp. The annotated tag `v1.0.0-rc2` points at the stamp commit.

A commit cannot contain its own SHA, because the SHA covers the file that would state it. The stamp commit therefore records its parent, the preparation commit. After the tag exists, the tag target is:

```text
git rev-parse v1.0.0-rc2^{}
```

That command is the identity of the stamp commit. This file does not embed that SHA.

| Field | Value |
|-------|--------|
| Release name | AgentSec v1.0.0-rc2 |
| Release version | 1.0.0-rc2 |
| Package version | 1.0.0rc2 |
| Splunk app version | 1.0.0-rc2 |
| Branch | develop |
| RC1 peeled commit | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| Independent review commit | `2eb3cce749100b08a5b85c77b615e6924474cbbc` |
| Preparation commit | `080201be4e9436abb8728da3fd8c649f8ebabc11` |
| Tag | v1.0.0-rc2 |
| Tag type | annotated |
| Tag target | the stamp commit that contains this table after the preparation SHA is filled |
| Runtime schema | 1.9.0 |
| ExternalEvidence contract | 1.0.0 |
| Academy | L0–L10 plus Mastery Check |
| LIVE labs | 7 |
| REPLAY investigation rows | 11 |
| Static / reasoning | L0, L4, L7 activity, Mastery Check |
| Studio XML views | 21 |
| Enabled detectors | none |
| Disabled packaged detector | DET-MCP-001 |
| Disabled placeholders | Q-RUN, Q-DENY |
| External integrations | Cisco mcp-scanner 4.8.4 (Cisco AI Defense); garak 0.17.0 (NVIDIA). REPLAYED / pack-based |
| Focused tests | 97 passed in 0.55s |
| Full offline tests | 1027 passed, 3 deselected in 13.15s |
| Live Splunk this release | OBSERVED health on existing images still reporting 1.0.0rc1. No new LIVE launch |
| UI smoke | PASS at 1440 and 1024 on the existing volume. Screen reader NOT TESTED |
| Clean-room | NOT PROVEN |
| Limitations | `docs/KNOWN_LIMITATIONS.md` |
| Notes | `V1_0_0_RC2_RELEASE_NOTES.md` |
| Inventory | `V1_0_0_RC2_PRODUCT_INVENTORY.md` |
| Validation | `V1_0_0_RC2_VALIDATION.md` |
| Independent review | `docs/reviews/AGENTSEC_INDEPENDENT_RC2_VALIDATION.md` |
| Artifact checksums | Not used. The RC1 manifest did not require them |

The preparation commit named above is the parent of the stamp commit. The tagged tree does not contain an unfilled placeholder.
