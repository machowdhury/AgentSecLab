#!/usr/bin/env python3
"""Build the scanner + runtime evidence Dashboard Studio workshop.

Reuses validated Q-SCANNER-* and Q-MCP-* hunts. Bind tokens only.
DET-MCP-001.spl is not modified. No DET-SCANNER. No DET-MCP-CATALOG.
Scanner evidence does not feed CTRL-MCP-001.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
OUT_JSON = (
    ROOT / "learning" / "level_1" / "LAB-SCANNER-RUNTIME-EVIDENCE" / "dashboard.definition.json"
)
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_scanner_runtime_evidence.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
WHITE = "#FFFFFF"

BASELINE_ID = "d95717ed-ffd2-46c0-a130-9a5d7d539a5d"
ATTACK_ID = "a0937bff-31a5-453a-99bf-47d7b5148ce4"
RETEST_ID = "23c222ea-6a87-40b7-a3e9-f12a5b572fa1"
NORMAL_SCAN = "b3061c4e-7a81-445c-8fd8-3108dd14c419"
MALICIOUS_SCAN = "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8"
NORMAL_HASH = "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
MALICIOUS_HASH = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_SCAN = (
    "No indexed finding row was returned for this scan. That is not ZERO FINDINGS, "
    "not SAFE, and not a completed-scan security verdict. It can be a wrong scan_id "
    "or an incomplete copy."
)
EMPTY_CORR = (
    "No matching runtime event was found for this description hash. That is not "
    "proof the runtime never observed the metadata. Check the hash and the complete copy."
)
EMPTY_CONTROL = (
    "No indexed control.decision was found for this run. That is not DENY. "
    "It can be a wrong run.id or an incomplete copy."
)
EMPTY_TOOL = (
    "No indexed follow-on execution event was found for this run. That does not "
    "automatically mean DENY, blocked, or prevented. ERROR, schema failure, and "
    "export loss also look like zero rows."
)
EMPTY_AFTER = (
    "No indexed DENY followed later by mcp.started was found. "
    "That does not independently prove the handler never executed. Runtime handler "
    "count remains authoritative."
)
EMPTY_CATALOG = (
    "Q-MCP-CATALOG-AUTHORITY returned zero rows. Zero rows is not safe, not DENY, "
    "and not proof metadata-derived authority was refused."
)
EMPTY_HUNT = (
    "Hunt run.id defaults to BASELINE. Hunt scan defaults to NORMAL. Replace a "
    "token and Submit to hunt another complete copy. Empty tables are missing "
    "indexed rows, not security outcomes."
)

SCANNER_NOT_AUTHZ = (
    "SCANNER FINDING != AUTHORIZATION DECISION. SCANNER HIGH != HIGH-SEVERITY "
    "INCIDENT. ZERO FINDINGS != SAFE. METADATA OBSERVED != AUTHORIZED. "
    "REQUEST != GRANT. ALLOW != EXECUTION. mcp.started != SUCCESS. "
    "DENY + NO SPLUNK EVENT != INDEPENDENT PROOF OF NON-EXECUTION. "
    "SPLUNK != ENFORCEMENT."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at mcp.started. "
    "Do not read ALLOW as execution. mcp.completed is success of a begun call. "
    "mcp.failed is execution then error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of non-execution. Missing "
    "Splunk execution event is corroboration only, and only on a complete copy."
)
PLANES = (
    "PLANE 1 is artifact evidence (Cisco mcp-scanner). PLANE 2 is runtime trust "
    "and request (METADATA-001). PLANE 3 is authorization and execution "
    "(CTRL-MCP-001). Do not collapse these planes."
)


def load_spl(name: str, *, catalog: bool = False) -> str:
    directory = CATALOG_DIR if catalog else SEARCH_DIR
    return (directory / name).read_text(encoding="utf-8").strip()


def bind_run_id(spl: str, token: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError(f"expected __RUN_ID__ in query for token {token}")
    return spl.replace("__RUN_ID__", f'"${token}$"')


def bind_scan_id(spl: str, token: str) -> str:
    if "__SCAN_ID__" not in spl:
        raise ValueError(f"expected __SCAN_ID__ in query for token {token}")
    return spl.replace("__SCAN_ID__", f'"${token}$"')


def bind_hash(spl: str, value: str) -> str:
    if "__DESCRIPTION_SHA256__" not in spl:
        raise ValueError("expected __DESCRIPTION_SHA256__")
    return spl.replace("__DESCRIPTION_SHA256__", value)


def block(item: str, x: int, y: int, w: int, h: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def markdown(viz_id: str, body: str, title: str | None = None) -> tuple[str, dict]:
    viz = {
        "type": "splunk.markdown",
        "options": {
            "markdown": textwrap.dedent(body).strip() + "\n",
            "fontColor": TEXT,
            "backgroundColor": WHITE,
            "fontSize": "large",
        },
    }
    if title:
        viz["title"] = title
    return viz_id, viz


def table(
    viz_id: str,
    ds: str,
    title: str,
    description: str,
    *,
    no_data: str,
) -> tuple[str, dict]:
    return viz_id, {
        "type": "splunk.table",
        "title": title,
        "description": description,
        "dataSources": {"primary": ds},
        "showProgressBar": True,
        "showLastUpdated": False,
        "hideWhenNoData": False,
        "options": {
            "count": 50,
            "showRowNumbers": False,
            "backgroundColor": WHITE,
            "headerBackgroundColor": NAVY,
            "headerTextColor": WHITE,
            "noDataMessage": no_data,
        },
    }


def search_ds(ds_id: str, name: str, query: str) -> tuple[str, dict]:
    return ds_id, {
        "type": "ds.search",
        "name": name,
        "options": {"query": query},
    }


def layout(structure: list[dict], height: int) -> dict:
    return {
        "type": "grid",
        "options": {
            "backgroundColor": BG,
            "display": "auto-scale",
            "gutterSize": 8,
            "width": CANVAS_W,
            "height": height,
        },
        "structure": structure,
    }


def build() -> dict:
    q_who_scan = bind_scan_id(load_spl("Q-SCANNER-WHO.spl", catalog=True), "scan_id")
    q_art_scan = bind_scan_id(load_spl("Q-SCANNER-ARTIFACT.spl", catalog=True), "scan_id")
    q_find_scan = bind_scan_id(load_spl("Q-SCANNER-FINDINGS.spl", catalog=True), "scan_id")
    q_who_n = bind_scan_id(load_spl("Q-SCANNER-WHO.spl", catalog=True), "normal_scan_id")
    q_art_n = bind_scan_id(load_spl("Q-SCANNER-ARTIFACT.spl", catalog=True), "normal_scan_id")
    q_find_n = bind_scan_id(load_spl("Q-SCANNER-FINDINGS.spl", catalog=True), "normal_scan_id")
    q_who_m = bind_scan_id(load_spl("Q-SCANNER-WHO.spl", catalog=True), "malicious_scan_id")
    q_art_m = bind_scan_id(load_spl("Q-SCANNER-ARTIFACT.spl", catalog=True), "malicious_scan_id")
    q_find_m = bind_scan_id(load_spl("Q-SCANNER-FINDINGS.spl", catalog=True), "malicious_scan_id")
    q_corr_n = bind_hash(load_spl("Q-SCANNER-RUNTIME-CORRELATION.spl", catalog=True), NORMAL_HASH)
    q_corr_m = bind_hash(
        load_spl("Q-SCANNER-RUNTIME-CORRELATION.spl", catalog=True), MALICIOUS_HASH
    )
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_catalog = bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), "run_id")
    q_authz_b = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "baseline_run_id")
    q_authz_a = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "attack_run_id")
    q_authz_r = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "retest_run_id")
    q_tool_r = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "retest_run_id")
    q_exec_b = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "baseline_run_id")
    q_exec_a = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "attack_run_id")
    q_exec_r = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "retest_run_id")
    q_cat_b = bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), "baseline_run_id")
    q_cat_a = bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), "attack_run_id")
    q_cat_r = bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), "retest_run_id")
    q_after_a = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "attack_run_id")
    q_after_r = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "retest_run_id")

    data_sources = dict(
        (
            search_ds("ds_scan_who", "Q-SCANNER-WHO Hunt", q_who_scan),
            search_ds("ds_scan_art", "Q-SCANNER-ARTIFACT Hunt", q_art_scan),
            search_ds("ds_scan_find", "Q-SCANNER-FINDINGS Hunt", q_find_scan),
            search_ds("ds_scan_who_n", "Q-SCANNER-WHO NORMAL", q_who_n),
            search_ds("ds_scan_art_n", "Q-SCANNER-ARTIFACT NORMAL", q_art_n),
            search_ds("ds_scan_find_n", "Q-SCANNER-FINDINGS NORMAL", q_find_n),
            search_ds("ds_scan_who_m", "Q-SCANNER-WHO MALICIOUS", q_who_m),
            search_ds("ds_scan_art_m", "Q-SCANNER-ARTIFACT MALICIOUS", q_art_m),
            search_ds("ds_scan_find_m", "Q-SCANNER-FINDINGS MALICIOUS", q_find_m),
            search_ds("ds_corr_n", "Q-SCANNER-RUNTIME-CORRELATION NORMAL", q_corr_n),
            search_ds("ds_corr_m", "Q-SCANNER-RUNTIME-CORRELATION MALICIOUS", q_corr_m),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_catalog", "Q-MCP-CATALOG-AUTHORITY", q_catalog),
            search_ds("ds_q_authz_b", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_a", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_r", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_tool_r", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_exec_b", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_exec_a", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_exec_r", "Q-MCP-EXECUTED RETEST", q_exec_r),
            search_ds("ds_q_cat_b", "Q-MCP-CATALOG-AUTHORITY BASELINE", q_cat_b),
            search_ds("ds_q_cat_a", "Q-MCP-CATALOG-AUTHORITY ATTACK", q_cat_a),
            search_ds("ds_q_cat_r", "Q-MCP-CATALOG-AUTHORITY RETEST", q_cat_r),
            search_ds("ds_q_after_a", "Q-MCP-AFTER-DENY ATTACK", q_after_a),
            search_ds("ds_q_after_r", "Q-MCP-AFTER-DENY RETEST", q_after_r),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
        )
    )

    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str, *, no_data: str) -> str:
        key, viz = table(viz_id, ds, title, description, no_data=no_data)
        visualizations[key] = viz
        return key

    cap_who = (
        "Q-SCANNER-WHO. Scan-summary event on sourcetype agentsec:scanner:finding. "
        "target_executed answers whether the scan ran. That is not a security verdict."
    )
    cap_art = (
        "Q-SCANNER-ARTIFACT. description_sha256 is the runtime correlation key. "
        "artifact.sha256 is the file hash of the exported catalog JSON. File hash "
        "is not the runtime join key."
    )
    cap_find = (
        "Q-SCANNER-FINDINGS. finding_state distinguishes scan_executed_zero_findings "
        "from finding_present. Native HIGH is scanner-native severity, not incident HIGH."
    )
    cap_corr = (
        "Q-SCANNER-RUNTIME-CORRELATION. Join is description SHA-256, not artifact "
        "file hash. Scanner rows and METADATA-001 rows share the hash. Correlation "
        "is not authorization."
    )
    cap_catalog = (
        "Q-MCP-CATALOG-AUTHORITY. metadata_trust=untrusted_data. METADATA-001 stays "
        "OBSERVE. Follow-on decision is CTRL-MCP-001, not the scanner."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. METADATA-001 OBSERVE is classification, "
        "not a grant. Do not collapse METADATA-001 into CTRL-MCP-001."
    )
    cap_tool = "Q-MCP-TOOL mcp.started rows. Zero rows is not automatically DENY."
    cap_exec = (
        "Q-MCP-EXECUTED. Read has_started and execution_state for whether the "
        "handler began. " + ALLOW_NOT_EXEC
    )

    add_md(
        "viz_learn",
        f"""
# Scanner + runtime evidence

**WS-SCANNER-RUNTIME** · GUIDED · schema **1.5.0** · INV-002

**When an external security scanner flags agent/tool metadata, what can the SOC actually conclude from that evidence?**

External security evidence and runtime authorization answer **different questions**. Scanner evidence informs investigation. Scanner evidence does **not** feed CTRL-MCP-001.

- SCANNER FINDING != AUTHORIZATION DECISION
- SCANNER HIGH != HIGH-SEVERITY INCIDENT
- ZERO FINDINGS != SAFE
- METADATA OBSERVED != AUTHORIZED
- REQUEST != GRANT
- ALLOW != EXECUTION
- mcp.started != SUCCESS
- SPLUNK != ENFORCEMENT

**LIVE ids (copy the full UUID / hash)**

BASELINE RUN `{BASELINE_ID}`

ATTACK RUN `{ATTACK_ID}`

RETEST RUN `{RETEST_ID}`

NORMAL SCAN `{NORMAL_SCAN}`

MALICIOUS SCAN `{MALICIOUS_SCAN}`

NORMAL hash `{NORMAL_HASH}`

MALICIOUS hash `{MALICIOUS_HASH}`

```text
MCP catalog
    |
    +----> Cisco mcp-scanner ----> Artifact Evidence  (PLANE 1)
    |
    +----> Agent runtime
               |
               +--> Metadata Observation  (PLANE 2)
               |
               +--> Follow-on Request --> CTRL-MCP-001  (PLANE 3)
                                          ALLOW --> execution
                                          DENY  --> X
```

This workshop is not a second catalog-poisoning runtime. LAB-MCP-CATALOG taught whether metadata can influence a request. This workshop teaches how a SOC combines scanner and runtime evidence. Splunk does **not** ALLOW or DENY.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_p1",
        """
# PLANE 1 Artifact

**Source:** Cisco mcp-scanner (static YARA)

**Questions:** What artifact was scanned? Did the scan execute? Were findings produced? What was the native severity? What description SHA-256 was scanned?

**Evidence class:** OBSERVED_SCANNER

A finding is not an exploit. Native HIGH is not incident HIGH.
""",
        title="PLANE 1",
    )
    add_md(
        "viz_learn_p2",
        """
# PLANE 2 Trust / request

**Source:** CTRL-MCP-METADATA-001 + catalog telemetry

**Questions:** Did the runtime observe the same metadata? What description hash was observed? Was metadata classified as untrusted_data? Did it influence a follow-on request?

METADATA-001 stays **OBSERVE**. OBSERVE is classification, not authorization.
""",
        title="PLANE 2",
    )
    add_md(
        "viz_learn_p3",
        """
# PLANE 3 Authz / execution

**Source:** CTRL-MCP-001 + MCP execution telemetry

**Questions:** Was the follow-on request ALLOW or DENY? Why? Did mcp.started occur? Did the handler complete or fail?

Provenance says where bytes came from. Trust says how they are classified. Authorization says whether the tool is granted.
""",
        title="PLANE 3",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**PLANE 1:** NORMAL scan executed · finding_count=**0** · finding_state=`scan_executed_zero_findings`

Do **not** display PASS. Do **not** label this SAFE, trusted, or approved.

**Zero findings means this scanner produced zero findings for this artifact under this scan configuration.** Nothing stronger.

**PLANE 2:** METADATA-001 **OBSERVE** `metadata_is_data` · hash `{NORMAL_HASH}`

**PLANE 3:** `lookup_policy` ALLOW `tool_granted` · mcp.started · mcp.completed · **no follow-on**

NORMAL SCAN `{NORMAL_SCAN}` · BASELINE RUN `{BASELINE_ID}`

Tables use the **NORMAL SCAN** and **BASELINE RUN** tokens.
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_who",
        "ds_scan_who_n",
        "PLANE 1 Q-SCANNER-WHO",
        cap_who + " Expect cisco-ai-mcp-scanner, target_executed, LIVE.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_baseline_find",
        "ds_scan_find_n",
        "PLANE 1 Q-SCANNER-FINDINGS",
        cap_find + " Expect scan_executed_zero_findings. Not SAFE.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_baseline_art",
        "ds_scan_art_n",
        "PLANE 1 Q-SCANNER-ARTIFACT",
        cap_art + " Expect NORMAL description hash.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_baseline_corr",
        "ds_corr_n",
        "PLANES 1+2 Q-SCANNER-RUNTIME-CORRELATION",
        cap_corr + " NORMAL hash should match BASELINE METADATA-001.",
        no_data=EMPTY_CORR,
    )
    add_table(
        "viz_baseline_cat",
        "ds_q_cat_b",
        "PLANE 2 Q-MCP-CATALOG-AUTHORITY",
        cap_catalog + " Expect OBSERVE, no_followon.",
        no_data=EMPTY_CATALOG,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_b",
        "PLANE 3 Q-MCP-AUTHZ",
        cap_authz + " Expect METADATA-001 OBSERVE then lookup_policy ALLOW.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_exec_b",
        "PLANE 3 Q-MCP-EXECUTED",
        cap_exec + " lookup_policy started. No follow-on.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE** — not a production exploit.

**PLANE 1:** MALICIOUS scan executed · finding_count=**1** · native category **PROMPT INJECTION** · native severity **HIGH** · tool `lookup_policy` · analyzer `yara_analyzer`

The scanner independently identified suspicious metadata.

**PLANE 2:** same MALICIOUS hash observed · METADATA-001 **OBSERVE**

`{MALICIOUS_HASH}`

**PLANE 3:** follow-on REQUEST `lookup_customer_tier` · CTRL-MCP-001 **ALLOW** · reason `vulnerable_profile_fail_open:metadata_derived_authority` · mcp.started · mcp.completed · runtime follow-on handler **1**

The vulnerable AgentSec profile independently allowed metadata-derived authority.

Do **not** treat native HIGH as the cause of execution.

MALICIOUS SCAN `{MALICIOUS_SCAN}` · ATTACK RUN `{ATTACK_ID}`
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_who",
        "ds_scan_who_m",
        "PLANE 1 Q-SCANNER-WHO",
        cap_who + " Expect cisco-ai-mcp-scanner, target_executed, LIVE.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_attack_find",
        "ds_scan_find_m",
        "PLANE 1 Q-SCANNER-FINDINGS",
        cap_find + " Expect finding_present, native HIGH, PROMPT INJECTION.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_attack_art",
        "ds_scan_art_m",
        "PLANE 1 Q-SCANNER-ARTIFACT",
        cap_art + " Expect MALICIOUS description hash.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_attack_corr",
        "ds_corr_m",
        "PLANES 1+2 Q-SCANNER-RUNTIME-CORRELATION",
        cap_corr + " Same MALICIOUS hash as RETEST. ATTACK mode is vulnerable.",
        no_data=EMPTY_CORR,
    )
    add_table(
        "viz_attack_cat",
        "ds_q_cat_a",
        "PLANE 2 Q-MCP-CATALOG-AUTHORITY",
        cap_catalog + " Expect OBSERVE, follow-on ALLOW, mcp.completed_observed.",
        no_data=EMPTY_CATALOG,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_a",
        "PLANE 3 Q-MCP-AUTHZ",
        cap_authz + " Hop-1 ALLOW is the vulnerable grant, not scanner authorization.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_exec_a",
        "PLANE 3 Q-MCP-EXECUTED",
        cap_exec + " Follow-on lookup_customer_tier has_started=1.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Build the investigation around three planes. Tables are telemetry, not a story. Full descriptions and `_raw` are not shown.

Use **Hunt** (defaults to BASELINE) and **Hunt scan** (defaults to NORMAL).

{PLANES}

{SCANNER_NOT_AUTHZ}

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table(
        "viz_obs_who",
        "ds_scan_who",
        "ARTIFACT Q-SCANNER-WHO",
        cap_who,
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_obs_art",
        "ds_scan_art",
        "ARTIFACT Q-SCANNER-ARTIFACT",
        cap_art,
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_obs_find",
        "ds_scan_find",
        "ARTIFACT Q-SCANNER-FINDINGS",
        cap_find,
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_obs_cat",
        "ds_q_catalog",
        "RUNTIME Q-MCP-CATALOG-AUTHORITY",
        cap_catalog,
        no_data=EMPTY_CATALOG,
    )
    add_table(
        "viz_obs_authz",
        "ds_q_authz",
        "AUTHORIZATION Q-MCP-AUTHZ",
        cap_authz,
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_obs_exec",
        "ds_q_executed",
        "EXECUTION Q-MCP-EXECUTED",
        cap_exec,
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

Pivot: **scanner → description hash → runtime → authorization → execution**

**Primary searches (reuse, not rewritten):** Q-SCANNER-WHO · Q-SCANNER-ARTIFACT · Q-SCANNER-FINDINGS · Q-SCANNER-RUNTIME-CORRELATION

**Runtime reuse:** Q-MCP-AUTHZ · Q-MCP-EXECUTED · Q-MCP-CATALOG-AUTHORITY

Copy `description_sha256` from the artifact table. That field correlates scanner evidence with runtime metadata. `artifact.sha256` is the exported file hash and is **not** the runtime correlation key.

No DET-SCANNER. No DET-MCP-CATALOG. Hunts are not detectors.

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_who", "ds_scan_who", "Q-SCANNER-WHO", cap_who, no_data=EMPTY_SCAN)
    add_table("viz_hunt_art", "ds_scan_art", "Q-SCANNER-ARTIFACT", cap_art, no_data=EMPTY_SCAN)
    add_table("viz_hunt_find", "ds_scan_find", "Q-SCANNER-FINDINGS", cap_find, no_data=EMPTY_SCAN)
    add_table(
        "viz_hunt_corr_n",
        "ds_corr_n",
        "Q-SCANNER-RUNTIME-CORRELATION NORMAL hash",
        cap_corr,
        no_data=EMPTY_CORR,
    )
    add_table(
        "viz_hunt_corr_m",
        "ds_corr_m",
        "Q-SCANNER-RUNTIME-CORRELATION MALICIOUS hash",
        cap_corr + " ATTACK and RETEST share this fingerprint.",
        no_data=EMPTY_CORR,
    )
    add_table(
        "viz_hunt_cat",
        "ds_q_catalog",
        "Q-MCP-CATALOG-AUTHORITY",
        cap_catalog,
        no_data=EMPTY_CATALOG,
    )
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=EMPTY_CONTROL)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=EMPTY_TOOL)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_exec, no_data=EMPTY_TOOL)

    add_md(
        "viz_detect_md",
        """
# DETECT — DETECTION ANALYZED — NO NEW DETECTOR

Phase 9D concluded: **do not create a detector.** This dashboard does **not** enable DET-MCP-001. **No DET-SCANNER. No DET-MCP-CATALOG. No DET-MCP-005.**

DET-MCP-001 detects **DENY then later mcp.started**. It is behaving correctly.

- **ATTACK = 0** because no DENY occurred (vulnerable ALLOW).
- **RETEST = 0** because DENY occurred but no later mcp.started.

Zero rows is not detector failure. Zero rows is not SAFE. The two tables below are **expected empty**. Studio may show its default empty graphic. That is 0 indexed DENY-then-start rows, not SAFE and not detector failure.

**Phase 9D candidate classification**

- Scanner finding: **CONTEXT / HUNT**
- Finding + runtime metadata: **HUNT**
- Finding + request: **HUNT**
- Finding + ALLOW: **LAB HUNT ONLY**
- Finding + execution: **FUTURE RESEARCH / TELEMETRY DEPENDENT**
- `metadata_derived_authority` reason: **REJECT** as production detector
- DENY then execution: **DET-MCP-001** (existing)

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not OBSERVED runtime. Not LIVE.
""",
        title="STEP 5 DETECT",
    )
    add_table(
        "viz_detect_attack",
        "ds_q_after_a",
        "DET-MCP-001 hunt Q-MCP-AFTER-DENY ATTACK",
        "Indexed hunt. ATTACK is ALLOW-path fail-open, so 0 rows is expected. Not a detector failure. Not SAFE.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_retest",
        "ds_q_after_r",
        "DET-MCP-001 hunt Q-MCP-AFTER-DENY RETEST",
        "Indexed hunt. RETEST DENY then no later mcp.started, so 0 rows is expected. Runtime handler count 0 is authoritative.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. DENY then mcp.started. Do not treat as a live incident.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

The scanner does **not** block the tool. Splunk does **not** block the tool. Metadata trust classification does **not** grant authority.

CTRL-MCP-001 decides whether the follow-on request is authorized.

```text
MALICIOUS metadata
      ↓
REQUEST lookup_customer_tier
      ↓
CTRL-MCP-001
      ↓
DENY tool_not_granted
      ↓
handler count 0
```

Do **not** claim the scanner prevented execution.

Scanner HIGH on this artifact is unchanged between ATTACK and RETEST. The authorization outcome is what changed.

{RUNTIME_AUTH}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_planes",
        f"""
# What each plane can prove

**PLANE 1** can prove: a scan executed and a native finding existed for this description hash.

**PLANE 2** can prove: the runtime observed the same hash as untrusted_data and a follow-on was requested.

**PLANE 3** can prove: ALLOW or DENY, and whether mcp.started occurred.

INV-002: data cannot grant authority. Provenance is not trust. Trust is not a grant.

{SCANNER_NOT_AUTHZ}
""",
        title="PLANES",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

profile = **defended** · same MALICIOUS artifact as ATTACK

Scanner finding is **unchanged** (finding_count=1, native HIGH).

ATTACK hash == RETEST hash:

`{MALICIOUS_HASH}`

- METADATA-001: **OBSERVE** `metadata_is_data`
- same follow-on REQUEST `lookup_customer_tier`
- CTRL-MCP-001 **DENY** `tool_not_granted`
- runtime handler count = **0** (authoritative non-execution proof)
- no follow-on mcp.started on COMPLETE Splunk copy (corroboration)

Missing Splunk execution event is corroboration. It is not independent proof of non-execution.

MALICIOUS SCAN `{MALICIOUS_SCAN}` · RETEST RUN `{RETEST_ID}`
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_find",
        "ds_scan_find_m",
        "PLANE 1 Q-SCANNER-FINDINGS (same MALICIOUS scan)",
        cap_find + " Unchanged from ATTACK. Scanner evidence is the same.",
        no_data=EMPTY_SCAN,
    )
    add_table(
        "viz_retest_corr",
        "ds_corr_m",
        "PLANES 1+2 same MALICIOUS hash",
        cap_corr + " Correlation includes ATTACK and RETEST run ids.",
        no_data=EMPTY_CORR,
    )
    add_table(
        "viz_retest_cat",
        "ds_q_cat_r",
        "PLANE 2 Q-MCP-CATALOG-AUTHORITY",
        cap_catalog + " Expect same hash, OBSERVE, follow-on DENY.",
        no_data=EMPTY_CATALOG,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_r",
        "PLANE 3 Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 DENY tool_not_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_r",
        "PLANE 3 Q-MCP-TOOL",
        cap_tool + " lookup_policy start is expected. No follow-on mcp.started.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_exec_r",
        "PLANE 3 Q-MCP-EXECUTED",
        cap_exec + " Follow-on should show no_mcp_execution_event.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

**THE SCANNER EVIDENCE FOR ATTACK AND RETEST IS THE SAME.**

**THE AUTHORIZATION OUTCOME IS DIFFERENT.**

Therefore: scanner finding != authorization decision.

Fingerprint (hash, not preview): `{MALICIOUS_HASH}`
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**Artifact:** NORMAL

**Scanner:** ZERO FINDINGS (scan executed)

**Follow-on:** none

**Authz:** lookup_policy ALLOW

**Execution:** lookup_policy mcp.completed

Not labeled SAFE.

`{BASELINE_ID}`
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**Artifact:** MALICIOUS

**Scanner:** native HIGH · PROMPT INJECTION

**Follow-on:** lookup_customer_tier

**Authz:** ALLOW (INTENTIONALLY VULNERABLE)

**Execution:** mcp.started · mcp.completed · handler 1

Scanner HIGH did not grant the tool.

`{ATTACK_ID}`
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**Artifact:** SAME MALICIOUS

**Scanner:** SAME native HIGH

**Follow-on:** same request

**Authz:** DENY tool_not_granted

**Execution:** handler 0 · no follow-on mcp.started

CTRL-MCP-001 changed the outcome.

`{RETEST_ID}`
""",
        title="RETEST",
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Answer from indexed evidence. Full hashes and ids are on LEARN.

1. Did the NORMAL scan run? Look at Q-SCANNER-WHO `target_executed` for `{NORMAL_SCAN}`.
2. Does zero findings prove the artifact is safe? No. It means this scanner produced zero findings for this artifact under this scan configuration.
3. What field correlates scanner evidence with runtime metadata? `artifact.description_sha256` / `agentsec.content.hash`.
4. Why is artifact.sha256 not the runtime correlation key? It hashes the exported catalog file, not the tool description bytes the runtime observed.
5. Did the scanner authorize lookup_customer_tier? No. Scanner evidence does not feed CTRL-MCP-001.
6. Why does ATTACK execute? The vulnerable profile independently ALLOWED metadata-derived authority. Not because of scanner HIGH.
7. Why does RETEST not execute? CTRL-MCP-001 DENY `tool_not_granted`. Runtime handler count 0.
8. Why does DET-MCP-001 return zero for ATTACK? No DENY occurred.
9. Why does DET-MCP-001 return zero for RETEST? DENY occurred, but no later mcp.started.
10. What is the difference between provenance and trust? Provenance is where the bytes came from. Trust is how they are classified (`untrusted_data`).
11. Which evidence plane proves authorization? PLANE 3 (CTRL-MCP-001).
12. Which evidence proves handler non-execution? Runtime handler count. Missing Splunk mcp.started is corroboration.
13. Why must scanner native HIGH not automatically become incident HIGH? Native severity is the scanner's label. Incident severity needs authorization, execution, and impact context.
14. What would a SOC need before promoting this hunt into a production detection? Stable grant snapshots, pin telemetry, a join stronger than lab overlay strings, and a defined true-positive class that is not ATTACK-and-RETEST-identical scanner HIGH.
15. Which AgentSec invariant is being demonstrated? INV-002 Data Cannot Grant Authority.

{SCANNER_NOT_AUTHZ}
""",
        title="STEP 10 PROVE",
    )
    add_table(
        "viz_prove_corr",
        "ds_corr_m",
        "MALICIOUS hash correlation (ATTACK + RETEST)",
        cap_corr + " Use this row to prove ATTACK and RETEST share the fingerprint.",
        no_data=EMPTY_CORR,
    )

    definition = {
        "title": "LAB-SCANNER-RUNTIME Scanner + Runtime Evidence",
        "description": (
            "WS-SCANNER-RUNTIME. Validated Q-SCANNER and Q-MCP hunts. "
            "DET-MCP-001 packaged disabled. No DET-SCANNER. No DET-MCP-CATALOG. "
            "Scanner evidence does not authorize. Splunk does not ALLOW or DENY."
        ),
        "defaults": {
            "visualizations": {
                "splunk.table": {
                    "options": {
                        "backgroundColor": WHITE,
                        "headerBackgroundColor": NAVY,
                        "headerTextColor": WHITE,
                    }
                },
                "splunk.markdown": {"options": {"fontColor": TEXT, "fontSize": "large"}},
            }
        },
        "inputs": {
            "input_run_id": {
                "type": "input.text",
                "title": "Hunt",
                "options": {"token": "run_id", "defaultValue": BASELINE_ID},
            },
            "input_scan_id": {
                "type": "input.text",
                "title": "Hunt scan",
                "options": {"token": "scan_id", "defaultValue": NORMAL_SCAN},
            },
            "input_baseline_run_id": {
                "type": "input.text",
                "title": "BASELINE RUN",
                "options": {"token": "baseline_run_id", "defaultValue": BASELINE_ID},
            },
            "input_attack_run_id": {
                "type": "input.text",
                "title": "ATTACK RUN",
                "options": {"token": "attack_run_id", "defaultValue": ATTACK_ID},
            },
            "input_retest_run_id": {
                "type": "input.text",
                "title": "RETEST RUN",
                "options": {"token": "retest_run_id", "defaultValue": RETEST_ID},
            },
            "input_normal_scan_id": {
                "type": "input.text",
                "title": "NORMAL SCAN",
                "options": {"token": "normal_scan_id", "defaultValue": NORMAL_SCAN},
            },
            "input_malicious_scan_id": {
                "type": "input.text",
                "title": "MALICIOUS SCAN",
                "options": {"token": "malicious_scan_id", "defaultValue": MALICIOUS_SCAN},
            },
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": {
                "submitButton": True,
                "submitOnDashboardLoad": True,
                "showTitleAndDescription": True,
            },
            "globalInputs": [
                "input_run_id",
                "input_scan_id",
                "input_baseline_run_id",
                "input_attack_run_id",
                "input_retest_run_id",
                "input_normal_scan_id",
                "input_malicious_scan_id",
            ],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_learn", "label": "LEARN"},
                    {"layoutId": "layout_baseline", "label": "BASELINE"},
                    {"layoutId": "layout_attack", "label": "ATTACK"},
                    {"layoutId": "layout_observe", "label": "OBSERVE"},
                    {"layoutId": "layout_hunt", "label": "HUNT"},
                    {"layoutId": "layout_detect", "label": "DETECT"},
                    {"layoutId": "layout_defend", "label": "DEFEND"},
                    {"layoutId": "layout_retest", "label": "RETEST"},
                    {"layoutId": "layout_compare", "label": "COMPARE"},
                    {"layoutId": "layout_prove", "label": "PROVE"},
                ],
            },
            "layoutDefinitions": {
            "layout_learn": layout(
                [
                    block("viz_learn", 0, 0, FULL, 720),
                    block("viz_learn_p1", 0, 720, THIRD, 280),
                    block("viz_learn_p2", THIRD, 720, THIRD, 280),
                    block("viz_learn_p3", THIRD * 2, 720, THIRD, 280),
                ],
                1020,
            ),
            "layout_baseline": layout(
                [
                    block("viz_baseline_md", 0, 0, FULL, 340),
                    block("viz_baseline_who", 0, 340, HALF, 240),
                    block("viz_baseline_find", HALF, 340, HALF, 240),
                    block("viz_baseline_art", 0, 580, FULL, 240),
                    block("viz_baseline_corr", 0, 820, FULL, 240),
                    block("viz_baseline_cat", 0, 1060, FULL, 240),
                    block("viz_baseline_authz", 0, 1300, HALF, 260),
                    block("viz_baseline_exec", HALF, 1300, HALF, 260),
                ],
                1580,
            ),
            "layout_attack": layout(
                [
                    block("viz_attack_md", 0, 0, FULL, 420),
                    block("viz_attack_who", 0, 420, THIRD, 260),
                    block("viz_attack_find", THIRD, 420, THIRD, 260),
                    block("viz_attack_art", THIRD * 2, 420, THIRD, 260),
                    block("viz_attack_corr", 0, 680, FULL, 240),
                    block("viz_attack_cat", 0, 920, FULL, 240),
                    block("viz_attack_authz", 0, 1160, HALF, 280),
                    block("viz_attack_exec", HALF, 1160, HALF, 280),
                ],
                1460,
            ),
            "layout_observe": layout(
                [
                    block("viz_observe_md", 0, 0, FULL, 280),
                    block("viz_obs_who", 0, 280, THIRD, 260),
                    block("viz_obs_art", THIRD, 280, THIRD, 260),
                    block("viz_obs_find", THIRD * 2, 280, THIRD, 260),
                    block("viz_obs_cat", 0, 540, FULL, 260),
                    block("viz_obs_authz", 0, 800, HALF, 260),
                    block("viz_obs_exec", HALF, 800, HALF, 260),
                ],
                1080,
            ),
            "layout_hunt": layout(
                [
                    block("viz_hunt_md", 0, 0, FULL, 300),
                    block("viz_hunt_who", 0, 300, HALF, 240),
                    block("viz_hunt_art", HALF, 300, HALF, 240),
                    block("viz_hunt_find", 0, 540, FULL, 240),
                    block("viz_hunt_corr_n", 0, 780, HALF, 240),
                    block("viz_hunt_corr_m", HALF, 780, HALF, 240),
                    block("viz_hunt_cat", 0, 1020, FULL, 240),
                    block("viz_hunt_authz", 0, 1260, THIRD, 240),
                    block("viz_hunt_tool", THIRD, 1260, THIRD, 240),
                    block("viz_hunt_exec", THIRD * 2, 1260, THIRD, 240),
                ],
                1520,
            ),
            "layout_detect": layout(
                [
                    block("viz_detect_md", 0, 0, FULL, 420),
                    block("viz_detect_attack", 0, 420, HALF, 320),
                    block("viz_detect_retest", HALF, 420, HALF, 320),
                    block("viz_detect_sim", 0, 740, FULL, 280),
                ],
                1040,
            ),
            "layout_defend": layout(
                [
                    block("viz_defend", 0, 0, FULL, 420),
                    block("viz_defend_planes", 0, 420, FULL, 360),
                ],
                800,
            ),
            "layout_retest": layout(
                [
                    block("viz_retest_md", 0, 0, FULL, 380),
                    block("viz_retest_find", 0, 380, HALF, 240),
                    block("viz_retest_corr", HALF, 380, HALF, 240),
                    block("viz_retest_cat", 0, 620, FULL, 240),
                    block("viz_retest_authz", 0, 860, FULL, 280),
                    block("viz_retest_tool", 0, 1140, HALF, 260),
                    block("viz_retest_exec", HALF, 1140, HALF, 260),
                ],
                1420,
            ),
            "layout_compare": layout(
                [
                    block("viz_compare_md", 0, 0, FULL, 260),
                    block("viz_cmp_card_base", 0, 260, THIRD, 420),
                    block("viz_cmp_card_atk", THIRD, 260, THIRD, 420),
                    block("viz_cmp_card_rt", THIRD * 2, 260, THIRD, 420),
                ],
                700,
            ),
            "layout_prove": layout(
                [
                    block("viz_prove", 0, 0, FULL, 720),
                    block("viz_prove_corr", 0, 720, FULL, 280),
                ],
                1020,
            ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    return definition


def write_xml(definition: dict) -> None:
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>LAB-SCANNER-RUNTIME Scanner + Runtime Evidence</label>\n"
        "  <description>WS-SCANNER-RUNTIME. Validated Q-SCANNER and Q-MCP hunts. DET-MCP-001 packaged disabled. No DET-SCANNER. No DET-MCP-CATALOG. Scanner evidence does not authorize. Splunk does not ALLOW or DENY.</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    OUT_XML.parent.mkdir(parents=True, exist_ok=True)
    OUT_XML.write_text(xml, encoding="utf-8")


def main() -> None:
    definition = build()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(definition, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_xml(definition)
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
