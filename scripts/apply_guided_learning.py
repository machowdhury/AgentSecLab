#!/usr/bin/env python3
"""Inject the guided-learning shell into existing Studio workshops.

Curriculum order stays learning/academy/curriculum.json. This script groups
the existing views, writes navigation, and adds one guide band to the first
tab of each workshop. It does not delete tabs, specimens, or searches.

LIVE workshops gain one empty text token, live_run_id. REPLAY workshops that
already have a run_id specimen token reuse it. Workshops with no run token
get the orientation band only, so an empty token cannot search the index.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.workshop_flows import apply_table_format  # noqa: E402

CURRICULUM_PATH = ROOT / "learning" / "academy" / "curriculum.json"
NAV_PATH = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
ARENA_XML = VIEWS / "ws_agentsec_arena.xml"
PATH_XML = VIEWS / "learner_path.xml"
PATH_JS = ROOT / "splunk_app" / "agentsec" / "appserver" / "static" / "agentsec_learner_path.js"

# Existing human labels. Grouping changes; view names and labels do not.
VIEW_LABELS = {
    "ws_lab_pi_001": "Direct Prompt Injection",
    "ws_lab_mcp_001": "Tool Authorization",
    "ws_lab_mcp_003": "Scope Escalation",
    "ws_lab_mcp_004": "Parameter / Resource Authorization",
    "ws_lab_rag_context": "RAG / Retrieved Context",
    "ws_lab_memory_security": "Persistent Memory",
    "ws_lab_mcp_005": "Tool Result Trust",
    "ws_lab_mcp_catalog": "Tool Catalog",
    "ws_lab_scanner_runtime_evidence": "Scanner + Runtime Evidence",
    "ws_lab_external_evaluation_garak": "External Security Toolbox",
    "ws_lab_agent_goal_integrity": "Goal / Instruction Integrity",
    "ws_lab_agent_delegation": "Agent Identity / Delegation",
    "ws_lab_mcp_006": "Confused Deputy",
    "ws_lab_agentsec_capstone": "Lending Assistant Investigation",
    "ws_lab_splunk_defender_bridge": "Splunk Defender Bridge",
    "ws_lab_blue_team_incident": "AcmeBank Incident AI-2026-001",
    "ws_lab_detection_engineering": "Detection Engineering — Prove Your Coverage",
    "ws_lab_threat_modeling": "Threat Modeling",
    "ws_lab_agent_identity_nhi": "Agent Identity and Non-Human IAM",
    "ws_lab_a2a_auth_delegation": "A2A Authentication and Delegation",
    "ws_lab_hitl_approval": "Human Approval and Action Binding",
    "ws_lab_credential_lifetime": "Short-Lived Credential Lifetime",
    "ws_lab_privacy_data_governance": "Privacy Investigation",
    "ws_lab_purpose_authorization": "RAG Purpose Authorization",
    "ws_lab_recall_isolation": "Memory Ownership and Isolation",
    "ws_lab_asset_inventory": "AI Asset Inventory",
    "ws_lab_component_provenance": "Component Provenance",
    "ws_lab_code_agent_bounds": "Code Agent Bounds",
    "ws_lab_change_bounds": "Change Bounds",
    "ws_lab_multi_stage_incident": "AGENT-2026-009",
    "ws_lab_advanced_capstone": "MASTER-2026-001",
    "ws_agentsec_mastery": "Mastery Check",
}

# Curriculum sequence, collapsed so singleton menus are not the navigation.
GROUPS = [
    (
        "Foundations",
        ["ws_lab_pi_001", "ws_lab_mcp_001", "ws_lab_mcp_003", "ws_lab_mcp_004"],
    ),
    (
        "Context Security",
        [
            "ws_lab_rag_context",
            "ws_lab_memory_security",
            "ws_lab_mcp_005",
            "ws_lab_mcp_catalog",
            "ws_lab_scanner_runtime_evidence",
            "ws_lab_external_evaluation_garak",
        ],
    ),
    (
        "Agent Intent",
        ["ws_lab_agent_goal_integrity", "ws_lab_agent_delegation", "ws_lab_mcp_006"],
    ),
    ("Capstone", ["ws_lab_agentsec_capstone"]),
    (
        "Blue Team and Threat Modeling",
        [
            "ws_lab_splunk_defender_bridge",
            "ws_lab_blue_team_incident",
            "ws_lab_detection_engineering",
            "ws_lab_threat_modeling",
        ],
    ),
    (
        "Identity and Delegation",
        [
            "ws_lab_agent_identity_nhi",
            "ws_lab_a2a_auth_delegation",
            "ws_lab_hitl_approval",
            "ws_lab_credential_lifetime",
        ],
    ),
    (
        "Data and Memory Governance",
        [
            "ws_lab_privacy_data_governance",
            "ws_lab_purpose_authorization",
            "ws_lab_recall_isolation",
            "ws_lab_asset_inventory",
            "ws_lab_component_provenance",
        ],
    ),
    (
        "Operational Scenarios",
        [
            "ws_lab_code_agent_bounds",
            "ws_lab_change_bounds",
            "ws_lab_multi_stage_incident",
        ],
    ),
    ("Mastery", ["ws_lab_advanced_capstone", "ws_agentsec_mastery"]),
]

NO_DATA = (
    "No indexed event matched this evidence question. "
    "No indexed rows for this run.id. If the box is empty, launch or select a run and enter its run.id. "
    "Zero rows are not DENY, not a timeout, and not a backend failure. Those states are reported on Attack Service. "
    "Indexing can lag. HEC HTTP 200 is not this table."
)


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;")


def write_nav(curriculum: dict) -> None:
    collections = [{"label": label, "views": views} for label, views in GROUPS]
    curriculum["nav_collections"] = collections
    lines = [
        '<nav search_view="search" color="0B1F33">',
        '  <view name="ws_agentsec_home" default="true">Home</view>',
        '  <view name="learner_path">Your path</view>',
    ]
    for label, views in GROUPS:
        lines.append(f'  <collection label="{_xml_escape(label)}">')
        for view in views:
            lines.append(f'    <view name="{view}">{_xml_escape(VIEW_LABELS[view])}</view>')
        lines.append("  </collection>")
    lines.append('  <view name="ws_agentsec_arena">Arena</view>')
    lines.append('  <view name="search">Search</view>')
    lines.append("</nav>")
    NAV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def workshop_rows(curriculum: dict) -> list[dict]:
    by_view: dict[str, dict] = {}
    for level in curriculum["levels"]:
        for lab in level["labs"]:
            by_view[lab["view"]] = {
                "view": lab["view"],
                "title": lab["title"],
                "mode": lab["mode"],
                "lab_id": lab["lab_id"],
                "level_id": level["id"],
                "level_title": level["title"],
                "objective": level["learn"],
                "beginner": level["id"] in {"L0", "L1", "L2"},
            }
    for checkpoint in curriculum["checkpoints"]:
        by_view[checkpoint["view"]] = {
            "view": checkpoint["view"],
            "title": checkpoint["title"],
            "mode": checkpoint["mode"],
            "lab_id": checkpoint["lab_id"],
            "level_id": "checkpoint",
            "level_title": checkpoint["placement"],
            "objective": checkpoint["title"],
            "beginner": False,
        }
    by_view["ws_agentsec_mastery"] = {
        "view": "ws_agentsec_mastery",
        "title": "Mastery Check",
        "mode": "REPLAY",
        "lab_id": "MASTERY",
        "level_id": "L10",
        "level_title": "Advanced capstone and mastery",
        "objective": "Check what you can explain. This is not a certificate and not a security verdict.",
        "beginner": False,
    }
    ordered = []
    for _label, views in GROUPS:
        for view in views:
            ordered.append(by_view[view])
    total = len(ordered)
    for index, row in enumerate(ordered):
        row["position"] = index + 1
        row["total"] = total
        nxt = ordered[index + 1] if index + 1 < total else None
        row["next_view"] = nxt["view"] if nxt else "ws_agentsec_arena"
        row["next_title"] = nxt["title"] if nxt else "Arena (optional)"
    return ordered


def _tokens(definition: dict) -> set[str]:
    found = set()
    for inp in definition.get("inputs", {}).values():
        token = inp.get("options", {}).get("token")
        if token:
            found.add(token)
    return found


def _query(token: str, summary: bool) -> str:
    head = (
        f'index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 '
        f'"agentsec.run.id"="${token}$"\n'
        f'| where "${token}$"!=""\n'
        "| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))\n"
        "| eval event_name=mvindex(mvdedup('event.name'),0)\n"
        "| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)\n"
        "| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)\n"
        "| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)\n"
        "| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)\n"
        "| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)\n"
        "| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)\n"
        "| eval agent_id=mvindex(mvdedup('gen_ai.agent.id'),0)\n"
        "| eval outcome=mvindex(mvdedup('agentsec.outcome'),0)\n"
    )
    if summary:
        return head + "| stats count by event_name decision executed\n| sort event_name"
    return (
        head
        + "| table _time sequence event_name control_id decision reason attempted executed mode agent_id outcome\n"
        + "| sort sequence"
    )


#: Labs whose Workbench hands the LIVE run.id to a Studio text input through the
#: URL. Must equal agentsec.search_handoff.LAB_TO_LIVE_RUN_TOKEN (a test pins it).
#: Every other lab still has no such handoff, so "Studio cannot receive that id"
#: stays true for them.
DEEP_LINK_LABS = frozenset({"LAB-MCP-001"})

def _guide_markdown(row: dict, token: str | None, live: bool) -> str:
    nxt = f"/app/agentsec/{row['next_view']}"
    path = "/app/agentsec/learner_path"
    if live and row["lab_id"] in DEEP_LINK_LABS:
        # The Workbench "Investigate evidence" handoff opens the INVESTIGATE tab with
        # the LIVE box filled in (form.live_run_id). That mechanism was OBSERVED to
        # work and is SUPPORTED WITH CONSTRAINTS: it is not a documented Splunk
        # guarantee, so manual entry stays as the fallback and is said to be one.
        do = (
            "1. Open the Attack Service Workbench, record your prediction, and run the experiment.\n"
            "2. Choose **Investigate evidence** in the Workbench. It opens the INVESTIGATE tab with your LIVE run filled in.\n"
            "3. Read the question, the table and the SPL on the INVESTIGATE tab.\n"
            "4. If the **LIVE: your run.id** box still reads `none`, enter your LIVE run.id by hand. That is a fallback for recovery, not the normal path. "
            "The prefill is observed Dashboard Studio behavior, not a documented Splunk guarantee."
        )
        question = "What happened during this run, and where did a control decision stop or continue relative to execution?"
    elif live:
        do = (
            "1. Open Attack Service and launch this LIVE lab.\n"
            "2. Copy the fresh run.id from the launcher.\n"
            "3. Return here and paste it into **LIVE run.id**. Studio cannot receive that id on its own.\n"
            "4. Read the SPL and the table on this tab."
        )
        question = "What happened during this run, and where did a control decision stop or continue relative to execution?"
    elif token:
        do = (
            "1. Use **Investigate specimen** to choose the canonical BASELINE, ATTACK, or RETEST copy.\n"
            "2. Read the SPL and the table on this tab. The rows are that specimen, not a launch you just minted.\n"
            "3. REPLAY is a teaching mode. A historical or simulated copy is not a fresh LIVE run, and it is not a weaker rule."
        )
        question = "What does this canonical specimen show about the control decision, and which separate event, if any, shows execution?"
    else:
        do = (
            "1. Follow this workshop's own specimen or question. It does not mint a run.id.\n"
            "2. Use the searches already on the later tabs.\n"
            "3. Keep simulated, historical, and measured claims in the words this workshop already uses."
        )
        question = "What question is this workshop asking, and which claim does the evidence still leave open?"
    if row["beginner"] and token:
        spl_help = "Beginner read: the search looks in `agentsec_telemetry` for one quoted run.id. The token is the only value you change."
    elif token:
        spl_help = "Advanced: copy the SPL into Search if you want to change the filter. Search is optional from here."
    else:
        spl_help = "This workshop does not add a new run.id search on this tab."
    spl = f"```\n{_query(token, False)}\n```" if token else "No new run.id search is added on this tab."
    launch = ""
    if live:
        launch = f"\n\nLaunch: [Attack Service](/app/agentsec/open_attack?path=/labs/{row['lab_id']})"
    return f"""# Where you are

**{row['level_id']} · {row['level_title']}** · {row['title']} · step {row['position']} of {row['total']} · {row['mode']}

# What you are learning

{row['objective']}

# What you do now

{do}{launch}

# What to investigate

{question}

# What a row means

A `decision` value is a control result. `executed=true` on a start or complete event is execution evidence. Those are different events. A decision row does not prove a handler ran. An execution row does not prove a downstream resource changed.

# What this does not prove

A control decision is not execution. Execution is not a measured downstream resource change. An empty table is not DENY. HEC HTTP 200 is not this table. One RETEST is not universal protection. Progress on Your path is not a security verdict.

# States you may see

**NO RUN.ID** — the box is empty. Launch or select a run, then enter its run.id.

**NO INDEXED RESULTS YET** — zero rows after a real id. Indexing can lag. This is not DENY.

**RUN DENIED** — a control event whose decision is DENY. That is a security result. An empty table is not this state.

**RUN FAILED**, **BACKEND UNAVAILABLE**, and **RUN TIMED OUT** are launcher states. They are not DENY and they are not an empty table.

**NO MATCHING EVIDENCE** — Splunk returned no row for this id. Do not invent the reason.

# SPL used

{spl_help}

{spl}

# Conclude

Write one sentence: what the control decided, and whether a separate event shows execution. Then say one thing the evidence does not prove.

# Next

[{row['next_title']}]({nxt})

Record navigation on [Your path]({path}). Opening this page does not mark the workshop investigated.
"""


def _search(name: str, query: str) -> dict:
    return {
        "type": "ds.search",
        "name": name,
        "options": {"query": query},
    }


def _table(title: str, description: str, source: str) -> dict:
    viz = {
        "type": "splunk.table",
        "title": title,
        "description": description,
        "dataSources": {"primary": source},
        "showProgressBar": True,
        "showLastUpdated": False,
        "hideWhenNoData": False,
        "options": {
            "count": 20,
            "showRowNumbers": False,
            "backgroundColor": "#FFFFFF",
            "headerBackgroundColor": "#0B1F33",
            "headerTextColor": "#FFFFFF",
            "noDataMessage": NO_DATA,
        },
    }
    # Same decision/executed semantics every other evidence table uses. These
    # tables are created here, after apply_workshop_flows.py has run, so they
    # have to ask for the formatting themselves.
    apply_table_format(viz)
    return viz


def _block(item: str, y: int, h: int, width: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": 0, "y": y, "w": width, "h": h}}


def _shift(structure: list, dy: int) -> None:
    for item in structure:
        position = item.get("position")
        if isinstance(position, dict) and "y" in position:
            position["y"] = int(position["y"]) + dy


def apply_guide(definition: dict, row: dict) -> None:
    if "viz_guide_shell" in definition.get("visualizations", {}):
        options = definition["visualizations"]["viz_guide_shell"].setdefault("options", {})
        options["fontSize"] = "large"
        options["fontColor"] = "#17202A"
        for viz_id in ("viz_guide_events", "viz_guide_summary"):
            viz = definition.get("visualizations", {}).get(viz_id)
            if viz and viz.get("options") is not None:
                viz["options"]["noDataMessage"] = NO_DATA
        return
    tabs = definition.get("layout", {}).get("tabs", {}).get("items") or []
    if not tabs:
        return
    layout_id = tabs[0]["layoutId"]
    layout = definition["layout"]["layoutDefinitions"][layout_id]
    structure = layout.setdefault("structure", [])
    width = 1440
    for item in structure:
        position = item.get("position") or {}
        if position.get("w"):
            width = max(width, int(position["w"]))
    live = row["mode"] == "LIVE"
    token = "live_run_id" if live else ("run_id" if "run_id" in _tokens(definition) else None)
    if live and "input_live_run" not in definition.setdefault("inputs", {}):
        definition["inputs"]["input_live_run"] = {
            "type": "input.text",
            "title": "LIVE run.id",
            "options": {"token": "live_run_id", "defaultValue": ""},
        }
        global_inputs = definition["layout"].setdefault("globalInputs", [])
        if "input_live_run" not in global_inputs:
            global_inputs.append("input_live_run")
    definition["visualizations"]["viz_guide_shell"] = {
        "type": "splunk.markdown",
        "title": "Guided path",
        "options": {
            "markdown": _guide_markdown(row, token, live),
            "fontSize": "large",
            "fontColor": "#17202A",
        },
    }
    blocks = [_block("viz_guide_shell", 0, 640, width)]
    shift = 660
    if token:
        definition.setdefault("dataSources", {})
        definition["dataSources"]["ds_guide_events"] = _search("Guided events", _query(token, False))
        definition["dataSources"]["ds_guide_summary"] = _search("Guided summary", _query(token, True))
        definition["visualizations"]["viz_guide_events"] = _table(
            "Indexed events for this run.id",
            "Rows Splunk returned for the token. A decision column is not execution. executed=true is not a downstream resource change.",
            "ds_guide_events",
        )
        definition["visualizations"]["viz_guide_summary"] = _table(
            "Event and decision summary",
            "Counts of indexed copies. A count is not a second execution. Zero is not DENY.",
            "ds_guide_summary",
        )
        blocks.append(_block("viz_guide_events", 660, 420, width))
        blocks.append(_block("viz_guide_summary", 1100, 280, width))
        shift = 1400
    # The architecture flow image has to stay first on the tab
    # (tests/unit/test_visual_learning.py), so lift it above the guide blocks
    # instead of letting the guide push it down the page.
    flow = next((i for i in structure if i.get("item") == "viz_flow_diagram"), None)
    if flow is not None:
        structure.remove(flow)
        flow_offset = int(flow["position"]["h"]) + 8
        flow["position"]["y"] = 0
        # Only the guide blocks move down past the image. Content the generator
        # already authored below the image keeps its existing relationship to it.
        _shift(blocks, flow_offset)
    _shift(structure, shift)
    layout["structure"] = ([flow] if flow is not None else []) + blocks + structure


def _load_xml_definition(text: str) -> dict:
    start = text.index("<![CDATA[") + len("<![CDATA[")
    end = text.index("]]>")
    return json.loads(text[start:end])


def _store_xml_definition(text: str, definition: dict) -> str:
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    start = text.index("<![CDATA[") + len("<![CDATA[")
    end = text.index("]]>")
    return text[:start] + "\n" + payload + "\n  " + text[end:]


def write_arena() -> None:
    labs = [
        ("Direct Prompt Injection", "/labs/LAB-PI-001"),
        ("Tool Authorization", "/labs/LAB-MCP-001"),
        ("RAG / Retrieved Context", "/labs/LAB-RAG-CONTEXT"),
        ("Persistent Memory", "/labs/LAB-MEMORY-001"),
        ("Goal / Instruction Integrity", "/labs/LAB-AGENT-GOAL-INTEGRITY-001"),
        ("Agent Identity / Delegation", "/labs/LAB-AGENT-DELEGATION-001"),
        ("Lending Assistant Investigation", "/labs/LAB-AGENTSEC-CAPSTONE-001"),
    ]
    links = "\n".join(
        f"- [{title}](/app/agentsec/open_attack?path={path})" for title, path in labs
    )
    markdown = f"""# Arena

Optional. This is after the guided curriculum. It is not the start, and it does not replace a workshop.

Use the same LIVE launchers. There is no separate curriculum and no extra grant. Evidence rules are unchanged:

- a control decision is not execution
- execution is not a measured downstream resource change
- an empty search is not DENY
- HEC HTTP 200 is not indexed evidence
- one RETEST is not universal protection

{links}

Return to [Home](/app/agentsec/ws_agentsec_home) or [Your path](/app/agentsec/learner_path) when you want the guided sequence again.
"""
    definition = {
        "title": "Arena",
        "description": "Optional advanced exploration. Same evidence rules as the guided labs.",
        "visualizations": {
            "viz_arena": {"type": "splunk.markdown", "options": {"markdown": markdown}}
        },
        "dataSources": {},
        "inputs": {},
        "layout": {
            "type": "absolute",
            "options": {
                "submitButton": False,
                "submitOnDashboardLoad": True,
                "showTitleAndDescription": True,
            },
            "structure": [_block("viz_arena", 0, 640, 1440)],
            "globalInputs": [],
        },
    }
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>Arena</label>\n"
        "  <description>Optional advanced exploration. Same evidence rules as the guided labs. Not the landing page.</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    ARENA_XML.write_text(xml, encoding="utf-8")


def write_path(rows: list[dict]) -> None:
    catalog = [
        {
            "id": row["view"],
            "title": row["title"],
            "level": row["level_id"],
            "mode": row["mode"],
            "href": f"/app/agentsec/{row['view']}",
        }
        for row in rows
    ]
    # The curriculum owns the catalog only. Rendering, styling and the Splunk
    # dashboard-ready lifecycle in agentsec_learner_path.js are maintained by hand,
    # so splice the catalog in instead of regenerating the whole file.
    source = PATH_JS.read_text(encoding="utf-8")
    marker = "  var CATALOG = "
    start = source.index(marker)
    end = source.index("\n];\n", start) + len("\n];\n")
    block = marker + json.dumps(catalog, indent=2) + ";\n"
    PATH_JS.write_text(source[:start] + block + source[end:], encoding="utf-8")
    xml = """<?xml version="1.0" encoding="utf-8"?>
<dashboard version="1.1" script="agentsec_learner_path.js" hideEdit="true">
  <label>Your path</label>
  <description>Browser-local learning navigation. Not indexed evidence and not a security verdict.</description>
  <row>
    <panel>
      <html>
        <div id="agentsec-progress">
          <p>Learning progress loads in this browser. It is not a Splunk result.</p>
        </div>
      </html>
    </panel>
  </row>
</dashboard>
"""
    PATH_XML.write_text(xml, encoding="utf-8")


def main() -> None:
    curriculum = json.loads(CURRICULUM_PATH.read_text(encoding="utf-8"))
    write_nav(curriculum)
    CURRICULUM_PATH.write_text(json.dumps(curriculum, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = {row["view"]: row for row in workshop_rows(curriculum)}
    json_by_title: dict[str, list[Path]] = {}
    for path in (ROOT / "learning").rglob("*.definition.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        title = data.get("title")
        if title:
            json_by_title.setdefault(title, []).append(path)
    for view, row in rows.items():
        xml_path = VIEWS / f"{view}.xml"
        if not xml_path.is_file():
            print(f"skip missing {view}")
            continue
        text = xml_path.read_text(encoding="utf-8")
        if "<![CDATA[" not in text:
            print(f"skip non-studio {view}")
            continue
        definition = _load_xml_definition(text)
        title = definition.get("title")
        apply_guide(definition, row)
        xml_path.write_text(_store_xml_definition(text, definition), encoding="utf-8")
        for path in json_by_title.get(title, []):
            data = json.loads(path.read_text(encoding="utf-8"))
            apply_guide(data, row)
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"guided {view}")
    write_arena()
    write_path(workshop_rows(json.loads(CURRICULUM_PATH.read_text(encoding="utf-8"))))
    print("wrote nav, arena, and your path")


if __name__ == "__main__":
    main()
