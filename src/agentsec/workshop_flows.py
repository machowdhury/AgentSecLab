"""Workshop flow diagrams and evidence-table presentation helpers.

Architecture only. Does not encode expected ALLOW/DENY answers.
Does not change SPL. Dashboard Studio table formatting uses documented
columnFormat + matchValue only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "splunk_app" / "agentsec" / "appserver" / "static"
FLOWS_DIR = STATIC / "flows"
LEARNING = ROOT / "learning" / "level_1"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"

NAVY = "#0B1F33"
TEAL = "#007F86"
PAGE = "#F6F8FB"
TEXT = "#17202A"
SECONDARY = "#3D4654"
BORDER = "#D9E0E7"
WHITE = "#FFFFFF"
INFO = "#3568A8"
WARNING = "#B7791F"
MUTED = "#8AA0B4"

# ALLOW stays informational. Do not treat it as success/green.
EVIDENCE_TABLE_CONTEXT = {
    "decisionBackgrounds": [
        {"match": "ALLOW", "value": "#E8EEF5"},
        {"match": "DENY", "value": "#F6EBD8"},
        {"match": "ERROR", "value": "#F8E6E6"},
        {"match": "OBSERVE", "value": "#F0F3F6"},
    ],
    "decisionText": [
        {"match": "ALLOW", "value": INFO},
        {"match": "DENY", "value": WARNING},
        {"match": "ERROR", "value": "#C62828"},
        {"match": "OBSERVE", "value": SECONDARY},
    ],
    "executedBackgrounds": [
        {"match": "true", "value": NAVY},
        {"match": "false", "value": "#EEF1F4"},
        {"match": "1", "value": NAVY},
        {"match": "0", "value": "#EEF1F4"},
    ],
    "executedText": [
        {"match": "true", "value": WHITE},
        {"match": "false", "value": SECONDARY},
        {"match": "1", "value": WHITE},
        {"match": "0", "value": SECONDARY},
    ],
}

EVIDENCE_TABLE_COLUMN_FORMAT = {
    "decision": {
        "rowBackgroundColors": '> table | seriesByName("decision") | matchValue(decisionBackgrounds)',
        "rowColors": '> table | seriesByName("decision") | matchValue(decisionText)',
    },
    "executed": {
        "rowBackgroundColors": '> table | seriesByName("executed") | matchValue(executedBackgrounds)',
        "rowColors": '> table | seriesByName("executed") | matchValue(executedText)',
    },
}

LAB_TO_VIEW = {
    "LAB-PI-001": "ws_lab_pi_001",
    "LAB-MCP-001": "ws_lab_mcp_001",
    "LAB-MCP-003": "ws_lab_mcp_003",
    "LAB-MCP-004": "ws_lab_mcp_004",
    "LAB-MCP-005": "ws_lab_mcp_005",
    "LAB-MCP-006": "ws_lab_mcp_006",
    "LAB-MCP-CATALOG": "ws_lab_mcp_catalog",
    "LAB-RAG-CONTEXT": "ws_lab_rag_context",
    "LAB-MEMORY-001": "ws_lab_memory_security",
    "LAB-SCANNER-RUNTIME-EVIDENCE": "ws_lab_scanner_runtime_evidence",
    "LAB-EXTERNAL-EVALUATION-GARAK": "ws_lab_external_evaluation_garak",
    "LAB-AGENT-GOAL-INTEGRITY-001": "ws_lab_agent_goal_integrity",
    "LAB-AGENT-DELEGATION-001": "ws_lab_agent_delegation",
    "LAB-AGENTSEC-CAPSTONE-001": "ws_lab_agentsec_capstone",
    "LAB-SPLUNK-DEFENDER-BRIDGE": "ws_lab_splunk_defender_bridge",
    "LAB-BLUE-TEAM-INCIDENT-001": "ws_lab_blue_team_incident",
    "LAB-DETECTION-ENGINEERING": "ws_lab_detection_engineering",
    "LAB-THREAT-MODELING-001": "ws_lab_threat_modeling",
    "LAB-AGENT-IDENTITY-NHI": "ws_lab_agent_identity_nhi",
    "LAB-A2A-AUTH-DELEGATION": "ws_lab_a2a_auth_delegation",
    "LAB-HITL-APPROVAL": "ws_lab_hitl_approval",
    "LAB-CREDENTIAL-LIFETIME": "ws_lab_credential_lifetime",
    "LAB-PRIVACY-DATA-GOVERNANCE-001": "ws_lab_privacy_data_governance",
    "LAB-RAG-PURPOSE": "ws_lab_purpose_authorization",
    "LAB-RECALL-ISOLATION": "ws_lab_recall_isolation",
    "LAB-ASSET-INVENTORY": "ws_lab_asset_inventory",
    "LAB-COMPONENT-PROVENANCE": "ws_lab_component_provenance",
    "LAB-CODE-AGENT-BOUNDS": "ws_lab_code_agent_bounds",
    "LAB-CHANGE-BOUNDS": "ws_lab_change_bounds",
    "LAB-MULTI-STAGE-INCIDENT-001": "ws_lab_multi_stage_incident",
    "LAB-ADVANCED-CAPSTONE-MASTERY-001": "ws_lab_advanced_capstone",
}

#: Where a learner arriving from the Attack Service should land, per lab.
#:
#: Studio opens a workshop on its first tab. For most labs that is correct: the
#: learner needs the mission before the evidence. LAB-MCP-001 is the exception
#: because its Attack Service workbench explicitly promises to open the guided
#: Investigation Notebook, and the learner arrives holding a fresh run.id with
#: nothing left to read. Landing them on MISSION made that promise false.
#:
#: Only list a lab here when its workbench actually makes that promise, and
#: only with a layoutId that exists in that lab's view. An unknown tab id is
#: ignored by Studio, which would silently restore the old behaviour.
LAB_TO_LANDING_TAB = {
    "LAB-MCP-001": "layout_investigate",
}

# kind: source | boundary | control | execution | telemetry | observe
FLOWS: list[dict] = [
    {
        "lab": "LAB-PI-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-INPUT-001",
        "execution": "Ollama / acmebank.llm_call",
        "telemetry": "Splunk investigation",
        "title": "Direct Prompt Injection flow",
        "desc": "Untrusted loan text meets CTRL-INPUT-001 at acmebank.http_api before Ollama. ALLOW is a decision, not execution.",
        "steps": [
            ("source", "SOURCE — untrusted input"),
            ("boundary", "TRUST BOUNDARY — acmebank.http_api"),
            ("observe", "INFLUENCE / REQUEST — loan string"),
            ("control", "CTRL-INPUT-001 — ALLOW / DENY decision"),
            ("execution", "EXECUTION — Ollama, only if ALLOW"),
            ("telemetry", "TELEMETRY — Splunk investigation"),
        ],
    },
    {
        "lab": "LAB-MCP-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "Tool handler",
        "telemetry": "Splunk (observe only)",
        "title": "Tool Authorization flow",
        "desc": "A tool request meets CTRL-MCP-001 before the handler. ALLOW is not execution.",
        "steps": [
            ("source", "USER / AGENT"),
            ("observe", "TOOL REQUEST — tool, scope, arguments"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY / ERROR"),
            ("execution", "HANDLER START — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk observes"),
        ],
        # Golden path: drawn left-to-right at 1440 x 200 so the labels are large
        # enough to read without zoom. Same five nodes, same order as "steps".
        "horizontal": [
            ("source", "USER / AGENT", "asks for a tool"),
            ("observe", "TOOL REQUEST", "tool · scope · arguments"),
            ("control", "CTRL-MCP-001", "ALLOW / DENY / ERROR"),
            ("execution", "HANDLER START", "only after ALLOW"),
            ("telemetry", "TELEMETRY", "Splunk observes"),
        ],
    },
    {
        "lab": "LAB-MCP-003",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "Tool handler",
        "telemetry": "Splunk",
        "title": "Scope Escalation flow",
        "desc": "Catalog and grant checks happen before a handler starts.",
        "steps": [
            ("source", "TOOL REQUEST"),
            ("observe", "Tool exists? Tool granted?"),
            ("observe", "Requested scope valid and granted?"),
            ("observe", "Arguments valid?"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "HANDLER — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-MCP-004",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001",
        "execution": "Tool handler",
        "telemetry": "Splunk",
        "title": "Parameter / Resource Authorization flow",
        "desc": "A granted tool still needs an authorized resource or parameter.",
        "steps": [
            ("source", "TOOL REQUEST plus resource argument"),
            ("boundary", "AUTHORIZATION BOUNDARY"),
            ("control", "CTRL-MCP-001 — parameter / resource check"),
            ("execution", "HANDLER — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-MCP-005",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "lookup_policy, then any follow-on handler",
        "telemetry": "Splunk",
        "title": "Tool Result Trust flow",
        "desc": "A tool result is data. A follow-on operation still requires authorization.",
        "steps": [
            ("observe", "REQUEST → CTRL-MCP-001 → lookup_policy"),
            ("execution", "FIRST EXECUTION — authorized tool"),
            ("boundary", "TOOL RESULT = DATA"),
            ("observe", "FOLLOW-ON INTENT"),
            ("control", "CTRL-MCP-001 — follow-on ALLOW / DENY"),
            ("execution", "FOLLOW-ON HANDLER — only after ALLOW"),
        ],
    },
    {
        "lab": "LAB-MCP-006",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-DELEGATION-001 then CTRL-MCP-001",
        "execution": "Tool handler",
        "telemetry": "Splunk",
        "title": "Confused Deputy flow",
        "desc": "Delegated authority and tool authorization are separate controls.",
        "steps": [
            ("source", "CALLER REQUEST"),
            ("control", "CTRL-DELEGATION-001 — delegated authority"),
            ("control", "CTRL-MCP-001 — tool authorization"),
            ("execution", "TOOL HANDLER — only after both ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-MCP-CATALOG",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "Handler only after ALLOW",
        "telemetry": "Splunk",
        "title": "Tool Catalog flow",
        "desc": "Catalog metadata may influence a request. It does not mint a grant.",
        "steps": [
            ("source", "MCP CATALOG / tool metadata"),
            ("observe", "AGENT MAY FORM A REQUEST"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "HANDLER — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-RAG-CONTEXT",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "Handler",
        "telemetry": "Splunk",
        "title": "RAG / Retrieved Context flow",
        "desc": "Retrieved content is data. It may influence a request. It cannot mint authority.",
        "steps": [
            ("source", "RETRIEVED CONTENT"),
            ("observe", "UNTRUSTED DATA"),
            ("observe", "MAY INFLUENCE A REQUEST"),
            ("control", "CTRL-MCP-001 — server authorization"),
            ("execution", "EXECUTION — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-MEMORY-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MEMORY-CONTEXT-001 then CTRL-MCP-001",
        "execution": "Handler",
        "telemetry": "Splunk",
        "title": "Persistent Memory flow",
        "desc": "Stored memory is later recalled. Recall is not a tool grant.",
        "steps": [
            ("observe", "WRITE RUN → MEMORY STORE"),
            ("observe", "LATER RECALL RUN"),
            ("control", "CTRL-MEMORY-CONTEXT-001 — OBSERVE"),
            ("observe", "FOLLOW-ON REQUEST"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "HANDLER — only after ALLOW"),
        ],
    },
    {
        "lab": "LAB-SCANNER-RUNTIME-EVIDENCE",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001 remains the runtime PDP",
        "execution": "Runtime handler, separate from scanner",
        "telemetry": "Splunk sourcetype agentsec:scanner:finding",
        "title": "Scanner plus runtime evidence flow",
        "desc": "A scanner finding is adjacent evidence. It is not a control decision.",
        "steps": [
            ("source", "INDEPENDENT SCANNER"),
            ("observe", "ADAPTER / ExternalEvidence finding"),
            ("telemetry", "HEC → Splunk scanner sourcetype"),
            ("control", "RUNTIME PDP remains CTRL-MCP-001"),
            ("execution", "HANDLER evidence is a separate plane"),
        ],
    },
    {
        "lab": "LAB-EXTERNAL-EVALUATION-GARAK",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001",
        "execution": "Runtime handler, separate from evaluation",
        "telemetry": "Splunk copy of evaluation and runtime",
        "title": "External Security Toolbox flow",
        "desc": "An evaluation result is not authorization. CTRL-MCP-001 remains the PDP.",
        "steps": [
            ("source", "EVALUATION / SCAN INPUT"),
            ("observe", "FINDING or EVALUATION RESULT"),
            ("telemetry", "SPLUNK COPY — not a PDP"),
            ("control", "CTRL-MCP-001 — tool authorization"),
            ("execution", "RUNTIME HANDLER — only after ALLOW"),
        ],
    },
    {
        "lab": "LAB-AGENT-GOAL-INTEGRITY-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-GOAL-INTEGRITY-001 then CTRL-MCP-001",
        "execution": "Operation-specific handler",
        "telemetry": "Splunk",
        "title": "Goal / Instruction Integrity flow",
        "desc": "An authorized tool is not an authorized goal.",
        "steps": [
            ("source", "SERVER-OWNED TASK"),
            ("observe", "UNTRUSTED INSTRUCTION / proposed goal"),
            ("control", "CTRL-GOAL-INTEGRITY-001 — goal decision"),
            ("control", "CTRL-MCP-001 — tool authorization"),
            ("execution", "OPERATION-SPECIFIC EXECUTION"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-AGENT-DELEGATION-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-IDENTITY-001 then CTRL-MCP-001",
        "execution": "Handler",
        "telemetry": "Splunk",
        "title": "Agent Identity / Delegation flow",
        "desc": "A delegation claim is data. CTRL-MCP-001 still authorizes the tool.",
        "steps": [
            ("source", "PRINCIPAL → CALLER → CALLEE"),
            ("observe", "DELEGATION CLAIM — data"),
            ("control", "CTRL-IDENTITY-001 — OBSERVE"),
            ("observe", "REQUESTED CAPABILITY"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "EXECUTION — only after ALLOW"),
        ],
    },
    {
        "lab": "LAB-AGENTSEC-CAPSTONE-001",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-RAG-CONTEXT-001, CTRL-MEMORY-CONTEXT-001, CTRL-MCP-001",
        "execution": "lookup_customer_tier handler",
        "telemetry": "Splunk",
        "title": "Lending Assistant Investigation flow",
        "desc": "Retrieve, persist, later recall, then a tool request. OBSERVE is not ALLOW.",
        "steps": [
            ("source", "RETRIEVED CONTENT"),
            ("observe", "WRITE then LATER RECALL"),
            ("control", "RAG / MEMORY controls — OBSERVE"),
            ("observe", "FOLLOW-ON REQUEST"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "HANDLER — only after ALLOW"),
            ("telemetry", "TELEMETRY — Splunk"),
        ],
    },
    {
        "lab": "LAB-SPLUNK-DEFENDER-BRIDGE",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001 in historical evidence",
        "execution": "Historical runtime copy",
        "telemetry": "Splunk Search",
        "title": "Splunk Defender Bridge flow",
        "desc": "Discover and correlate without a handed run.id. Splunk does not authorize.",
        "steps": [
            ("source", "INDEXED TELEMETRY"),
            ("observe", "DISCOVER / NARROW"),
            ("observe", "CORRELATE SEQUENCE"),
            ("observe", "COMPARE ATTACK / RETEST / BASELINE"),
            ("telemetry", "SPLUNK SEARCH — observe only"),
        ],
    },
    {
        "lab": "LAB-BLUE-TEAM-INCIDENT-001",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001 in historical evidence",
        "execution": "Historical runtime copy",
        "telemetry": "Splunk Search",
        "title": "Blue-team investigation flow",
        "desc": "Hypothesis, search, reconstruct, and challenge. Absence is not DENY.",
        "steps": [
            ("source", "INCOMPLETE EVIDENCE"),
            ("observe", "HYPOTHESIZE"),
            ("observe", "SEARCH / RECONSTRUCT"),
            ("observe", "CHALLENGE / CONCLUDE"),
            ("telemetry", "SPLUNK SEARCH — observe only"),
        ],
    },
    {
        "lab": "LAB-DETECTION-ENGINEERING",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001 in compared evidence",
        "execution": "Historical copies compared by predicate",
        "telemetry": "Splunk Search",
        "title": "Detection Engineering flow",
        "desc": "A candidate predicate is not a control. DET-MCP-001 stays disabled.",
        "steps": [
            ("observe", "SECURITY QUESTION"),
            ("observe", "CANDIDATE PREDICATE"),
            ("observe", "COMPARE ATTACK / RETEST / BASELINE"),
            ("observe", "STATE WHAT IT DOES NOT COVER"),
            ("telemetry", "SPLUNK SEARCH — not enforcement"),
        ],
    },
    {
        "lab": "LAB-THREAT-MODELING-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001 at TB-04",
        "execution": "Tool registry / fixture-backed records",
        "telemetry": "OTel → Splunk (TB-06)",
        "title": "Threat modeling architecture",
        "desc": "RAG and memory can influence a request. They do not mint authority.",
        "steps": [
            ("source", "HUMAN USER request / claimed id"),
            ("boundary", "ACMEBANK APP → AGENT / MODEL"),
            ("observe", "RAG and MEMORY may influence"),
            ("control", "MCP + CTRL-MCP-001 — authority"),
            ("execution", "TOOL REGISTRY / fixture records"),
            ("telemetry", "APP → OTEL → SPLUNK"),
        ],
    },
    {
        "lab": "LAB-AGENT-IDENTITY-NHI",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-IDENTITY-001 then CTRL-MCP-001",
        "execution": "Handler evidence",
        "telemetry": "Splunk",
        "title": "Agent Identity and Non-Human IAM flow",
        "desc": "A claimed name is not authentication. CTRL-MCP-001 remains the tool PDP.",
        "steps": [
            ("source", "CLAIMED NAME"),
            ("observe", "IDENTITY OBSERVATION"),
            ("control", "CTRL-IDENTITY-001 — not a grant"),
            ("control", "CTRL-MCP-001 — tool decision"),
            ("execution", "EXECUTION EVIDENCE"),
            ("telemetry", "SPLUNK — downstream"),
        ],
    },
    {
        "lab": "LAB-A2A-AUTH-DELEGATION",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-IDENTITY-001 then CTRL-MCP-001",
        "execution": "Handler evidence",
        "telemetry": "Splunk",
        "title": "A2A Authentication and Delegation flow",
        "desc": "A simulated authentication result is not tool authorization.",
        "steps": [
            ("source", "IDENTITY CLAIM"),
            ("observe", "SIMULATED AUTHENTICATION RESULT"),
            ("observe", "SIMULATED DELEGATION EVALUATION"),
            ("control", "CTRL-MCP-001 — tool decision"),
            ("execution", "EXECUTION EVIDENCE"),
            ("telemetry", "SPLUNK — downstream"),
        ],
    },
    {
        "lab": "LAB-HITL-APPROVAL",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001",
        "execution": "Submitted action evidence",
        "telemetry": "Splunk",
        "title": "Human Approval and Action Binding flow",
        "desc": "Approval is not authorization. A binding match is not an ALLOW.",
        "steps": [
            ("observe", "APPROVED ACTION"),
            ("observe", "SUBMITTED ACTION"),
            ("boundary", "BINDING COMPARE"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "EXECUTION EVIDENCE"),
            ("telemetry", "SPLUNK — downstream"),
        ],
    },
    {
        "lab": "LAB-CREDENTIAL-LIFETIME",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001",
        "execution": "Handler evidence",
        "telemetry": "Splunk",
        "title": "Short-Lived Credential Lifetime flow",
        "desc": "A current credential is not tool authorization. No secret is stored.",
        "steps": [
            ("source", "IDENTITY"),
            ("observe", "SYNTHETIC CREDENTIAL REFERENCE"),
            ("observe", "EXPIRY / CURRENT STATUS"),
            ("control", "CTRL-MCP-001 — tool decision"),
            ("execution", "EXECUTION EVIDENCE"),
            ("telemetry", "SPLUNK — downstream"),
        ],
    },
    {
        "lab": "LAB-PRIVACY-DATA-GOVERNANCE-001",
        "existing_ascii": True,
        "source_class": "CONVERTED FROM EXISTING ASCII/STRUCTURED CONTENT",
        "control": "CTRL-MCP-001",
        "execution": "Fixture tool",
        "telemetry": "Splunk copy",
        "title": "Privacy investigation data flow",
        "desc": "CTRL-MCP-001 authorizes the tool. It does not prove every argument is appropriate.",
        "steps": [
            ("source", "SYNTHETIC FIXTURE"),
            ("observe", "TOOL ARGUMENT"),
            ("control", "CTRL-MCP-001 — tool authorization"),
            ("execution", "FIXTURE TOOL"),
            ("telemetry", "TELEMETRY → SPLUNK COPY"),
        ],
    },
    {
        "lab": "LAB-RAG-PURPOSE",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "Purpose evaluation; retrieval does not invoke CTRL-MCP-001",
        "execution": "Retrieval is not tool execution",
        "telemetry": "Splunk observe",
        "title": "RAG Purpose Authorization flow",
        "desc": "A retrieved document is not authorized for every purpose. Similarity is not authorization.",
        "steps": [
            ("source", "RETRIEVED FIXTURE DOCUMENT"),
            ("observe", "PURPOSE EVALUATION"),
            ("boundary", "RETRIEVAL ≠ CTRL-MCP-001"),
            ("control", "TOOL PDP remains CTRL-MCP-001 if a tool is requested"),
            ("telemetry", "SPLUNK — observe only"),
        ],
    },
    {
        "lab": "LAB-RECALL-ISOLATION",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MEMORY-CONTEXT-001 then CTRL-MCP-001",
        "execution": "Recall is not a tool grant",
        "telemetry": "Splunk",
        "title": "Memory Ownership and Isolation flow",
        "desc": "Recall is not tool authorization. Deletion is NOT MEASURED.",
        "steps": [
            ("observe", "MEMORY WRITE"),
            ("observe", "LATER RECALL REQUEST"),
            ("boundary", "OWNERSHIP / ISOLATION"),
            ("control", "CTRL-MEMORY-CONTEXT-001"),
            ("control", "CTRL-MCP-001 if a tool is requested"),
            ("telemetry", "SPLUNK — observe only"),
        ],
    },
    {
        "lab": "LAB-ASSET-INVENTORY",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001 remains the tool PDP",
        "execution": "Inventory is not execution",
        "telemetry": "Documented component list",
        "title": "AI Asset Inventory flow",
        "desc": "A listed component is not trusted and not authorized.",
        "steps": [
            ("source", "COMPONENT LIST"),
            ("observe", "INVENTORY RECORD"),
            ("boundary", "LIST ≠ TRUST ≠ AUTHORIZATION"),
            ("control", "CTRL-MCP-001 remains the tool PDP"),
            ("telemetry", "DOCUMENTATION / SPLUNK as copies"),
        ],
    },
    {
        "lab": "LAB-COMPONENT-PROVENANCE",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001",
        "execution": "Identified component is not authorized",
        "telemetry": "Splunk / documented provenance",
        "title": "Component Provenance flow",
        "desc": "Known is not trusted. Scanned is not safe. Identified is not authorized.",
        "steps": [
            ("source", "IDENTIFIED COMPONENT"),
            ("observe", "KNOWN / SCANNED LABELS"),
            ("boundary", "PROVENANCE ≠ TRUST"),
            ("control", "CTRL-MCP-001 — tool decision"),
            ("telemetry", "SPLUNK / documented copy"),
        ],
    },
    {
        "lab": "LAB-CODE-AGENT-BOUNDS",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "Binding plus tool decision",
        "execution": "Simulated start is not an install",
        "telemetry": "Splunk / workshop ledger",
        "title": "Code Agent Bounds flow",
        "desc": "A read grant is not an install. No GitHub credential is used.",
        "steps": [
            ("source", "CLAIMED CODE AGENT"),
            ("observe", "DELEGATED / APPROVED read_repository"),
            ("observe", "SUBMITTED OPERATION"),
            ("boundary", "BINDING COMPARE"),
            ("control", "ALLOW / DENY decision"),
            ("execution", "SIMULATED START ≠ install / PR"),
        ],
    },
    {
        "lab": "LAB-CHANGE-BOUNDS",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "Binding plus tool decision",
        "execution": "A started action is not a completed change",
        "telemetry": "Splunk / workshop ledger",
        "title": "Change Bounds flow",
        "desc": "Inspect scope is not delete authority. No cloud credential is used.",
        "steps": [
            ("source", "SYNTHETIC OPS CREDENTIAL"),
            ("observe", "DELEGATED / APPROVED inspect_resource"),
            ("observe", "SUBMITTED OPERATION"),
            ("boundary", "BINDING COMPARE"),
            ("control", "ALLOW / DENY decision"),
            ("execution", "START ≠ completed change"),
        ],
    },
    {
        "lab": "LAB-MULTI-STAGE-INCIDENT-001",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "CTRL-MCP-001 in the packet",
        "execution": "Stage-specific handler evidence",
        "telemetry": "Splunk investigation",
        "title": "Multi-stage incident flow",
        "desc": "Influence, authorization, and execution stay separate across the packet.",
        "steps": [
            ("source", "INFLUENCE / UNTRUSTED INPUT"),
            ("observe", "REQUEST"),
            ("control", "CTRL-MCP-001 — ALLOW / DENY decision"),
            ("execution", "EXECUTION EVIDENCE"),
            ("telemetry", "TELEMETRY — Splunk investigation"),
        ],
    },
    {
        "lab": "LAB-ADVANCED-CAPSTONE-MASTERY-001",
        "existing_ascii": False,
        "source_class": "AUTHORED FROM EXISTING WORKSHOP PROSE",
        "control": "Named from evidence, not assumed",
        "execution": "Named from evidence, not assumed",
        "telemetry": "Splunk investigation",
        "title": "Advanced capstone investigation flow",
        "desc": "Start from an unfamiliar packet. Do not assume the control or the outcome.",
        "steps": [
            ("source", "UNFAMILIAR INCIDENT PACKET"),
            ("observe", "ARCHITECTURE / EVIDENCE"),
            ("control", "AUTHORIZATION — named from evidence"),
            ("execution", "EXECUTION — named from evidence"),
            ("telemetry", "SPLUNK INVESTIGATION"),
        ],
    },
]


def asset_name(lab: str) -> str:
    return f"flow-{lab.lower()}.svg"


def asset_url(lab: str) -> str:
    return f"/en-US/static/app/agentsec/flows/{asset_name(lab)}"


#: Wide layout for the golden-path lab. Same 1440 x 200 box the vertical image
#: occupies in Dashboard Studio, so the shared layout contract is unchanged.
HORIZONTAL_W = 1440
HORIZONTAL_H = 200


def _render_horizontal(flow: dict) -> str:
    """Left-to-right flow with the control drawn as a branch point.

    Grammar: the control is the only filled node; execution has a heavy teal
    border; DENY/ERROR ends the path at a stop bar, so the picture cannot be read
    as "everything proceeds to the handler". Splunk is last and drawn as a
    dashed observer: it receives copies of events and never sits on the decision
    path. Colour is never the only signal (words, borders, dashes and a stop bar
    carry meaning), and there is no green or red.
    """
    nodes = flow["horizontal"]
    count = len(nodes)
    margin = 30
    gap = 60
    box_w = (HORIZONTAL_W - 2 * margin - gap * (count - 1)) // count
    box_y, box_h = 22, 96
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {HORIZONTAL_W} {HORIZONTAL_H}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{_xml(flow["title"])}</title>',
        f'<desc id="desc">{_xml(flow["desc"])}</desc>',
        f'<rect width="{HORIZONTAL_W}" height="{HORIZONTAL_H}" fill="{PAGE}"/>',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        f'<path d="M0 0 L10 5 L0 10 z" fill="{TEXT}"/></marker></defs>',
        '<g font-family="system-ui, Segoe UI, sans-serif" fill="#17202A">',
    ]
    control_cx = None
    for index, (kind, title, sub) in enumerate(nodes):
        x = margin + index * (box_w + gap)
        fill, stroke, dash, text_fill = _kind_style(kind)
        stroke_w = 4 if kind == "execution" else 2
        dash_attr = ' stroke-dasharray="6 4"' if dash or kind == "telemetry" else ""
        parts.append(
            f'<rect x="{x}" y="{box_y}" width="{box_w}" height="{box_h}" rx="6" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{stroke_w}"{dash_attr}/>'
        )
        cx = x + box_w // 2
        parts.append(
            f'<text x="{cx}" y="{box_y + 42}" text-anchor="middle" font-size="19" font-weight="700" fill="{text_fill}">{_xml(title)}</text>'
        )
        parts.append(
            f'<text x="{cx}" y="{box_y + 70}" text-anchor="middle" font-size="16" fill="{text_fill}">{_xml(sub)}</text>'
        )
        if kind == "control":
            control_cx = cx
        if index < count - 1:
            ax1, ax2 = x + box_w + 4, x + box_w + gap - 4
            ay = box_y + box_h // 2
            nxt_dashed = nodes[index + 1][0] == "telemetry"
            dash_line = ' stroke-dasharray="6 5"' if nxt_dashed else ""
            parts.append(
                f'<line x1="{ax1}" y1="{ay}" x2="{ax2}" y2="{ay}" stroke="{TEXT}" stroke-width="3"{dash_line} marker-end="url(#arrow)"/>'
            )
    if control_cx is not None:
        # DENY / ERROR branch: leaves the control and ends at a stop bar. No arrow
        # reaches the handler from here.
        stub_top = box_y + box_h
        parts.append(f'<line x1="{control_cx}" y1="{stub_top}" x2="{control_cx}" y2="156" stroke="{TEXT}" stroke-width="3" stroke-dasharray="6 5"/>')
        parts.append(f'<line x1="{control_cx - 34}" y1="160" x2="{control_cx + 34}" y2="160" stroke="{TEXT}" stroke-width="6"/>')
        parts.append(
            f'<text x="{control_cx + 46}" y="167" font-size="16" font-weight="700" fill="{TEXT}">DENY / ERROR: the path ends here, no handler starts</text>'
        )
    parts.append("</g></svg>\n")
    return "\n".join(parts)


def render_flow_svg(flow: dict) -> str:
    if flow.get("horizontal"):
        return _render_horizontal(flow)
    steps = flow["steps"]
    width = 880
    top = 28
    box_h = 48
    gap = 20
    height = top + len(steps) * (box_h + gap) + 16
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{_xml(flow["title"])}</title>',
        f'<desc id="desc">{_xml(flow["desc"])}</desc>',
        f'<rect width="{width}" height="{height}" fill="{PAGE}"/>',
        '<g font-family="system-ui, Segoe UI, sans-serif" font-size="15" fill="#17202A">',
    ]
    cx = width // 2
    box_w = 640
    x = (width - box_w) // 2
    y = top
    for index, (kind, label) in enumerate(steps):
        fill, stroke, dash, text_fill = _kind_style(kind)
        dash_attr = f' stroke-dasharray="4 3"' if dash else ""
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="4" fill="{fill}" stroke="{stroke}"{dash_attr}/>'
        )
        parts.append(
            f'<text x="{cx}" y="{y + 30}" text-anchor="middle" fill="{text_fill}">{_xml(label)}</text>'
        )
        if index < len(steps) - 1:
            ny = y + box_h
            parts.append(
                f'<path d="M{cx} {ny} V{ny + gap}" stroke="{MUTED}" stroke-width="2" fill="none"/>'
            )
        y += box_h + gap
    parts.append("</g></svg>\n")
    return "\n".join(parts)


def _kind_style(kind: str) -> tuple[str, str, bool, str]:
    if kind == "control":
        return NAVY, NAVY, False, WHITE
    if kind == "boundary":
        return WHITE, TEAL, False, TEXT
    if kind == "execution":
        return WHITE, TEAL, False, TEXT
    if kind == "telemetry":
        return WHITE, BORDER, False, TEXT
    if kind == "observe":
        return WHITE, MUTED, True, TEXT
    return WHITE, BORDER, False, TEXT


def _xml(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_svgs() -> list[Path]:
    FLOWS_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for flow in FLOWS:
        path = FLOWS_DIR / asset_name(flow["lab"])
        path.write_text(render_flow_svg(flow), encoding="utf-8")
        written.append(path)
    return written


def apply_table_format(viz: dict) -> bool:
    if viz.get("type") != "splunk.table":
        return False
    options = viz.setdefault("options", {})
    column_format = options.setdefault("columnFormat", {})
    changed = False
    for field, rules in EVIDENCE_TABLE_COLUMN_FORMAT.items():
        if column_format.get(field) != rules:
            column_format[field] = rules
            changed = True
    context = viz.setdefault("context", {})
    for key, value in EVIDENCE_TABLE_CONTEXT.items():
        if context.get(key) != value:
            context[key] = value
            changed = True
    return changed


def _insert_flow_viz(definition: dict, flow: dict) -> None:
    viz_id = "viz_flow_diagram"
    definition.setdefault("visualizations", {})[viz_id] = {
        "type": "splunk.image",
        "title": "Architecture flow",
        "description": flow["desc"],
        "options": {
            "src": asset_url(flow["lab"]),
            "preserveAspectRatio": True,
        },
    }
    layout = definition.setdefault("layout", {})
    tabs = (layout.get("tabs") or {}).get("items") or []
    first = tabs[0]["layoutId"] if tabs else next(iter(layout.get("layoutDefinitions") or {}))
    canvas = layout.setdefault("layoutDefinitions", {}).setdefault(first, {})
    structure = canvas.setdefault("structure", [])
    if any(item.get("item") == viz_id for item in structure):
        return
    shift = 208
    for item in structure:
        pos = item.setdefault("position", {})
        pos["y"] = int(pos.get("y") or 0) + shift
    structure.insert(
        0,
        {"item": viz_id, "type": "block", "position": {"x": 0, "y": 0, "w": 1440, "h": 200}},
    )
    options = canvas.setdefault("options", {})
    options["height"] = int(options.get("height") or 800) + shift


def _write_view_xml(view_name: str, definition: dict) -> None:
    path = VIEWS / f"{view_name}.xml"
    text = path.read_text(encoding="utf-8")
    label_match = re.search(r"<label>(.*?)</label>", text)
    desc_match = re.search(r"<description>(.*?)</description>", text)
    label = label_match.group(1) if label_match else definition.get("title", view_name)
    description = desc_match.group(1) if desc_match else definition.get("description", "")
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        f"  <label>{label}</label>\n"
        f"  <description>{description}</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n",
        encoding="utf-8",
    )


def apply_dashboards() -> dict:
    tables_changed = 0
    views_updated = 0
    for flow in FLOWS:
        lab = flow["lab"]
        json_path = LEARNING / lab / "dashboard.definition.json"
        definition = json.loads(json_path.read_text(encoding="utf-8"))
        for viz_id, viz in definition.get("visualizations", {}).items():
            if viz_id in {"viz_guide_events", "viz_guide_summary"}:
                if apply_table_format(viz):
                    tables_changed += 1
        _insert_flow_viz(definition, flow)
        json_path.write_text(json.dumps(definition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _write_view_xml(LAB_TO_VIEW[lab], definition)
        views_updated += 1
    return {"tables_changed": tables_changed, "views_updated": views_updated}


def inventory() -> list[dict]:
    return [
        {
            "lab": flow["lab"],
            "existing_ascii": "YES" if flow["existing_ascii"] else "NO",
            "source": flow["source_class"],
            "diagram": "YES",
            "control": flow["control"],
            "execution": flow["execution"],
            "telemetry": flow["telemetry"],
            "asset": f"splunk_app/agentsec/appserver/static/flows/{asset_name(flow['lab'])}",
            "view": LAB_TO_VIEW[flow["lab"]],
        }
        for flow in FLOWS
    ]


if __name__ == "__main__":
    write_svgs()
    print(apply_dashboards())
