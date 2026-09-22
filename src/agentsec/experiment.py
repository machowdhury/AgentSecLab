"""Server-owned experiment dimensions. Attacker JSON cannot set these values."""

from __future__ import annotations

from agentsec.attacks import ATK_002_PAYLOAD
from agentsec.settings import Settings, VALID_TESTBED_MODES

EXECUTION_MODE = "LIVE"
TELEMETRY_FIDELITY = "OBSERVED"
SCHEMA_NAME = "agentsec.security_event"
SCHEMA_VERSION = "1.9.0"
LOAN_WORKFLOW_ENTRY = "/process"
LOAN_WORKFLOW_NAME = "loan_pipeline"
MCP_WORKFLOW_ENTRY = "/mcp/invoke"
MCP_WORKFLOW_NAME = "mcp_tool_lab"
RAG_WORKFLOW_ENTRY = "/rag/retrieve"
RAG_WORKFLOW_NAME = "rag_context_lab"
MEMORY_WRITE_ENTRY = "/memory/write"
MEMORY_RECALL_ENTRY = "/memory/recall"
MEMORY_WORKFLOW_NAME = "memory_lab"
IDENTITY_WORKFLOW_ENTRY = "/identity/delegate"
IDENTITY_WORKFLOW_NAME = "identity_delegation_lab"
GOAL_WORKFLOW_ENTRY = "/goal/evaluate"
GOAL_WORKFLOW_NAME = "goal_integrity_lab"
WORKFLOW_ENTRY = LOAN_WORKFLOW_ENTRY
WORKFLOW_NAME = LOAN_WORKFLOW_NAME


def resolve_attack_id(input_text: str) -> str:
    if isinstance(input_text, str) and input_text.strip() == ATK_002_PAYLOAD.strip():
        return "ATK-002"
    return "ATK-001"


def resolve_testbed_mode(*, input_text: str, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    if resolve_attack_id(input_text) == "ATK-002":
        return "ATTACK"
    return "BASELINE"


def technique_id_for(attack_id: str) -> str | None:
    if attack_id == "ATK-002":
        return "AML.T0054"
    if attack_id == "MCP-002":
        return "AML.T0050"
    if attack_id == "MCP-003":
        return "AML.T0050"
    if attack_id == "MCP-004":
        return "AML.T0050"
    return None


def resolve_mcp_attack_id(
    tool: str | None,
    requested_scope: str | None = None,
    policy_id: str | None = None,
    testbed_mode: str | None = None,
) -> str:
    if tool == "lookup_policy":
        if requested_scope and requested_scope != "policy:read":
            return "MCP-003"
        if policy_id and policy_id != "lending-basics":
            return "MCP-004"
        if testbed_mode in ("ATTACK", "RETEST"):
            return "MCP-005"
        return "MCP-001"
    return "MCP-002"


def resolve_mcp_testbed_mode(
    *,
    tool: str | None,
    settings: Settings,
    requested_scope: str | None = None,
    policy_id: str | None = None,
) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    if tool == "lookup_policy" and (not requested_scope or requested_scope == "policy:read"):
        if policy_id and policy_id != "lending-basics":
            return "ATTACK"
        return "BASELINE"
    return "ATTACK"


def resolve_rag_testbed_mode(*, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    return "BASELINE"


def resolve_memory_testbed_mode(*, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    return "BASELINE"


def resolve_goal_testbed_mode(*, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    return "BASELINE"


def resolve_identity_testbed_mode(*, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    return "BASELINE"
