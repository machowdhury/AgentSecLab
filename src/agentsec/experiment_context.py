"""Server-owned experiment context. Not constructed from arbitrary browser JSON.

Browser selection (lab_id + mode) is metadata that picks a predefined specimen.
It is not authorization, grants, or coded policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from agentsec.attacks import ATK_001, ATK_002
from agentsec.events import content_hash
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.rag.fixtures import (
    DOCUMENT_ID_MALICIOUS,
    DOCUMENT_ID_NORMAL,
    MALICIOUS_DOCUMENT,
    NORMAL_DOCUMENT,
    RAG_ATTACK_ID,
)
from agentsec.memory.fixtures import (
    MALICIOUS_MEMORY,
    MEMORY_ATTACK_ID,
    MEMORY_ID_CAPSTONE_MALICIOUS,
    MEMORY_ID_CAPSTONE_NORMAL,
    MEMORY_ID_MALICIOUS,
    MEMORY_ID_NORMAL,
    NORMAL_MEMORY,
)
from agentsec.goal.fixtures import (
    GOAL_ATTACK_ID,
    INSTRUCTION_ID_MALICIOUS,
    INSTRUCTION_ID_NORMAL,
    MALICIOUS_NOTE,
    NORMAL_NOTE,
)
from agentsec.identity.fixtures import (
    CLAIM_ID_MALICIOUS,
    CLAIM_ID_NORMAL,
    IDENTITY_ATTACK_ID,
    adversarial_a2a_payload,
    baseline_a2a_payload,
    claim_payload_for,
)

LAB_PI = "LAB-PI-001"
LAB_MCP = "LAB-MCP-001"
LAB_RAG = "LAB-RAG-CONTEXT"
LAB_MEMORY = "LAB-MEMORY-001"
LAB_GOAL = "LAB-AGENT-GOAL-INTEGRITY-001"
LAB_IDENTITY = "LAB-AGENT-DELEGATION-001"
LAB_CAPSTONE = "LAB-AGENTSEC-CAPSTONE-001"
ROUTE_PROCESS = "process"
ROUTE_MCP = "mcp_invoke"
ROUTE_RAG = "rag_retrieve"
ROUTE_MEMORY = "memory_lifecycle"
ROUTE_GOAL = "goal_evaluate"
ROUTE_IDENTITY = "identity_delegate"
ROUTE_CAPSTONE = "capstone_lifecycle"
CAPSTONE_ATTACK_ID = "CAPSTONE-001"


def identity_canonical_bytes(payload: dict) -> str:
    """Same JSON A2ADelegationRequest.fingerprint hashes. Do not invent a new hash."""
    from agentsec.identity.request import parse_a2a_delegation_request

    parsed = parse_a2a_delegation_request(payload)
    if not parsed.ok or parsed.request is None:
        raise ValueError(parsed.error_reason)
    return json.dumps(parsed.request.canonical_dict(), sort_keys=True, separators=(",", ":"))


def mcp_canonical_payload(tool: str, arguments: dict, requested_scope: str) -> str:
    """Same JSON the MCP control event hashes. Sort keys; do not pretty-print."""
    return json.dumps(
        {"arguments": arguments, "requested_scope": requested_scope, "tool": tool},
        sort_keys=True,
    )


@dataclass(frozen=True)
class ExperimentDefinition:
    experiment_id: str
    lab_id: str
    specimen_id: str
    mode: str
    profile: str
    payload: str
    user_id: str
    attack_id: str
    intentionally_vulnerable: bool
    live_supported: bool = True
    runtime_route: str = ROUTE_PROCESS
    tool: str = ""
    requested_scope: str = ""
    arguments_json: str = "{}"
    document_id: str = ""
    memory_id: str = ""
    instruction_id: str = ""
    claim_id: str = ""
    not_authorization: bool = True


@dataclass(frozen=True)
class ExperimentContext:
    experiment_id: str
    lab_id: str
    specimen_id: str
    mode: str
    profile: str
    payload: str
    user_id: str
    attack_id: str
    input_fingerprint: str
    intentionally_vulnerable: bool
    runtime_route: str = ROUTE_PROCESS
    tool: str = ""
    requested_scope: str = ""
    arguments_json: str = "{}"
    document_id: str = ""
    memory_id: str = ""
    instruction_id: str = ""
    claim_id: str = ""
    not_authorization: bool = True

    @classmethod
    def from_definition(cls, definition: ExperimentDefinition) -> "ExperimentContext":
        return cls(
            experiment_id=definition.experiment_id,
            lab_id=definition.lab_id,
            specimen_id=definition.specimen_id,
            mode=definition.mode,
            profile=definition.profile,
            payload=definition.payload,
            user_id=definition.user_id,
            attack_id=definition.attack_id,
            input_fingerprint=content_hash(definition.payload),
            intentionally_vulnerable=definition.intentionally_vulnerable,
            runtime_route=definition.runtime_route,
            tool=definition.tool,
            requested_scope=definition.requested_scope,
            arguments_json=definition.arguments_json,
            document_id=definition.document_id,
            memory_id=definition.memory_id,
            instruction_id=definition.instruction_id,
            claim_id=definition.claim_id,
            not_authorization=True,
        )


def _pi(
    *,
    mode: str,
    specimen: object,
    profile: str,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_PI}:{mode}",
        lab_id=LAB_PI,
        specimen_id=specimen.attack_id,
        mode=mode,
        profile=profile,
        payload=specimen.payload,
        user_id=user_id,
        attack_id=specimen.attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_PROCESS,
    )


def _mcp(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    tool: str,
    requested_scope: str,
    arguments: dict,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    payload = mcp_canonical_payload(tool, arguments, requested_scope)
    return ExperimentDefinition(
        experiment_id=f"{LAB_MCP}:{mode}",
        lab_id=LAB_MCP,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=payload,
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_MCP,
        tool=tool,
        requested_scope=requested_scope,
        arguments_json=json.dumps(arguments, sort_keys=True),
    )


def _rag(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    document_id: str,
    document_bytes: str,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_RAG}:{mode}",
        lab_id=LAB_RAG,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=document_bytes,
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_RAG,
        document_id=document_id,
    )


def _memory(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    memory_id: str,
    memory_bytes: str,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_MEMORY}:{mode}",
        lab_id=LAB_MEMORY,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=memory_bytes,
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_MEMORY,
        memory_id=memory_id,
    )


def _capstone(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    document_id: str,
    document_bytes: str,
    memory_id: str,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_CAPSTONE}:{mode}",
        lab_id=LAB_CAPSTONE,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=document_bytes,
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_CAPSTONE,
        document_id=document_id,
        memory_id=memory_id,
    )


def _goal(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    instruction_id: str,
    instruction_bytes: str,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_GOAL}:{mode}",
        lab_id=LAB_GOAL,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=instruction_bytes,
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_GOAL,
        instruction_id=instruction_id,
    )


def _identity(
    *,
    mode: str,
    specimen_id: str,
    attack_id: str,
    profile: str,
    claim_id: str,
    payload: dict,
    user_id: str,
    intentionally_vulnerable: bool = False,
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id=f"{LAB_IDENTITY}:{mode}",
        lab_id=LAB_IDENTITY,
        specimen_id=specimen_id,
        mode=mode,
        profile=profile,
        payload=identity_canonical_bytes(payload),
        user_id=user_id,
        attack_id=attack_id,
        intentionally_vulnerable=intentionally_vulnerable,
        runtime_route=ROUTE_IDENTITY,
        claim_id=claim_id,
    )


EXPERIMENT_DEFINITIONS: tuple[ExperimentDefinition, ...] = (
    _pi(mode="BASELINE", specimen=ATK_001, profile="defended", user_id="applicant-web"),
    _pi(
        mode="ATTACK",
        specimen=ATK_002,
        profile="vulnerable",
        user_id="attacker-lab",
        intentionally_vulnerable=True,
    ),
    _pi(mode="RETEST", specimen=ATK_002, profile="defended", user_id="attacker-lab"),
    _mcp(
        mode="BASELINE",
        specimen_id="MCP-001",
        attack_id="MCP-001",
        profile="defended",
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments=dict(MCP_LOOKUP_POLICY_ARGS),
        user_id="applicant-web",
    ),
    _mcp(
        mode="ATTACK",
        specimen_id="MCP-002",
        attack_id="MCP-002",
        profile="vulnerable",
        tool="lookup_customer_tier",
        requested_scope=MCP_CUSTOMER_SCOPE,
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _mcp(
        mode="RETEST",
        specimen_id="MCP-002",
        attack_id="MCP-002",
        profile="defended",
        tool="lookup_customer_tier",
        requested_scope=MCP_CUSTOMER_SCOPE,
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        user_id="applicant-web",
    ),
    _rag(
        mode="BASELINE",
        specimen_id="RAG-BASELINE",
        attack_id="RAG-BASELINE",
        profile="defended",
        document_id=DOCUMENT_ID_NORMAL,
        document_bytes=NORMAL_DOCUMENT,
        user_id="applicant-web",
    ),
    _rag(
        mode="ATTACK",
        specimen_id=RAG_ATTACK_ID,
        attack_id=RAG_ATTACK_ID,
        profile="vulnerable",
        document_id=DOCUMENT_ID_MALICIOUS,
        document_bytes=MALICIOUS_DOCUMENT,
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _rag(
        mode="RETEST",
        specimen_id=RAG_ATTACK_ID,
        attack_id=RAG_ATTACK_ID,
        profile="defended",
        document_id=DOCUMENT_ID_MALICIOUS,
        document_bytes=MALICIOUS_DOCUMENT,
        user_id="applicant-web",
    ),
    _memory(
        mode="BASELINE",
        specimen_id="MEMORY-BASELINE",
        attack_id="MEMORY-BASELINE",
        profile="defended",
        memory_id=MEMORY_ID_NORMAL,
        memory_bytes=NORMAL_MEMORY,
        user_id="applicant-web",
    ),
    _memory(
        mode="ATTACK",
        specimen_id=MEMORY_ATTACK_ID,
        attack_id=MEMORY_ATTACK_ID,
        profile="vulnerable",
        memory_id=MEMORY_ID_MALICIOUS,
        memory_bytes=MALICIOUS_MEMORY,
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _memory(
        mode="RETEST",
        specimen_id=MEMORY_ATTACK_ID,
        attack_id=MEMORY_ATTACK_ID,
        profile="defended",
        memory_id=MEMORY_ID_MALICIOUS,
        memory_bytes=MALICIOUS_MEMORY,
        user_id="applicant-web",
    ),
    _goal(
        mode="BASELINE",
        specimen_id="GOAL-BASELINE",
        attack_id="GOAL-BASELINE",
        profile="defended",
        instruction_id=INSTRUCTION_ID_NORMAL,
        instruction_bytes=NORMAL_NOTE,
        user_id="applicant-web",
    ),
    _goal(
        mode="ATTACK",
        specimen_id=GOAL_ATTACK_ID,
        attack_id=GOAL_ATTACK_ID,
        profile="vulnerable",
        instruction_id=INSTRUCTION_ID_MALICIOUS,
        instruction_bytes=MALICIOUS_NOTE,
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _goal(
        mode="RETEST",
        specimen_id=GOAL_ATTACK_ID,
        attack_id=GOAL_ATTACK_ID,
        profile="defended",
        instruction_id=INSTRUCTION_ID_MALICIOUS,
        instruction_bytes=MALICIOUS_NOTE,
        user_id="applicant-web",
    ),
    _identity(
        mode="BASELINE",
        specimen_id="A2A-BASELINE",
        attack_id="A2A-BASELINE",
        profile="defended",
        claim_id=CLAIM_ID_NORMAL,
        payload=baseline_a2a_payload(),
        user_id="applicant-web",
    ),
    _identity(
        mode="ATTACK",
        specimen_id=IDENTITY_ATTACK_ID,
        attack_id=IDENTITY_ATTACK_ID,
        profile="vulnerable",
        claim_id=CLAIM_ID_MALICIOUS,
        payload=adversarial_a2a_payload(),
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _identity(
        mode="RETEST",
        specimen_id=IDENTITY_ATTACK_ID,
        attack_id=IDENTITY_ATTACK_ID,
        profile="defended",
        claim_id=CLAIM_ID_MALICIOUS,
        payload=adversarial_a2a_payload(),
        user_id="applicant-web",
    ),
    _capstone(
        mode="BASELINE",
        specimen_id="CAPSTONE-BASELINE",
        attack_id="CAPSTONE-BASELINE",
        profile="defended",
        document_id=DOCUMENT_ID_NORMAL,
        document_bytes=NORMAL_DOCUMENT,
        memory_id=MEMORY_ID_CAPSTONE_NORMAL,
        user_id="applicant-web",
    ),
    _capstone(
        mode="ATTACK",
        specimen_id=CAPSTONE_ATTACK_ID,
        attack_id=RAG_ATTACK_ID,
        profile="vulnerable",
        document_id=DOCUMENT_ID_MALICIOUS,
        document_bytes=MALICIOUS_DOCUMENT,
        memory_id=MEMORY_ID_CAPSTONE_MALICIOUS,
        user_id="applicant-web",
        intentionally_vulnerable=True,
    ),
    _capstone(
        mode="RETEST",
        specimen_id=CAPSTONE_ATTACK_ID,
        attack_id=RAG_ATTACK_ID,
        profile="defended",
        document_id=DOCUMENT_ID_MALICIOUS,
        document_bytes=MALICIOUS_DOCUMENT,
        memory_id=MEMORY_ID_CAPSTONE_MALICIOUS,
        user_id="applicant-web",
    ),
)

_BY_ID = {row.experiment_id: row for row in EXPERIMENT_DEFINITIONS}
_BY_LAUNCH = {(row.lab_id, row.specimen_id, row.mode): row for row in EXPERIMENT_DEFINITIONS}


def lookup_experiment(experiment_id: str) -> ExperimentDefinition | None:
    return _BY_ID.get(experiment_id)


def lookup_experiment_for_launch(
    *,
    lab_id: str,
    specimen_id: str,
    mode: str,
) -> ExperimentDefinition | None:
    return _BY_LAUNCH.get((lab_id, specimen_id, mode))


def attack_retest_fingerprint_pair(lab_id: str = LAB_PI) -> tuple[str, str]:
    attack = ExperimentContext.from_definition(_BY_ID[f"{lab_id}:ATTACK"])
    retest = ExperimentContext.from_definition(_BY_ID[f"{lab_id}:RETEST"])
    return attack.input_fingerprint, retest.input_fingerprint


def bind_experiment_for_process(
    *,
    experiment_id: str | None,
    input_text: str,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id to server-owned context.

    Missing experiment_id keeps the AcmeBank UI auto-mode path.
    Unknown or mismatched ids are ERROR — never a silent vulnerable fallback.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route != ROUTE_PROCESS:
        return None, "unknown_experiment"
    if input_text != definition.payload:
        return None, "experiment_payload_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def bind_experiment_for_mcp(
    *,
    experiment_id: str | None,
    tool: str,
    requested_scope: str,
    arguments: dict,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id onto the MCP invoke path.

    Missing experiment_id keeps the existing /mcp/invoke auto-mode path.
    Tool/scope/arguments must match the predefined specimen. The browser
    never supplies grants or profile.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route != ROUTE_MCP:
        return None, "unknown_experiment"
    if tool != definition.tool:
        return None, "experiment_tool_mismatch"
    if requested_scope != definition.requested_scope:
        return None, "experiment_scope_mismatch"
    expected_args = json.loads(definition.arguments_json)
    if arguments != expected_args:
        return None, "experiment_arguments_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def bind_experiment_for_rag(
    *,
    experiment_id: str | None,
    document_id: str,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id onto POST /rag/retrieve.

    Missing experiment_id keeps the existing auto-mode path (process env profile).
    Document id must match the predefined specimen. The browser never supplies
    grants, profile, document body, or trust labels.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route not in (ROUTE_RAG, ROUTE_CAPSTONE):
        return None, "unknown_experiment"
    if document_id != definition.document_id:
        return None, "experiment_document_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def bind_experiment_for_memory(
    *,
    experiment_id: str | None,
    memory_id: str,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id onto POST /memory/write and /memory/recall.

    Missing experiment_id keeps the existing auto-mode path (process env profile).
    Memory id must match the predefined specimen. The browser never supplies
    grants, profile, memory body, or trust labels. Overlay is recall-only.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route not in (ROUTE_MEMORY, ROUTE_CAPSTONE):
        return None, "unknown_experiment"
    if memory_id != definition.memory_id:
        return None, "experiment_memory_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def bind_experiment_for_goal(
    *,
    experiment_id: str | None,
    instruction_id: str,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id onto POST /goal/evaluate.

    Missing experiment_id keeps the existing auto-mode path (process env profile).
    Instruction id must match the predefined specimen. The browser never supplies
    grants, profile, instruction body, task contract, or goal decision.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route != ROUTE_GOAL:
        return None, "unknown_experiment"
    if instruction_id != definition.instruction_id:
        return None, "experiment_instruction_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def bind_experiment_for_identity(
    *,
    experiment_id: str | None,
    claim_id: str,
    user_id: str,
) -> tuple[ExperimentContext | None, str]:
    """Map a closed experiment_id onto POST /identity/delegate.

    Missing experiment_id keeps the auto-mode path (process env profile).
    Claim id must match the predefined specimen. The browser never supplies
    grants, profile, the A2A body, identity_verified, or authenticated.
    """
    if experiment_id is None:
        return None, ""
    definition = lookup_experiment(experiment_id)
    if definition is None or definition.runtime_route != ROUTE_IDENTITY:
        return None, "unknown_experiment"
    if claim_id != definition.claim_id:
        return None, "experiment_claim_mismatch"
    if user_id != definition.user_id:
        return None, "experiment_user_mismatch"
    return ExperimentContext.from_definition(definition), ""


def settings_for_experiment(base, ctx: ExperimentContext):
    """Per-request Settings copy. Does not mutate process environment."""
    from dataclasses import replace

    return replace(base, security_profile=ctx.profile, testbed_mode_override=None)
