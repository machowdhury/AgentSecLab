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

LAB_PI = "LAB-PI-001"
LAB_MCP = "LAB-MCP-001"
ROUTE_PROCESS = "process"
ROUTE_MCP = "mcp_invoke"


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


def settings_for_experiment(base, ctx: ExperimentContext):
    """Per-request Settings copy. Does not mutate process environment."""
    from dataclasses import replace

    return replace(base, security_profile=ctx.profile, testbed_mode_override=None)
