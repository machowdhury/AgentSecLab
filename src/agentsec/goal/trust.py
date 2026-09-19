"""CTRL-GOAL-INTEGRITY-001: untrusted instructions cannot redefine the task.

THIS CONTROL NEVER AUTHORIZES A TOOL.

OBSERVE records that an instruction was classified as data.
DENY rejects unauthorized task expansion. It is not tool_not_granted.
Overlay minting is a separate LAB vulnerable-profile path that selects
which task action to attempt; CTRL-MCP-001 still authorizes the tool.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.goal.fixtures import (
    CLOSED_EXPANSION_ACTION,
    INSTRUCTION_CANNOT_REDEFINE_REASON,
    INSTRUCTION_TRUST,
    UNAUTHORIZED_EXPANSION_REASON,
)
from agentsec.goal.influence import ProposedTaskChange
from agentsec.goal.task import TaskContract

GOAL_CONTROL_ID = "CTRL-GOAL-INTEGRITY-001"
GOAL_CONTROL_TYPE = "goal_integrity"
GOAL_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority"


@dataclass(frozen=True)
class GoalDerivedOverlay:
    """Per-request untrusted-instruction-derived task authority. Not a grant.

    INTENTIONALLY VULNERABLE LAB MACHINERY. Lives only inside one run.
    Closed to extract_full_policy. Does not mutate coded_policy() or TaskContract.
    """

    run_id: str
    accepted_action: str
    task_fingerprint: str
    proposed_fingerprint: str
    label: str = "untrusted-instruction-derived-task-authority"

    def __post_init__(self) -> None:
        if self.accepted_action != CLOSED_EXPANSION_ACTION:
            raise ValueError("goal overlay is not extensible")
        if self.label != "untrusted-instruction-derived-task-authority":
            raise ValueError("goal overlay must be labeled untrusted-instruction-derived-task-authority")


@dataclass(frozen=True)
class GoalTrustDecision:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    instruction_trust: str
    task: TaskContract | None
    change: ProposedTaskChange | None
    overlay_applied: bool
    error_stage: str | None = None

    @property
    def blocks_follow_on(self) -> bool:
        return self.decision == "ERROR"

    @property
    def proposed_action(self) -> str:
        if self.change is None:
            return "unparsed"
        return self.change.proposed_action


def evaluate_goal_integrity(
    *,
    task: TaskContract,
    change: ProposedTaskChange,
    profile: str,
) -> GoalTrustDecision:
    """Classify the proposed change against the frozen task. Never mint AllowTicket."""
    if not change.is_expansion:
        return GoalTrustDecision(
            control_id=GOAL_CONTROL_ID,
            control_type=GOAL_CONTROL_TYPE,
            decision="OBSERVE",
            reason=INSTRUCTION_CANNOT_REDEFINE_REASON,
            profile=profile,
            instruction_trust=INSTRUCTION_TRUST,
            task=task,
            change=change,
            overlay_applied=False,
            error_stage=None,
        )
    if profile == "vulnerable":
        return GoalTrustDecision(
            control_id=GOAL_CONTROL_ID,
            control_type=GOAL_CONTROL_TYPE,
            decision="OBSERVE",
            reason=GOAL_FAIL_OPEN_REASON,
            profile=profile,
            instruction_trust=INSTRUCTION_TRUST,
            task=task,
            change=change,
            overlay_applied=False,
            error_stage=None,
        )
    return GoalTrustDecision(
        control_id=GOAL_CONTROL_ID,
        control_type=GOAL_CONTROL_TYPE,
        decision="DENY",
        reason=UNAUTHORIZED_EXPANSION_REASON,
        profile=profile,
        instruction_trust=INSTRUCTION_TRUST,
        task=task,
        change=change,
        overlay_applied=False,
        error_stage=None,
    )


def evaluate_goal_integrity_safe(
    *,
    task: TaskContract,
    change: ProposedTaskChange | None,
    profile: str,
    parse_error: str | None = None,
    parse_stage: str | None = None,
) -> GoalTrustDecision:
    if parse_error:
        return GoalTrustDecision(
            control_id=GOAL_CONTROL_ID,
            control_type=GOAL_CONTROL_TYPE,
            decision="ERROR",
            reason=parse_error,
            profile=profile,
            instruction_trust=INSTRUCTION_TRUST,
            task=task,
            change=None,
            overlay_applied=False,
            error_stage=parse_stage or "schema_validation",
        )
    try:
        if change is None:
            raise ValueError("missing frozen proposed task change")
        return evaluate_goal_integrity(task=task, change=change, profile=profile)
    except Exception as exc:
        return GoalTrustDecision(
            control_id=GOAL_CONTROL_ID,
            control_type=GOAL_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            instruction_trust=INSTRUCTION_TRUST,
            task=task,
            change=None,
            overlay_applied=False,
            error_stage="control_evaluation",
        )


def mint_goal_overlay(
    *,
    task: TaskContract,
    change: ProposedTaskChange,
    run_id: str,
    profile: str,
) -> GoalDerivedOverlay | None:
    """LAB-only. Closed to extract_full_policy. Does not mutate coded policy. Does not persist."""
    if profile != "vulnerable":
        return None
    if change.proposed_action != CLOSED_EXPANSION_ACTION:
        return None
    return GoalDerivedOverlay(
        run_id=run_id,
        accepted_action=CLOSED_EXPANSION_ACTION,
        task_fingerprint=task.fingerprint,
        proposed_fingerprint=change.fingerprint,
    )


def effective_action(
    *,
    task: TaskContract,
    change: ProposedTaskChange,
    overlay: GoalDerivedOverlay | None,
    goal: GoalTrustDecision,
) -> str:
    """Which action the pipeline will attempt. Overlay cannot invent a new action id."""
    if overlay is not None:
        return overlay.accepted_action
    if goal.decision == "DENY":
        return task.permitted_action
    return change.proposed_action if task.permits(change.proposed_action) else task.permitted_action
