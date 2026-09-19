"""LAB-AGENT-GOAL-INTEGRITY-001: untrusted instructions cannot redefine the task.

This package models security semantics only. It is not a planner, LLM,
LangGraph graph, or production prompt filter.
"""

from agentsec.goal.fixtures import (
    CLOSED_EXPANSION_ACTION,
    GOAL_AGENT_ID,
    GOAL_ATTACK_ID,
    PRINCIPAL_ID,
    TASK_ID,
)
from agentsec.goal.influence import ProposedTaskChange, parse_goal_request
from agentsec.goal.task import TaskContract, authoritative_task_contract
from agentsec.goal.trust import (
    GOAL_CONTROL_ID,
    GOAL_FAIL_OPEN_REASON,
    GoalDerivedOverlay,
)

__all__ = [
    "CLOSED_EXPANSION_ACTION",
    "GOAL_AGENT_ID",
    "GOAL_ATTACK_ID",
    "GOAL_CONTROL_ID",
    "GOAL_FAIL_OPEN_REASON",
    "GoalDerivedOverlay",
    "PRINCIPAL_ID",
    "ProposedTaskChange",
    "TASK_ID",
    "TaskContract",
    "authoritative_task_contract",
    "parse_goal_request",
]
