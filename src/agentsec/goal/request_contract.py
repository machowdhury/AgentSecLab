"""Closed HTTP contract for POST /goal/evaluate. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.goal.fixtures import AUTHORITY_LIKE_FIELDS

ALLOWED_GOAL_EVALUATE_FIELDS = frozenset({"instruction_id", "user_id", "experiment_id"})


@dataclass(frozen=True)
class ParsedGoalEvaluateRequest:
    ok: bool
    instruction_id: str | None
    user_id: str
    experiment_id: str | None
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_goal_evaluate_body(data: object) -> ParsedGoalEvaluateRequest:
    if not isinstance(data, dict):
        return ParsedGoalEvaluateRequest(
            ok=False,
            instruction_id=None,
            user_id="unknown",
            experiment_id=None,
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(
        sorted(
            str(key)
            for key in data.keys()
            if key not in ALLOWED_GOAL_EVALUATE_FIELDS or key in AUTHORITY_LIKE_FIELDS
        )
    )
    unknown = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_GOAL_EVALUATE_FIELDS))
    extra = tuple(sorted(set(extra) | set(unknown)))
    if extra:
        instruction_id = data.get("instruction_id") if isinstance(data.get("instruction_id"), str) else None
        return ParsedGoalEvaluateRequest(
            ok=False,
            instruction_id=instruction_id,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=_optional_experiment_id(data.get("experiment_id")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    experiment_id, experiment_error = _parse_experiment_id(data)
    if experiment_error:
        return ParsedGoalEvaluateRequest(
            ok=False,
            instruction_id=data.get("instruction_id") if isinstance(data.get("instruction_id"), str) else None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=None,
            error_reason=experiment_error,
            extra_fields=(),
        )

    instruction_id = data.get("instruction_id")
    if not isinstance(instruction_id, str) or not instruction_id:
        return ParsedGoalEvaluateRequest(
            ok=False,
            instruction_id=None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=experiment_id,
            error_reason="missing_instruction_id",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedGoalEvaluateRequest(
            ok=False,
            instruction_id=instruction_id,
            user_id="unknown",
            experiment_id=experiment_id,
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedGoalEvaluateRequest(
        ok=True,
        instruction_id=instruction_id,
        user_id=_label_user_id(user_id),
        experiment_id=experiment_id,
        error_reason="",
        extra_fields=(),
    )


def _label_user_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return "applicant-web"
    return value.strip()[:64]


def _optional_experiment_id(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_experiment_id(data: dict) -> tuple[str | None, str]:
    if "experiment_id" not in data:
        return None, ""
    value = data["experiment_id"]
    if not isinstance(value, str) or not value.strip():
        return None, "malformed_experiment"
    return value.strip(), ""
