"""Closed HTTP contract for POST /process. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_PROCESS_FIELDS = frozenset({"input", "user_id", "experiment_id"})


@dataclass(frozen=True)
class ParsedProcessRequest:
    ok: bool
    input_text: str | None
    user_id: str
    experiment_id: str | None
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_process_body(data: object) -> ParsedProcessRequest:
    if not isinstance(data, dict):
        return ParsedProcessRequest(
            ok=False,
            input_text=None,
            user_id="unknown",
            experiment_id=None,
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_PROCESS_FIELDS))
    if extra:
        return ParsedProcessRequest(
            ok=False,
            input_text=data.get("input") if isinstance(data.get("input"), str) else None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=_optional_experiment_id(data.get("experiment_id")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    experiment_id, experiment_error = _parse_experiment_id(data)
    if experiment_error:
        return ParsedProcessRequest(
            ok=False,
            input_text=data.get("input") if isinstance(data.get("input"), str) else None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=None,
            error_reason=experiment_error,
            extra_fields=(),
        )

    if "input" not in data:
        return ParsedProcessRequest(
            ok=False,
            input_text=None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=experiment_id,
            error_reason="missing_input",
            extra_fields=(),
        )

    raw = data["input"]
    if not isinstance(raw, str):
        return ParsedProcessRequest(
            ok=False,
            input_text=None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=experiment_id,
            error_reason="malformed_input",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedProcessRequest(
            ok=False,
            input_text=raw,
            user_id="unknown",
            experiment_id=experiment_id,
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedProcessRequest(
        ok=True,
        input_text=raw,
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
