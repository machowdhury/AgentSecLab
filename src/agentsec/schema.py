"""Closed security-event schema validator."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from agentsec.settings import get_settings


@lru_cache(maxsize=1)
def load_schema() -> dict:
    path = get_settings().schema_path
    return json.loads(Path(path).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def validator() -> Draft202012Validator:
    return Draft202012Validator(load_schema(), format_checker=FormatChecker())


@lru_cache(maxsize=1)
def _loan_desk_validator() -> Draft202012Validator:
    path = Path(get_settings().schema_path).parent / "loan_desk_event.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")), format_checker=FormatChecker())


def validate_event(event: dict) -> None:
    # The Loan Desk events are a separate closed family so security_event 1.9.0 stays frozen.
    v = _loan_desk_validator() if event.get("agentsec.schema.name") == "agentsec.loan_desk_event" else validator()
    errors = sorted(v.iter_errors(event), key=lambda e: list(e.path))
    if errors:
        path = ".".join(str(p) for p in errors[0].absolute_path) or "<root>"
        raise ValidationError(f"{path}: {errors[0].message}")
