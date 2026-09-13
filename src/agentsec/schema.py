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


def validate_event(event: dict) -> None:
    errors = sorted(validator().iter_errors(event), key=lambda e: list(e.path))
    if errors:
        path = ".".join(str(p) for p in errors[0].absolute_path) or "<root>"
        raise ValidationError(f"{path}: {errors[0].message}")
