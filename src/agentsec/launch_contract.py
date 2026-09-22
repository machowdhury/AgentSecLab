"""Closed Attack Service launch JSON. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.json_strict import DuplicateJsonKeyError, loads_json_no_duplicate_keys

ALLOWED_LAUNCH_FIELDS = frozenset({"lab_id", "specimen_id", "mode", "execution"})
ALLOWED_MODES = frozenset({"BASELINE", "ATTACK", "RETEST"})
ALLOWED_EXECUTIONS = frozenset({"live"})

# Rejected even when they would also fail as unknown fields. Named for tests/docs.
# profile is authority-like: the browser selects a specimen, not a security profile.
AUTHORITY_LIKE_FIELDS = frozenset(
    {
        "grant",
        "grants",
        "authorization",
        "roles",
        "permissions",
        "token",
        "scope",
        "requested_scope",
        "allowed_scope",
        "allowed_tools",
        "tool",
        "payload",
        "command",
        "python",
        "spl",
        "target",
        "credentials",
        "password",
        "api_key",
        "input",
        "user_id",
        "profile",
        "run.id",
        "security.profile",
        "control.decision",
        "operation.executed",
        "policy",
        "controls",
        "environment",
        "AGENTSEC_SECURITY_PROFILE",
        "AGENTSEC_TESTBED_MODE",
    }
)


@dataclass(frozen=True)
class ParsedLaunchRequest:
    ok: bool
    lab_id: str | None
    specimen_id: str | None
    profile: str | None
    mode: str | None
    execution: str | None
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_launch_json(raw: str | None) -> ParsedLaunchRequest:
    if raw is None or not str(raw).strip():
        return _malformed()
    try:
        data = loads_json_no_duplicate_keys(raw)
    except DuplicateJsonKeyError:
        return _malformed(error_reason="duplicate_json_keys")
    except ValueError:
        return _malformed()
    return parse_launch_body(data)


def parse_launch_body(data: object) -> ParsedLaunchRequest:
    if not isinstance(data, dict):
        return _malformed()

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_LAUNCH_FIELDS))
    if extra:
        return ParsedLaunchRequest(
            ok=False,
            lab_id=_as_str(data.get("lab_id")),
            specimen_id=_as_str(data.get("specimen_id")),
            profile=_as_str(data.get("profile")),
            mode=_as_str(data.get("mode")),
            execution=_as_str(data.get("execution")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    lab_id = data.get("lab_id")
    specimen_id = data.get("specimen_id")
    mode = data.get("mode")
    execution = data.get("execution")

    if not _nonempty_str(lab_id):
        return _invalid("unknown_lab", lab_id=None)
    if not _nonempty_str(specimen_id):
        return _invalid("unknown_specimen", lab_id=lab_id)
    if not _nonempty_str(mode) or mode not in ALLOWED_MODES:
        return _invalid(
            "unknown_mode",
            lab_id=lab_id,
            specimen_id=specimen_id,
        )
    if not _nonempty_str(execution) or execution not in ALLOWED_EXECUTIONS:
        return _invalid(
            "unknown_execution",
            lab_id=lab_id,
            specimen_id=specimen_id,
            mode=mode,
        )

    return ParsedLaunchRequest(
        ok=True,
        lab_id=str(lab_id),
        specimen_id=str(specimen_id),
        profile=None,
        mode=str(mode),
        execution=str(execution),
        error_reason="",
        extra_fields=(),
    )


def _malformed(*, error_reason: str = "malformed_request") -> ParsedLaunchRequest:
    return ParsedLaunchRequest(
        ok=False,
        lab_id=None,
        specimen_id=None,
        profile=None,
        mode=None,
        execution=None,
        error_reason=error_reason,
        extra_fields=(),
    )


def _invalid(
    error_reason: str,
    *,
    lab_id: str | None = None,
    specimen_id: str | None = None,
    profile: str | None = None,
    mode: str | None = None,
    execution: str | None = None,
) -> ParsedLaunchRequest:
    return ParsedLaunchRequest(
        ok=False,
        lab_id=lab_id if isinstance(lab_id, str) else None,
        specimen_id=specimen_id if isinstance(specimen_id, str) else None,
        profile=profile if isinstance(profile, str) else None,
        mode=mode if isinstance(mode, str) else None,
        execution=execution if isinstance(execution, str) else None,
        error_reason=error_reason,
        extra_fields=(),
    )


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
