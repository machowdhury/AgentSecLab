"""Closed HTTP contract for POST /identity/delegate. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.identity.fixtures import AUTHORITY_LIKE_FIELDS

ALLOWED_IDENTITY_DELEGATE_FIELDS = frozenset({"claim_id", "user_id", "experiment_id"})


@dataclass(frozen=True)
class ParsedIdentityDelegateRequest:
    ok: bool
    claim_id: str | None
    user_id: str
    experiment_id: str | None
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_identity_delegate_body(data: object) -> ParsedIdentityDelegateRequest:
    if not isinstance(data, dict):
        return ParsedIdentityDelegateRequest(
            ok=False,
            claim_id=None,
            user_id="unknown",
            experiment_id=None,
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(
        sorted(
            str(key)
            for key in data.keys()
            if key not in ALLOWED_IDENTITY_DELEGATE_FIELDS or key in AUTHORITY_LIKE_FIELDS
        )
    )
    unknown = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_IDENTITY_DELEGATE_FIELDS))
    extra = tuple(sorted(set(extra) | set(unknown)))
    if extra:
        claim_id = data.get("claim_id") if isinstance(data.get("claim_id"), str) else None
        return ParsedIdentityDelegateRequest(
            ok=False,
            claim_id=claim_id,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=_optional_experiment_id(data.get("experiment_id")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    experiment_id, experiment_error = _parse_experiment_id(data)
    if experiment_error:
        return ParsedIdentityDelegateRequest(
            ok=False,
            claim_id=data.get("claim_id") if isinstance(data.get("claim_id"), str) else None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=None,
            error_reason=experiment_error,
            extra_fields=(),
        )

    claim_id = data.get("claim_id")
    if not isinstance(claim_id, str) or not claim_id:
        return ParsedIdentityDelegateRequest(
            ok=False,
            claim_id=None,
            user_id=_label_user_id(data.get("user_id")),
            experiment_id=experiment_id,
            error_reason="missing_claim_id",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedIdentityDelegateRequest(
            ok=False,
            claim_id=claim_id,
            user_id="unknown",
            experiment_id=experiment_id,
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedIdentityDelegateRequest(
        ok=True,
        claim_id=claim_id,
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
