"""Reusable learning metadata contracts. Not authorization and not coded policy."""

from __future__ import annotations

from agentsec.investigations import validate_investigations
from agentsec.lab_manifest import validate_lab_manifest

LEARNING_METADATA_NOT_AUTHORIZATION = True

REQUIRED_MANIFEST_CONCEPTS = (
    "lab_id",
    "title",
    "security_question",
    "specimens",
    "prediction",
    "limitations",
)

REQUIRED_SPECIMEN_CONCEPTS = (
    "specimen_id",
    "mode",
    "live",
    "experiment_id",
)


def assert_learning_not_policy(lab_id: str) -> None:
    """Fail closed if a lab pack claims to authorize."""
    validate_lab_manifest(lab_id)
    validate_investigations(lab_id)
