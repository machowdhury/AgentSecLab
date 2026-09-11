"""Server-owned experiment dimensions. Attacker JSON cannot set these values."""

from __future__ import annotations

from agentsec.attacks import ATK_002_PAYLOAD
from agentsec.settings import Settings, VALID_TESTBED_MODES

EXECUTION_MODE = "LIVE"
TELEMETRY_FIDELITY = "OBSERVED"
SCHEMA_NAME = "agentsec.security_event"
SCHEMA_VERSION = "1.0.0"
WORKFLOW_ENTRY = "/process"
WORKFLOW_NAME = "loan_pipeline"


def resolve_attack_id(input_text: str) -> str:
    if isinstance(input_text, str) and input_text.strip() == ATK_002_PAYLOAD.strip():
        return "ATK-002"
    return "ATK-001"


def resolve_testbed_mode(*, input_text: str, settings: Settings) -> str:
    if settings.testbed_mode_override in VALID_TESTBED_MODES:
        return settings.testbed_mode_override
    if resolve_attack_id(input_text) == "ATK-002":
        return "ATTACK"
    return "BASELINE"


def technique_id_for(attack_id: str) -> str | None:
    if attack_id == "ATK-002":
        return "AML.T0054"
    return None
