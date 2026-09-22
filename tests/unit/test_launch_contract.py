"""Phase 14B closed launch JSON: extra fields and authority-like keys are ERROR."""

from agentsec.launch_contract import AUTHORITY_LIKE_FIELDS, parse_launch_body, parse_launch_json

CHECKPOINT_AUTHORITY_FIELDS = (
    "profile",
    "grants",
    "allowed_tools",
    "allowed_scope",
    "roles",
    "permissions",
    "python",
    "spl",
    "environment",
    "payload",
    "policy",
    "run.id",
    "security.profile",
    "control.decision",
    "operation.executed",
)


def test_valid_attack_row_parses():
    parsed = parse_launch_body(
        {
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        }
    )
    assert parsed.ok is True
    assert parsed.error_reason == ""


def test_unknown_fields_and_authority_injection_are_error_not_deny():
    for field in sorted(AUTHORITY_LIKE_FIELDS)[:8]:
        parsed = parse_launch_body(
            {
                "lab_id": "LAB-PI-001",
                "specimen_id": "ATK-002",
                "mode": "ATTACK",
                "execution": "live",
                field: "injected",
            }
        )
        assert parsed.ok is False
        assert parsed.error_reason == "unknown_fields"
        assert field in parsed.extra_fields


def test_checkpoint_authority_fields_are_named_and_rejected():
    base = {
        "lab_id": "LAB-MCP-001",
        "specimen_id": "MCP-002",
        "mode": "ATTACK",
        "execution": "live",
    }
    for field in CHECKPOINT_AUTHORITY_FIELDS:
        assert field in AUTHORITY_LIKE_FIELDS
        parsed = parse_launch_body({**base, field: "injected"})
        assert parsed.ok is False
        assert parsed.error_reason == "unknown_fields"
        assert parsed.extra_fields == (field,)


def test_malformed_and_duplicate_json():
    assert parse_launch_json("not-json").error_reason == "malformed_request"
    assert parse_launch_json("").error_reason == "malformed_request"
    assert parse_launch_json(None).error_reason == "malformed_request"
    dup = '{"lab_id":"LAB-PI-001","lab_id":"LAB-MCP-001","specimen_id":"ATK-002","mode":"ATTACK","execution":"live"}'
    assert parse_launch_json(dup).error_reason == "duplicate_json_keys"


def test_unknown_enum_values():
    base = {
        "lab_id": "LAB-PI-001",
        "specimen_id": "ATK-002",
        "mode": "ATTACK",
        "execution": "live",
    }
    assert parse_launch_body({**base, "profile": "open"}).error_reason == "unknown_fields"
    assert parse_launch_body({**base, "mode": "PWN"}).error_reason == "unknown_mode"
    assert parse_launch_body({**base, "execution": "replay"}).error_reason == "unknown_execution"
    assert parse_launch_body({**base, "lab_id": ""}).error_reason == "unknown_lab"
