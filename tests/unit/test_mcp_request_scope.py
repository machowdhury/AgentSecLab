from agentsec.mcp.request_contract import parse_mcp_invoke_body


def test_parse_preserves_exact_requested_scope_token():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "policy:read ",
        }
    )
    assert parsed.ok is True
    assert parsed.requested_scope == "policy:read "


def test_parse_does_not_lowercase_scope():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "Policy:read",
        }
    )
    assert parsed.ok is True
    assert parsed.requested_scope == "Policy:read"


def test_parse_blank_scope_is_missing():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "   ",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "missing_requested_scope"


def test_parse_non_string_scope_is_missing():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": ["policy:read"],
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "missing_requested_scope"


def test_parse_client_allowed_scope_is_unknown_fields():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "policy:read",
            "allowed_scope": "policy:restricted:read",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"
    assert "allowed_scope" in parsed.extra_fields


def test_parse_client_allowed_policy_ids_is_unknown_fields():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "policy:read",
            "allowed_policy_ids": ["executive-restricted"],
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"
    assert "allowed_policy_ids" in parsed.extra_fields


def test_parse_missing_top_level_scope_ignores_argument_scope():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_policy",
            "arguments": {
                "policy_id": "lending-basics",
                "requested_scope": "policy:restricted:read",
            },
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "missing_requested_scope"
