from agentsec.mcp.authorize import authorize_tool, evaluate_mcp_control
from agentsec.mcp.policy import coded_policy


def test_granted_tool_allows():
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:read",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "ALLOW"
    assert result.reason == "tool_granted"
    assert result.blocks_tool is False


def test_known_ungranted_defended_denies():
    result = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "DENY"
    assert result.reason == "tool_not_granted"
    assert result.blocks_tool is True


def test_known_ungranted_vulnerable_is_labeled_fail_open():
    result = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "ALLOW"
    assert result.reason.startswith("vulnerable_profile_fail_open:")
    assert "lookup_customer_tier" in result.reason
    assert "allowed_tools" in result.reason


def test_unknown_tool_is_error_in_both_profiles():
    for profile in ("defended", "vulnerable"):
        result = authorize_tool(
            tool_name="unknown_tool_xyz",
            requested_scope="policy:read",
            profile=profile,
            policy=coded_policy(),
            tool_registered=False,
        )
        assert result.decision == "ERROR"
        assert result.reason == "unknown_tool"


def test_control_evaluation_failure_is_error():
    def boom(**kwargs):
        raise RuntimeError("injected")

    result = evaluate_mcp_control(
        tool_name="lookup_policy",
        requested_scope="policy:read",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
        authorize_fn=boom,
    )
    assert result.decision == "ERROR"
    assert "control_evaluation_failure" in result.reason
    assert result.error_stage == "control_evaluation"


def test_restricted_scope_defended_is_scope_not_granted():
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:restricted:read",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "DENY"
    assert result.reason == "scope_not_granted"
    assert result.requested_scope == "policy:restricted:read"
    assert result.allowed_scope == "policy:read"


def test_restricted_scope_vulnerable_is_mcp003_fail_open():
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:restricted:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "ALLOW"
    assert result.reason == "vulnerable_profile_fail_open:scope_not_granted"
    assert result.allowed_scope == "policy:read"
    assert "allowed_tools" not in result.reason


def test_unknown_scope_is_error_not_deny():
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:write",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "ERROR"
    assert result.reason == "unknown_scope"
    assert result.error_stage == "schema_validation"


def test_unknown_scope_does_not_fail_open_when_vulnerable():
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:write",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert result.decision == "ERROR"
    assert result.reason == "unknown_scope"


def test_mcp002_and_mcp003_fail_open_reasons_differ():
    mcp002 = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    mcp003 = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:restricted:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert mcp002.reason != mcp003.reason
    assert "allowed_tools" in mcp002.reason
    assert mcp003.reason == "vulnerable_profile_fail_open:scope_not_granted"
    assert not mcp002.reason.startswith("vulnerable_profile_fail_open:scope_not_granted")


def test_known_ungranted_resource_defended_is_resource_not_granted():
    from agentsec.mcp.authorize import authorize_resource

    decision, reason, stage = authorize_resource(
        profile="defended",
        policy=coded_policy(),
        resource_id="executive-restricted",
        valid_resources=frozenset({"lending-basics", "executive-restricted"}),
    )
    assert decision == "DENY"
    assert reason == "resource_not_granted"
    assert stage is None


def test_known_ungranted_resource_vulnerable_is_mcp004_fail_open():
    from agentsec.mcp.authorize import MCP004_FAIL_OPEN_REASON, authorize_resource

    decision, reason, stage = authorize_resource(
        profile="vulnerable",
        policy=coded_policy(),
        resource_id="executive-restricted",
        valid_resources=frozenset({"lending-basics", "executive-restricted"}),
    )
    assert decision == "ALLOW"
    assert reason == MCP004_FAIL_OPEN_REASON
    assert stage is None


def test_unknown_resource_is_error_not_deny_and_does_not_fail_open():
    from agentsec.mcp.authorize import authorize_resource

    for profile in ("defended", "vulnerable"):
        decision, reason, stage = authorize_resource(
            profile=profile,
            policy=coded_policy(),
            resource_id="does-not-exist",
            valid_resources=frozenset({"lending-basics", "executive-restricted"}),
        )
        assert decision == "ERROR", profile
        assert reason == "unknown_resource"
        assert stage == "schema_validation"


def test_mcp002_003_004_fail_open_reasons_differ():
    from agentsec.mcp.authorize import MCP003_FAIL_OPEN_REASON, MCP004_FAIL_OPEN_REASON, authorize_resource

    mcp002 = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    mcp003 = authorize_tool(
        tool_name="lookup_policy",
        requested_scope="policy:restricted:read",
        profile="vulnerable",
        policy=coded_policy(),
        tool_registered=True,
    )
    _decision, mcp004_reason, _stage = authorize_resource(
        profile="vulnerable",
        policy=coded_policy(),
        resource_id="executive-restricted",
        valid_resources=frozenset({"lending-basics", "executive-restricted"}),
    )
    assert mcp002.reason != mcp003.reason
    assert mcp002.reason != mcp004_reason
    assert mcp003.reason == MCP003_FAIL_OPEN_REASON
    assert mcp004_reason == MCP004_FAIL_OPEN_REASON
    assert "resource_not_granted" not in mcp003.reason
    assert "scope_not_granted" not in mcp004_reason


def test_case_and_whitespace_are_unknown_scope_not_normalized():
    for token in ("Policy:read", "policy:read ", " policy:read", "policy:*", "*", "policy"):
        result = authorize_tool(
            tool_name="lookup_policy",
            requested_scope=token,
            profile="defended",
            policy=coded_policy(),
            tool_registered=True,
        )
        assert result.decision == "ERROR", token
        assert result.reason == "unknown_scope", token
        assert result.requested_scope == token
