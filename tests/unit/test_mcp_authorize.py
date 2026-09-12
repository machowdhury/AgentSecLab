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
