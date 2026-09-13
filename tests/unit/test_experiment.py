from agentsec.attacks import ATK_002_PAYLOAD
from agentsec.experiment import (
    resolve_attack_id,
    resolve_mcp_attack_id,
    resolve_mcp_testbed_mode,
    resolve_testbed_mode,
)
from agentsec.request_contract import parse_process_body


def test_server_classifies_catalog_payloads(settings):
    assert resolve_attack_id("hello") == "ATK-001"
    assert resolve_attack_id(ATK_002_PAYLOAD) == "ATK-002"
    assert resolve_testbed_mode(input_text="hello", settings=settings) == "BASELINE"
    assert resolve_testbed_mode(input_text=ATK_002_PAYLOAD, settings=settings) == "ATTACK"


def test_env_override_wins_for_retest(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("AGENTSEC_TESTBED_MODE", "RETEST")
    from agentsec.settings import get_settings, reset_settings_cache

    reset_settings_cache()
    settings = get_settings()
    assert resolve_testbed_mode(input_text=ATK_002_PAYLOAD, settings=settings) == "RETEST"
    reset_settings_cache()


def test_unknown_fields_are_rejected():
    parsed = parse_process_body(
        {
            "input": "loan",
            "testbed.mode": "BASELINE",
            "security.profile": "vulnerable",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"
    assert "testbed.mode" in parsed.extra_fields


def test_mcp_attack_id_separates_tool_grant_from_scope(settings):
    assert resolve_mcp_attack_id("lookup_policy", "policy:read") == "MCP-001"
    assert resolve_mcp_attack_id("lookup_policy", "policy:restricted:read") == "MCP-003"
    assert resolve_mcp_attack_id("lookup_customer_tier", "customer:read") == "MCP-002"
    assert resolve_mcp_testbed_mode(tool="lookup_policy", requested_scope="policy:read", settings=settings) == "BASELINE"
    assert (
        resolve_mcp_testbed_mode(
            tool="lookup_policy",
            requested_scope="policy:restricted:read",
            settings=settings,
        )
        == "ATTACK"
    )
