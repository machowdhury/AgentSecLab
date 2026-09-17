"""Offline catalog export and SHA-256 identity for scanner input."""

from __future__ import annotations

from agentsec.mcp.catalog import FIXTURE_MALICIOUS, FIXTURE_NORMAL
from agentsec.mcp.fixtures import (
    MCP_CATALOG_DESCRIPTION_MALICIOUS,
    MCP_CATALOG_DESCRIPTION_NORMAL,
)
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.scanners.catalog_export import (
    catalog_export_bytes,
    catalog_export_dict,
    lookup_policy_description_hash,
    sha256_bytes,
    write_catalog_artifact,
)


def test_export_is_deterministic_and_tools_list_shaped():
    first = catalog_export_bytes(FIXTURE_NORMAL)
    second = catalog_export_bytes(FIXTURE_NORMAL)
    assert first == second
    assert first.endswith(b"\n")
    payload = catalog_export_dict(FIXTURE_NORMAL)
    assert set(payload) == {"tools"}
    for row in payload["tools"]:
        assert set(row) == {"name", "description", "inputSchema"}
        for banned in (
            "allowed_tools",
            "allowed_scope",
            "trusted",
            "authorized",
            "grant",
            "security_profile",
        ):
            assert banned not in row


def test_normal_and_malicious_exports_differ_only_in_lookup_policy_description():
    normal = catalog_export_dict(FIXTURE_NORMAL)
    malicious = catalog_export_dict(FIXTURE_MALICIOUS)
    n_policy = next(row for row in normal["tools"] if row["name"] == "lookup_policy")
    m_policy = next(row for row in malicious["tools"] if row["name"] == "lookup_policy")
    assert n_policy["description"] == MCP_CATALOG_DESCRIPTION_NORMAL
    assert m_policy["description"] == MCP_CATALOG_DESCRIPTION_MALICIOUS
    assert n_policy["inputSchema"] == m_policy["inputSchema"]
    assert catalog_export_bytes(FIXTURE_NORMAL) != catalog_export_bytes(FIXTURE_MALICIOUS)


def test_description_hash_matches_phase8d_content_hash():
    assert (
        lookup_policy_description_hash(FIXTURE_NORMAL)
        == "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
    )
    assert (
        lookup_policy_description_hash(FIXTURE_MALICIOUS)
        == "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
    )


def test_artifact_sha256_is_exact_file_bytes(tmp_path):
    dest = tmp_path / "tools.json"
    data, identity = write_catalog_artifact(dest, FIXTURE_NORMAL)
    on_disk = dest.read_bytes()
    assert on_disk == data
    assert identity.sha256 == sha256_bytes(on_disk)
    assert identity.bytes_len == len(on_disk)
    assert identity.fixture == FIXTURE_NORMAL
    assert identity.description_sha256 != identity.sha256
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
