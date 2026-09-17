"""Live Cisco mcp-scanner static YARA against NORMAL and MALICIOUS fixtures.

Skipped when the pinned binary is absent. Phase 9B PASS requires this to run.
"""

from __future__ import annotations

import json

import pytest

from agentsec.mcp.catalog import FIXTURE_MALICIOUS, FIXTURE_NORMAL
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.scanners.cisco_mcp_scanner import resolve_scanner_binary
from agentsec.scanners.evidence import export_and_scan_fixture
from agentsec.scanners.models import EVIDENCE_CLASS

pytestmark = pytest.mark.live_scanner


@pytest.fixture(scope="module")
def scanner_bin():
    binary = resolve_scanner_binary()
    if binary is None:
        pytest.skip("pinned cisco mcp-scanner is not installed")
    return binary


def test_live_normal_and_malicious_static_scans(tmp_path, scanner_bin):
    before = coded_policy()
    normal_pack, normal = export_and_scan_fixture(
        fixture=FIXTURE_NORMAL,
        packs_root=tmp_path / "packs",
        binary=scanner_bin,
    )
    malicious_pack, malicious = export_and_scan_fixture(
        fixture=FIXTURE_MALICIOUS,
        packs_root=tmp_path / "packs",
        binary=scanner_bin,
    )
    after = coded_policy()
    assert before.allowed_tools == ALLOWED_TOOLS == after.allowed_tools
    for scan, pack, fixture in (
        (normal, normal_pack, FIXTURE_NORMAL),
        (malicious, malicious_pack, FIXTURE_MALICIOUS),
    ):
        assert scan.evidence_class == EVIDENCE_CLASS
        assert scan.static_scan is True
        assert scan.target_executed is False
        assert scan.llm_used is False
        assert scan.scan_id
        assert "agentsec.run.id" not in json.loads((pack / "manifest.json").read_text()) or json.loads(
            (pack / "manifest.json").read_text()
        )["agentsec.run.id"] is None
        assert (pack / "raw" / "scanner-output.json").is_file()
        assert (pack / "input" / "tools.json").read_bytes()
        assert scan.artifact.fixture == fixture
        assert scan.artifact.sha256.startswith("sha256:")
        assert scan.artifact.description_sha256.startswith("sha256:")
        assert scan.artifact.sha256 != scan.artifact.description_sha256
    assert normal.artifact.sha256 != malicious.artifact.sha256
    assert (
        normal.artifact.description_sha256
        == "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
    )
    assert (
        malicious.artifact.description_sha256
        == "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
    )
    if malicious.classification:
        assert malicious.classification in {
            "DETECTED_BY_SCANNER",
            "NOT_DETECTED_BY_SCANNER",
            "SCANNER_ERROR",
            "UNSUPPORTED",
        }
        assert malicious.classification not in {"BLOCKED", "PREVENTED", "SAFE", "AUTHORIZED", "DENIED"}
