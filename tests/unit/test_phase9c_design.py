"""Phase 9C must not bump schema, change runtime authz, or add detectors/Studio."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
META = ROOT / "src" / "agentsec" / "mcp" / "metadata_trust.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"


def test_phase9c_boundaries():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "agentsec.scanner" not in schema
    assert "CTRL-MCP-001" in AUTHZ.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in META.read_text(encoding="utf-8")
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    scanner_views = {path.name for path in views.glob("*scanner*")}
    assert scanner_views <= {"ws_lab_scanner_runtime_evidence.xml"}
    assert not list((ROOT / "learning").rglob("DET-SCANNER*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-SCANNER*"))
    hec = (ROOT / "src" / "agentsec" / "scanners" / "hec_events.py").read_text(
        encoding="utf-8"
    )
    assert "authorize_tool" not in hec
    assert "coded_policy" not in hec
    phase = (ROOT / "docs" / "PHASE9C_SCANNER_SPLUNK_VALIDATION.md").read_text(
        encoding="utf-8"
    )
    assert "No Snyk Agent Scan" in phase
    assert "No rug-pull" in phase
    assert "No A2A" in phase
