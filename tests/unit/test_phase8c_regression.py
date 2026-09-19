"""Phase 8C must not rewrite validated SPL, DET-MCP-001, or Studio definitions."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
Q_MCP = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
STUDIO = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"


def test_det_mcp_001_unchanged_and_has_no_catalog_control():
    text = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in text
    assert "CTRL-MCP-METADATA" not in text
    assert "MCP-CATALOG" not in text
    assert "DET-MCP-CATALOG" not in text


def test_existing_q_mcp_spl_unchanged_by_catalog_lab():
    files = sorted(Q_MCP.glob("Q-MCP-*.spl"))
    assert files
    blob = "\n".join(path.read_text(encoding="utf-8") for path in files)
    assert "Q-MCP-CATALOG" not in blob
    assert "mcp_metadata_trust" not in blob
    assert not (Q_MCP / "Q-MCP-CATALOG.spl").exists()
    assert not list(ROOT.glob("learning/**/Q-MCP-CATALOG.spl"))


def test_predecessor_studio_definitions_have_no_catalog_control():
    assert (STUDIO / "ws_lab_mcp_005.xml").is_file()
    assert (STUDIO / "ws_lab_mcp_006.xml").is_file()
    catalog = STUDIO / "ws_lab_mcp_catalog.xml"
    assert catalog.is_file()
    catalog_text = catalog.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in catalog_text
    assert "DET-MCP-CATALOG.spl" not in catalog_text
    assert "No DET-MCP-CATALOG" in catalog_text
    for path in STUDIO.glob("ws_lab_mcp_00*.xml"):
        text = path.read_text(encoding="utf-8")
        assert "CTRL-MCP-METADATA-001" not in text
        assert "DET-MCP-CATALOG" not in text
