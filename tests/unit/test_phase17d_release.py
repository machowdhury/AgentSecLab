"""Phase 17D release-readiness consistency. Does not prove LIVE Splunk or clean-room install."""

from __future__ import annotations

from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.mcp.policy import ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"
APP_CONF = ROOT / "splunk_app" / "agentsec" / "default" / "app.conf"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_HTML = ROOT / "src" / "agentsec" / "templates" / "attack.html"
LICENSE = ROOT / "LICENSE"
DOCS = ROOT / "docs"

REQUIRED_DOCS = (
    DOCS / "GETTING_STARTED.md",
    DOCS / "QUICKSTART.md",
    DOCS / "ARCHITECTURE.md",
    DOCS / "SECURITY_BOUNDARY.md",
    DOCS / "LIVE_VS_REPLAY.md",
    DOCS / "TROUBLESHOOTING.md",
    DOCS / "INSTRUCTOR_GUIDE.md",
    DOCS / "KNOWN_LIMITATIONS.md",
    DOCS / "OPERATIONS.md",
    DOCS / "EVIDENCE_FLOW.md",
    DOCS / "AGENTSEC_V1_PRODUCT_BOUNDARY.md",
    DOCS / "AGENTSEC_RELEASE_INVENTORY.md",
    DOCS / "AGENTSEC_RELEASE_LAB_MATRIX.md",
    DOCS / "CONTRIBUTING.md",
    DOCS / "PHASE17D_RELEASE_READINESS.md",
    ROOT / "CHANGELOG.md",
)


def test_schema_and_pdp_frozen():
    assert SCHEMA_VERSION == "1.9.0"
    policy = coded_policy()
    assert policy.allowed_tools == frozenset({"lookup_policy"}) == ALLOWED_TOOLS
    assert policy.allowed_scopes == frozenset({"policy:read"}) == ALLOWED_SCOPES
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-CAPSTONE" not in saved
    assert "DET-RAG" not in saved
    assert saved.count("[AgentSec -") == 1


def test_readme_is_learner_entry():
    text = README.read_text(encoding="utf-8")
    assert "Not in this lab slice" not in text
    assert "./scripts/lab-up.sh" in text
    assert "LIVE" in text and "REPLAY" in text
    assert "ws_agentsec_home" in text
    assert "Apache License" in text
    assert "intentionally contains vulnerable" in text.lower() or "intentionally contains vulnerable" in (
        DOCS / "AGENTSEC_V1_PRODUCT_BOUNDARY.md"
    ).read_text(encoding="utf-8").lower()
    assert "docs/QUICKSTART.md" in text
    assert "docs/TROUBLESHOOTING.md" in text


def test_required_release_docs_exist():
    missing = [str(p.relative_to(ROOT)) for p in REQUIRED_DOCS if not p.is_file()]
    assert missing == []
    assert LICENSE.is_file()
    assert "Apache License" in LICENSE.read_text(encoding="utf-8")
    assert (ROOT / "scripts" / "lab-preflight.sh").is_file()
    assert (ROOT / "scripts" / "lab-down.sh").is_file()


def test_product_version_rc1_not_schema():
    py = PYPROJECT.read_text(encoding="utf-8")
    assert 'version = "1.0.0rc1"' in py
    assert "version = 1.0.0-rc1" in APP_CONF.read_text(encoding="utf-8")
    assert SCHEMA_VERSION == "1.9.0"


def test_atlas_qualifier_in_repository_ui():
    html = ATTACK_HTML.read_text(encoding="utf-8")
    assert "AML.T0054" in html
    assert "REQUIRES REVALIDATION" in html


def test_gitignore_env():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gi
    assert "artifacts/*" in gi
