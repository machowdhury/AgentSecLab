"""Local-tooling checks for contributors who use the Cursor editor integration (.cursor/ is NOT tracked in the public repository).
These tests validate the editor rule and skill files themselves, not product behavior, so they run only when the files are present
in the working tree. They are NOT part of the public gate; the tracked governance documents are checked in tests/unit/test_splunk_governance.py
and tests/unit/test_design_system.py."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CURSOR = ROOT / ".cursor"
RULE = CURSOR / "rules" / "33-splunk-agent-skills.mdc"
SKILL = CURSOR / "skills" / "splunk-ko-review" / "SKILL.md"
SKILL_REF = CURSOR / "skills" / "splunk-ko-review" / "reference.md"
UI_SKILL = CURSOR / "skills" / "ui-review" / "SKILL.md"

pytestmark = pytest.mark.skipif(not CURSOR.is_dir(), reason="local-only: .cursor/ is untracked editor tooling and is absent from this checkout")

def test_rule_is_glob_scoped_not_always_apply():
    text = RULE.read_text(encoding="utf-8")
    assert "alwaysApply: false" in text
    assert "alwaysApply: true" not in text
    assert "splunk_app/**" in text
    assert "learning/**/searches/**" in text
    assert "write SPL first" in text
    assert "SECURITY / OPERATIONAL QUESTION" in text
    assert "TELEMETRY GAP" in text
    assert "DETECTION ANALYZED" in text
    assert "splunk-ko-review" in text
    assert "https://splunkbase.splunk.com/skills" in text


def test_skill_has_required_review_template():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---")
    assert "name: splunk-ko-review" in text
    for needle in (
        "SPLUNK KNOWLEDGE OBJECT REVIEW",
        "INDEXED FIELDS VERIFIED:",
        "FIELD CONTRACT:",
        "CORRELATION CONTRACT:",
        "DETECTION READINESS:",
        "LIVE SPLUNK VALIDATION:",
        "DASHBOARD CONSUMER:",
        "TELEMETRY SOURCE:",
        "VERDICT:",
        "DO NOT PUBLISH",
        "HUNT ONLY",
        "CIM:",
        "ALLOW does not mean execution",
    ):
        assert needle in text, needle
    assert "write SPL first" in text


def test_official_skills_are_catalog_names_not_invented():
    ref = SKILL_REF.read_text(encoding="utf-8")
    for skill in (
        "Splunk Search",
        "Search Performance Optimizer",
        "Search and Dashboard Troubleshooter",
        "Field Extraction and CIM Mapping",
        "Knowledge Object Governance",
        "Dashboard, Report, and Alert Performance Advisor",
        "Report Authoring Specialist",
        "Alerting and Notable Workflows",
        "Data Model and Search Acceleration",
        "Data Source Onboarding Advisor",
        "Ingestion Pipeline Design",
        "HEC Setup and Troubleshooting",
        "App and Add-on Lifecycle Advisor",
    ):
        assert skill in ref, skill
    assert "Do not invent" in ref



def test_ui_review_skill_exists():
    assert UI_SKILL.is_file()

