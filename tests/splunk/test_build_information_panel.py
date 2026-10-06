"""The BUILD tab reports packaged identity and must never drift from its sources.

A build-information panel is only useful if it is true. The failure that matters
is quiet: someone bumps the app build or the schema, does not regenerate the
home view, and the panel then asserts a build the lab is not running. A learner
comparing it against the static URL their browser requested would be misled by
the surface that exists to resolve exactly that confusion.

So every value is asserted against the file that owns it, read independently
here, rather than against a literal copied from the generator.

The panel also must not report live service health. Studio cannot poll a
non-Splunk endpoint, and a green service card would collapse three independent
facts: SERVICE HEALTH, EVIDENCE READINESS and MODEL QUALITY.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "learning" / "home" / "dashboard.definition.json"
VIEW = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_agentsec_home.xml"
APP_CONF = ROOT / "splunk_app" / "agentsec" / "default" / "app.conf"
STATIC_IDENTITY = ROOT / "splunk_app" / "static_cache_identity.json"
PYPROJECT = ROOT / "pyproject.toml"
CURRICULUM = ROOT / "learning" / "academy" / "curriculum.json"


@pytest.fixture(scope="module")
def definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def identity_markdown(definition) -> str:
    return definition["visualizations"]["viz_build_identity"]["options"]["markdown"]


@pytest.fixture(scope="module")
def separation_markdown(definition) -> str:
    return definition["visualizations"]["viz_build_separation"]["options"]["markdown"]


def test_build_tab_exists_without_displacing_the_others(definition):
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == ["START", "ORIENT", "PATH", "SPLUNK", "BUILD"]


def test_product_version_matches_pyproject(identity_markdown):
    version = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M).group(1)
    assert f"AgentSec version — {version}" in identity_markdown


def test_app_build_matches_app_conf(identity_markdown):
    """The drift that breaks the static-asset cache story."""
    parser = configparser.ConfigParser()
    parser.read_string(APP_CONF.read_text(encoding="utf-8"))
    build = parser["install"]["build"].strip()
    assert f"Splunk app build — {build}" in identity_markdown


def test_static_asset_digest_matches_the_identity_file(identity_markdown):
    digest = json.loads(STATIC_IDENTITY.read_text(encoding="utf-8"))["assets_sha256"]
    assert digest[:16] in identity_markdown
    assert digest not in identity_markdown, "show a prefix, not a full digest to copy"


def test_schema_and_contract_versions_match_the_runtime(identity_markdown):
    from agentsec.experiment import SCHEMA_VERSION
    from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION

    assert f"Telemetry schema — {SCHEMA_VERSION}" in identity_markdown
    assert f"ExternalEvidence contract — {EXTERNAL_CONTRACT_VERSION}" in identity_markdown
    # Architectural invariants for Phase 1. A bump here is a deliberate decision.
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"


def test_curriculum_counts_match_the_curriculum(identity_markdown):
    curriculum = json.loads(CURRICULUM.read_text(encoding="utf-8"))
    levels = curriculum["levels"]
    labs = {lab["lab_id"] for level in levels for lab in level.get("labs", [])}
    assert f"{len(levels)} levels" in identity_markdown
    assert f"{len(labs)} labs" in identity_markdown
    assert f"{len(curriculum['checkpoints'])} checkpoints" in identity_markdown


def test_panel_is_labelled_documented_not_measured(identity_markdown):
    """It describes what is packaged, not what is running."""
    assert "DOCUMENTED" in identity_markdown
    assert "not" in identity_markdown and "running" in identity_markdown


@pytest.mark.parametrize(
    "claim",
    [
        "SERVICE HEALTH",
        "EVIDENCE READINESS",
        "MODEL QUALITY",
        "does not prove a lab works",
        "does not prove indexing",
        "does not prove generation quality",
        "does not mean the Academy is",
    ],
)
def test_required_separation_is_stated_on_the_surface(separation_markdown, claim):
    assert claim in separation_markdown


def test_panel_does_not_report_live_service_health(identity_markdown, separation_markdown):
    """Studio cannot poll a non-Splunk endpoint, so a status here would be fiction."""
    combined = identity_markdown + separation_markdown
    for banned in ("Ready", "Degraded", "Healthy", "Unhealthy", "Run checks"):
        assert banned not in combined, f"{banned!r} implies a live health check this panel cannot do"


def test_build_tab_has_no_search(definition):
    """Build identity is static text. It must not query the telemetry index."""
    for viz_id in ("viz_build_identity", "viz_build_separation"):
        assert "dataSources" not in definition["visualizations"][viz_id]


def test_view_xml_carries_the_build_tab():
    """The definition and the shipped view must not disagree."""
    xml = VIEW.read_text(encoding="utf-8")
    body = re.search(r"<definition><!\[CDATA\[(.*?)\]\]></definition>", xml, re.S).group(1)
    shipped = json.loads(body)
    assert "viz_build_identity" in shipped["visualizations"]
    assert "layout_build" in shipped["layout"]["layoutDefinitions"]


def test_panel_uses_no_gfm_table(identity_markdown, separation_markdown):
    """Studio markdown does not render GFM tables; one here shows raw pipes.

    tests/splunk/test_agentsec_ui_shell.py enforces this across every view. It
    is repeated for this panel because a build-identity surface is exactly the
    shape that tempts a table.
    """
    for markdown in (identity_markdown, separation_markdown):
        assert "| --- |" not in markdown
        assert "|" not in markdown
