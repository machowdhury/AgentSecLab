"""Research-integrity guard for the Phase 6C rejected MCP-005 candidate.

The rejected query must not enter learner-facing SPL, saved searches,
dashboards, or workshop content. Naming the field on a denylist is allowed.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REJECTED_FIELD = "agent.super_secret_field"
REJECTED_INDEX_TOKEN = "index=agentsec"

LEARNER_ROOTS = (
    ROOT / "learning",
    ROOT / "splunk_app",
    ROOT / "src" / "agentsec",
)

SKIP_SUFFIXES = {".pyc", ".png", ".svg", ".jpg", ".jpeg", ".woff", ".woff2"}
DENYLIST_MARKERS = ("prohibited_fields", "PROHIBITED", "rejected field", "do not publish")


def _learner_files():
    for root in LEARNER_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            if "__pycache__" in path.parts:
                continue
            yield path


def test_rejected_super_secret_field_is_absent_from_published_spl_and_views():
    hits = []
    for path in _learner_files():
        if path.suffix.lower() not in {".spl", ".xml", ".js", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if REJECTED_FIELD in text:
            hits.append(str(path.relative_to(ROOT)))
    assert hits == [], f"rejected field leaked into published SPL/views: {hits}"


def test_rejected_super_secret_field_is_not_used_as_a_search_filter():
    hits = []
    for path in _learner_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if REJECTED_FIELD not in text:
            continue
        denylist_file = any(marker.lower() in text.lower() for marker in DENYLIST_MARKERS)
        for i, line in enumerate(text.splitlines(), 1):
            if REJECTED_FIELD not in line:
                continue
            lowered = line.lower()
            stripped = line.strip().strip(",").strip('"').strip("'")
            if denylist_file and stripped == REJECTED_FIELD:
                continue
            if any(marker.lower() in lowered for marker in DENYLIST_MARKERS):
                continue
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue
            hits.append(f"{path.relative_to(ROOT)}:{i}:{line.strip()}")
    assert hits == [], f"rejected field used outside a denylist: {hits}"


def test_rejected_unvalidated_index_agentsec_is_absent_from_learner_spl():
    """index=agentsec without _telemetry was never validated. Do not publish it."""
    hits = []
    for path in _learner_files():
        if path.suffix.lower() not in {".spl", ".xml", ".json", ".conf", ".md"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if "index=agentsec_telemetry" in line:
                continue
            if REJECTED_INDEX_TOKEN in line:
                hits.append(f"{path.relative_to(ROOT)}:{i}:{line.strip()}")
    assert hits == [], f"unvalidated index=agentsec leaked into learner content: {hits}"


def test_mcp005_hunt_does_not_contain_rejected_candidate():
    spl = (ROOT / "learning/level_1/LAB-MCP-005/searches/Q-MCP-RESULT-AUTHORITY.spl").read_text(
        encoding="utf-8"
    )
    assert REJECTED_FIELD not in spl
    assert spl.startswith("index=agentsec_telemetry")
    assert "DET-MCP-005" not in spl
    catalog = (ROOT / "learning/level_1/LAB-MCP-005/searches/catalog.json").read_text(
        encoding="utf-8"
    )
    assert REJECTED_FIELD in catalog
    assert '"agent.super_secret_field"' in catalog
