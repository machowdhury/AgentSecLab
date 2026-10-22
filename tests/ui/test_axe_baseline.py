"""Accessibility regression guard: no serious or critical axe violation beyond the known baseline.

The baseline is what the pages shipped with before the shared shell: one colour-contrast node on four
LIVE workbench pages. They are listed, not hidden, so fixing them is a deliberate change. Viewport
widths emulate a narrow screen; this is not genuine zoom or a real device. SKIPPED without Chromium.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
KNOWN_SERIOUS = {
    ("/labs/LAB-RAG-CONTEXT", "color-contrast"), ("/labs/LAB-MEMORY-001", "color-contrast"),
    ("/labs/LAB-AGENT-GOAL-INTEGRITY-001", "color-contrast"), ("/labs/LAB-AGENT-DELEGATION-001", "color-contrast"),
}


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    chromium = os.environ.get("AGENTSEC_CHROMIUM")
    if not (chromium and Path(chromium).is_file()):
        pytest.skip("set AGENTSEC_CHROMIUM to a Chrome/Chromium executable")
    pytest.importorskip("axe_playwright_python")
    spec = importlib.util.spec_from_file_location("ui_shell_capture", ROOT / "scripts/ui_shell_capture.py")
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules["ui_shell_capture"] = mod
    spec.loader.exec_module(mod)
    return mod.capture(chromium, tmp_path_factory.mktemp("shots"), mod.PAGES)


def test_no_new_serious_or_critical_violations(report):
    found = {(r["page"], v["id"]) for r in report for v in r["violations"] if v["impact"] in ("serious", "critical")}
    assert found <= KNOWN_SERIOUS, sorted(found - KNOWN_SERIOUS)


def test_no_horizontal_overflow_at_desktop_or_phone_width(report):
    assert not [(r["page"], r["viewport"]) for r in report if r["horizontal_overflow"]]


def test_shared_bar_has_no_contrast_violation_anywhere(report):
    for r in report:
        for v in r["violations"]:
            assert not (v["id"] == "color-contrast" and r["page"] in ("/", "/academy", "/acmebank", "/labs/LAB-MCP-001")), r["page"]
