"""Design-system tokens exist and are used on first-lab Flask pages."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DS = (ROOT / "docs" / "AGENTSEC_DESIGN_SYSTEM.md").read_text(encoding="utf-8")
ACME = (ROOT / "src" / "agentsec" / "templates" / "acmebank.html").read_text(encoding="utf-8")
ATTACK = (ROOT / "src" / "agentsec" / "templates" / "attack.html").read_text(encoding="utf-8")

REQUIRED = (
    "#F6F8FB",
    "#FFFFFF",
    "#17202A",
    "#3D4654",
    "#0B1F33",
    "#007F86",
    "#2E7D32",
    "#B7791F",
    "#C62828",
    "#3568A8",
    "#6B46C1",
    "#D9E0E7",
)


def test_design_system_file_lists_tokens():
    assert (ROOT / "docs" / "AGENTSEC_DESIGN_SYSTEM.md").is_file()
    for token in REQUIRED:
        assert token in DS, token
    assert "Severity is never color alone" in DS or "never color alone" in DS.lower()
    assert (ROOT / ".cursor" / "skills" / "ui-review" / "SKILL.md").is_file()


def test_flask_pages_use_core_tokens_and_focus():
    for html in (ACME, ATTACK):
        assert 'lang="en"' in html
        assert "#F6F8FB" in html
        assert "#0B1F33" in html
        assert "#17202A" in html
        assert "focus-visible" in html
        assert "min-height: 44px" in html
    assert "#007F86" in ACME
    assert "#C62828" in ATTACK
    assert "Fire ATK-002" in ATTACK
    builder = (ROOT / "scripts" / "build_lab_pi_001_dashboard.py").read_text(encoding="utf-8")
    assert 'SECONDARY = "#3D4654"' in builder
    assert "#5B6573" not in builder
