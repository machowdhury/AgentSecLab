"""Design-system tokens exist and are used on first-lab Flask pages."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DS = (ROOT / "docs" / "AGENTSEC_DESIGN_SYSTEM.md").read_text(encoding="utf-8")
CSS = (ROOT / "src" / "agentsec" / "static" / "agentsec.css").read_text(encoding="utf-8")
JS = (ROOT / "src" / "agentsec" / "static" / "agentsec-ui.js").read_text(encoding="utf-8")
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


def test_shared_css_carries_first_lab_tokens():
    for token in REQUIRED:
        if token == "#6B46C1":
            continue
        assert token in CSS, token
    assert "#6B46C1" not in CSS
    assert "min-height: 44px" in CSS
    assert "outline: 2px solid" in CSS
    assert "@media (max-width: 768px)" in CSS
    assert "@media (max-width: 390px)" in CSS


def test_flask_pages_use_shared_system_and_states():
    for html in (ACME, ATTACK):
        assert 'lang="en"' in html
        assert 'name="viewport"' in html
        assert "agentsec.css" in html
        assert "agentsec-ui.js" in html
        assert 'href="#main"' in html
        assert 'id="main"' in html
        assert 'data-state="READY"' in html
    assert "Submit loan" in ACME
    assert "Run ATK-002" in ATTACK
    assert "Fire ATK-002" not in ATTACK
    assert "completed_allowed" in ACME
    assert "ALLOW is not execution" in ATTACK
    assert "statusFromResult" in JS
    builder = (ROOT / "scripts" / "build_lab_pi_001_dashboard.py").read_text(encoding="utf-8")
    assert 'SECONDARY = "#3D4654"' in builder
    assert "#5B6573" not in builder
