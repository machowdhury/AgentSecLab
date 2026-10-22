"""Shared tokens and surface bar: parity with the Figma Make export snapshot, contrast, and no host in pages."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app
from agentsec.shell import shell_links

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src/agentsec/templates"
SHELL_PAGES = ["academy/base.html", "attack.html", "attack_mcp.html", "attack_authority.html",
               "attack_context.html", "attack_capstone.html", "acmebank.html"]


def _tokens() -> dict[str, str]:
    css = (ROOT / "src/agentsec/static/tokens.css").read_text(encoding="utf-8")
    return {m.group(1): m.group(2).strip() for m in re.finditer(r"--(as-[a-z0-9-]+):\s*([^;]+);", css)}


def _lum(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    chan = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in chan]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_tokens_equal_the_figma_export_snapshot_or_are_declared_additions():
    snap = json.loads((ROOT / "docs/design/figma_v2_tokens.json").read_text(encoding="utf-8"))
    assert snap["native_figma_file_accessed"] is False  # fidelity to native Figma is never claimed
    tokens = _tokens()
    for fig_name, as_name in snap["mapped_to"].items():
        assert tokens[as_name] == snap["figma_tokens"][fig_name], as_name
    undeclared = set(tokens) - set(snap["mapped_to"].values()) - set(snap["additions_not_in_figma"])
    assert not undeclared, undeclared


@pytest.mark.parametrize("fg,bg,minimum", [
    ("as-text", "as-bg", 4.5), ("as-text", "as-panel", 4.5), ("as-muted", "as-bg", 4.5), ("as-muted", "as-panel", 4.5),
    ("as-teal", "as-panel", 4.5), ("as-teal-dark", "as-panel", 4.5), ("as-blue", "as-panel", 4.5),
    ("as-green", "as-panel", 4.5), ("as-amber", "as-panel", 4.5), ("as-red", "as-panel", 4.5),
    ("as-panel", "as-navy", 4.5), ("as-panel", "as-teal", 4.5), ("as-focus-on-dark", "as-navy", 4.5),
    ("as-focus", "as-panel", 3.0), ("as-focus-on-dark", "as-navy-2", 3.0),
])
def test_token_pairs_meet_wcag_contrast(fg, bg, minimum):
    t = _tokens()
    assert contrast(t[fg], t[bg]) >= minimum, (fg, bg, contrast(t[fg], t[bg]))


def test_tokens_do_not_load_external_fonts_or_hosts():
    for name in ("tokens.css", "shell.css"):
        css = (ROOT / "src/agentsec/static" / name).read_text(encoding="utf-8")
        assert "@import" not in css and "url(http" not in css and "googleapis" not in css


@pytest.mark.parametrize("page", SHELL_PAGES)
def test_every_surface_template_carries_the_shared_shell(page):
    text = (TEMPLATES / page).read_text(encoding="utf-8")
    assert '{% include "_shell_head.html" %}' in text
    assert text.index('{% include "_shell_bar.html" %}') > text.index('class="skip-link"')  # skip link stays first


def test_shell_bar_marks_the_active_surface_and_hardcodes_no_host():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    for path, label in (("/", "Attack Service"), ("/academy", "Academy"), ("/acmebank", "AcmeBank")):
        html = client.get(path, headers={"Host": "lab.example:5001"}).get_data(as_text=True)
        bar = html.split('data-shell>')[1].split("</nav>")[0]
        current = re.findall(r'aria-current="page"[^>]*>([^<]+)<', bar)
        assert current == [label], (path, current)
        assert "lab.example" not in bar and "127.0.0.1" not in bar and "localhost" not in bar
        assert 'aria-label="AgentSec surfaces"' in html


def test_read_only_acmebank_view_ships_no_splunk_link_because_it_ships_no_script():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    html = app.test_client().get("/acmebank").get_data(as_text=True)
    bar = html.split('data-shell>')[1].split("</nav>")[0]
    assert "Splunk Studio" not in bar and "<script" not in html


def test_acmebank_app_hops_to_the_attack_service_through_declared_ports():
    links = shell_links("/", surface="acmebank_app")
    assert links["active"] == "acmebank" and links["service_port"] and links["acmebank"] == "/"
    assert shell_links("/academy/path", surface="attack")["service_port"] == ""
