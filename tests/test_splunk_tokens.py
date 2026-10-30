"""Splunk visual alignment: supplied palette values, accessible ink pairs, one token block in both build environments."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src/agentsec/static"
BEGIN, END = "/* sp-tokens:begin", "/* sp-tokens:end */"


def _block(path: Path) -> str:
    t = path.read_text(encoding="utf-8")
    return t[t.index(BEGIN):t.index(END) + len(END)]


def _sp() -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"--(sp-[a-z0-9-]+):\s*(#[0-9a-f]{6})", _block(STATIC / "tokens.css"))}


def _lum(h: str) -> float:
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_the_academy_and_the_jinja_pages_share_one_token_block():
    assert _block(STATIC / "tokens.css") == (ROOT / "academy-ui/src/splunk-tokens.css").read_text(encoding="utf-8").strip()


def test_supplied_palette_is_kept_verbatim_and_in_order():
    t = _sp()
    cats = "1e93c6 f2b827 d6563c 6a5c9e 31a35f ed8440 3863a0 a2cc3e cc5068 73427f".split()
    assert [t[f"sp-cat-{i + 1}"] for i in range(10)] == ["#" + c for c in cats]
    semantic = {"critical": "d93f3c", "high": "f58f39", "warning": "f7bc38", "good": "65a637", "info": "6db7c6", "neutral": "555555"}
    assert {k: t[f"sp-{k}"] for k in semantic} == {k: "#" + v for k, v in semantic.items()}
    assert (t["sp-grid"], t["sp-axis"], t["sp-green"], t["sp-link"], t["sp-cta"]) == ("#ebedef", "#d9dce0", "#65a637", "#0f7bb8", "#2eb50b")
    assert [t[f"sp-seq-{i}"] for i in range(1, 7)] == ["#1d92c5", "#d6563c", "#6a5c9e", "#31a35f", "#ed8440", "#3863a0"]
    pairs = [(t[f"sp-div-{i}a"], t[f"sp-div-{i}b"]) for i in range(1, 7)]
    assert pairs == [("#ed8440", "#6a5c9e"), ("#d6563c", "#1e93c6"), ("#49443b", "#31a35f"), ("#3863a0", "#31a35f"), ("#3863a0", "#a2cc3e"), ("#cc5068", "#f7bc38")]


@pytest.mark.parametrize("name", ["critical", "high", "warning", "good", "info", "neutral", "recorded", "replayed"])
def test_every_ink_is_aa_on_its_tint_and_on_white(name):
    t = _sp()
    assert contrast(t[f"sp-ink-{name}"], t[f"sp-tint-{name}"]) >= 4.5
    assert contrast(t[f"sp-ink-{name}"], "#ffffff") >= 4.5


def test_high_severity_is_orange_with_accessible_dark_text_and_link_ink_is_aa():
    t = _sp()
    assert t["sp-high"] == "#f58f39" and contrast(t["sp-on-high"], t["sp-high"]) >= 4.5
    assert contrast(t["sp-ink-link"], "#ffffff") >= 4.5


def test_the_chart_bar_fill_is_the_first_series_and_is_a_3_to_1_graphic_on_white():
    t = _sp()
    assert contrast(t["sp-cat-1"], "#ffffff") >= 3.0
    css = (ROOT / "academy-ui/src/learn.css").read_text(encoding="utf-8")
    assert re.search(r"\.m-bars__bar\s*\{[^}]*var\(--sp-cat-1\)", css)


def test_status_rules_use_tokens_not_literal_colours():
    css = (ROOT / "academy-ui/src/index.css").read_text(encoding="utf-8")
    for rule in re.findall(r"^\.badge--[^{]*\{[^}]*\}", css, flags=re.M):
        assert not re.search(r"#[0-9a-fA-F]{3,6}\b", rule), rule
    for f in ("agentsec.css", "agentsec-workbench.css"):
        text = (STATIC / f).read_text(encoding="utf-8")
        assert not re.search(r"\.status\[[^{]*\{[^}]*var\(--state-", text), f  # the canonical --state-* values stay (design-system contract); use sites take accessible ink


def test_the_five_evidence_states_have_distinct_text_and_non_colour_cues():
    css = (ROOT / "academy-ui/src/index.css").read_text(encoding="utf-8")
    cues = {}
    for tone in ("live", "recorded", "replayed", "simulated", "unverified"):
        m = re.search(rf"\.badge--{tone}::before\s*\{{\s*content:\s*\"([^\"]+)\"", css)
        assert m, tone
        cues[tone] = m.group(1)
    assert len(set(cues.values())) == 5
    assert "dashed" in css.split(".badge--simulated {")[1].split("}")[0]
    assert "dotted" in css.split(".badge--unverified {")[1].split("}")[0]


def test_the_bank_brand_file_is_untouched_by_this_change():
    assert "--sp-" not in (STATIC / "acmebank-theme.css").read_text(encoding="utf-8")
