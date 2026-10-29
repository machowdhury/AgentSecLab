"""Every link in the Academy source that opens Splunk Web must be gated for gateway mode (RC1 L-1, review F4/F5).
Some of those links are created only after a live launch (search handoffs from the server), which a page crawl cannot reach, so the source is checked."""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "academy-ui/src"
ANCHOR = re.compile(r'<a\b((?:(?!>).)*?)>((?:(?!</a>).)*?)</a>', re.S)


def test_no_raw_anchor_to_splunk_web_without_a_gateway_gate():
    bad, scanned = [], 0
    for f in sorted(SRC.rglob("*.tsx")):
        text = f.read_text(encoding="utf-8")
        for m in ANCHOR.finditer(text):
            attrs, inner = m.groups()
            if 'target="_blank"' in attrs and "Splunk" in inner:
                scanned += 1
                line_start = text.rfind("\n", 0, m.start()) + 1
                line = text[line_start:text.find("\n", m.start())]
                if "config.urls.splunk_web" not in line:                       # gated by the null URL the server reports in gateway mode
                    bad.append(f"{f.relative_to(SRC)}: {inner[:60]!r}")
    assert scanned >= 5, f"the scan found only {scanned} raw Splunk anchors; the pattern no longer matches the source"       # the gated sites in Notebook/Investigate/InvestigationRecord
    assert not bad, f"anchors that open Splunk Web without a gateway gate (use <SplunkLink> or check config.urls.splunk_web): {bad}"


def test_the_gate_component_exists_and_hides_in_gateway_mode():
    cfg = (SRC / "config.tsx").read_text(encoding="utf-8")
    assert "export function SplunkLink" in cfg and "config.gateway ? null" in cfg
