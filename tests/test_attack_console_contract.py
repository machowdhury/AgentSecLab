"""Browser-free contract for the Attack console chrome on all five attack templates (Flask test client, no Playwright)."""
from __future__ import annotations

import re

import pytest

from agentsec.attack_app import AcmeBankClient, create_app

LABS = ["/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-MEMORY-001",
        "/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-AGENT-DELEGATION-001", "/labs/LAB-AGENTSEC-CAPSTONE-001"]
# one representative per template: attack.html, attack_mcp, attack_context, attack_authority, attack_capstone
TEMPLATES = ["/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-AGENTSEC-CAPSTONE-001"]


@pytest.fixture
def client(settings):
    return create_app(AcmeBankClient("http://127.0.0.1:9")).test_client()


@pytest.mark.parametrize("path", TEMPLATES)
def test_console_chrome_contract(client, path):
    html = client.get(path).get_data(as_text=True)
    cards = re.findall(r'<a class="scenario-card" href="([^"]+)"([^>]*)>', html)
    hrefs = [h for h, _ in cards]
    assert len(hrefs) == 7 and set(hrefs) == set(LABS)
    assert [h for h, attrs in cards if 'aria-current="page"' in attrs] == [path]
    assert html.count("<h1") == 1
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    if "step-rail" in html:  # MCP is a wizard with its own stepper: cards only
        rail = html[html.index('class="step-rail"'):]
        rail = rail[:rail.index("</ol>")]
        anchors = re.findall(r'href="#([^"]+)"', rail)
        assert len(anchors) == 6 and [a for a in anchors if a not in ids] == []
        strip = re.search(r'class="scope-strip">(.*?)</p>', html, re.S).group(1)
        assert "not production authentication" in strip and "closed allowlist" in strip and "does not authorize" in strip
    else:
        assert path == "/labs/LAB-MCP-001"


def test_step_rail_maps_real_run_states_to_the_right_step():
    """The rail must not claim Results for a launch that failed or has not finished (regression: the first regex matched none of the real state strings)."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src/agentsec/templates/attack.html").read_text()
    pattern = re.search(r'const idx = s === "READY" \? 2 : /(.+?)/\.test\(s\) \? 3 : 4;', src).group(1)
    progress = ["RUN STARTING", "RUN IN PROGRESS", "REQUEST ACCEPTED", "RUN FAILED", "RUN DENIED", "BACKEND UNAVAILABLE", "EVIDENCE CHECK UNAVAILABLE", "CHECK TIMED OUT"]
    results = ["RUN COMPLETED", "WAITING FOR INDEXING", "EVIDENCE CONFIRMED"]
    assert all(re.search(pattern, s) for s in progress) and not any(re.search(pattern, s) for s in results)
