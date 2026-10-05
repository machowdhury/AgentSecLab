"""AgentSec links inside Splunk must not carry the locale.

Splunk owns locale routing. `/app/agentsec/<view>` is redirected to
`/<locale>/app/agentsec/<view>` with the query string intact. An AgentSec link
that already starts with `/en-US/` can be locale-prefixed a second time, which
produced the observed 404 on `/en-US//en-US/app/agentsec/learner_path`.

These tests read repository files. They do not prove a browser request.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
APP_STATIC = ROOT / "splunk_app" / "agentsec" / "appserver" / "static"
LEARNING = ROOT / "learning"
PATH_JS = APP_STATIC / "agentsec_learner_path.js"

# Rendered by Splunk. AgentSec owns the link text, Splunk owns the locale.
SPLUNK_RENDERED = (
    sorted(VIEWS.glob("*.xml"))
    + [PATH_JS]
    + [LEARNING / "home" / "dashboard.definition.json"]
    + [LEARNING / "academy" / "mastery.definition.json"]
    + sorted(LEARNING.glob("level_1/*/dashboard.definition.json"))
)

# Served by the Attack Service on port 5001. `learnerHref` keys on the `/en-US/`
# prefix to decide which links move to Splunk on port 8000, so these keep it.
ATTACK_SERVICE_OWNED = (
    ROOT / "src" / "agentsec" / "static" / "agentsec-ui.js",
    ROOT / "src" / "agentsec" / "templates" / "attack.html",
    ROOT / "src" / "agentsec" / "search_handoff.py",
)


def prefix_locale(path: str, locale: str = "en-US") -> str:
    """Model Splunk prefixing a root-relative path with the active locale."""
    return "/" + locale + path


def test_splunk_rendered_agentsec_links_do_not_hard_code_the_locale():
    offenders = []
    for path in SPLUNK_RENDERED:
        text = path.read_text(encoding="utf-8")
        if "/en-US/app/agentsec/" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_agentsec_app_links_use_the_application_relative_form():
    found = 0
    for path in SPLUNK_RENDERED:
        text = path.read_text(encoding="utf-8")
        for link in re.findall(r"/app/agentsec/[A-Za-z0-9_]+", text):
            found += 1
            assert not link.startswith("/app/agentsec//")
    assert found > 100, found


def test_locale_prefixing_cannot_duplicate_the_locale():
    """The reported 404 shape must be unreachable from AgentSec link text."""
    links = set()
    for path in SPLUNK_RENDERED:
        text = path.read_text(encoding="utf-8")
        links.update(re.findall(r"/app/agentsec/[A-Za-z0-9_]+", text))
    assert "/app/agentsec/learner_path" in links
    assert "/app/agentsec/ws_agentsec_arena" in links
    assert "/app/agentsec/ws_agentsec_home" in links
    for link in sorted(links):
        prefixed = prefix_locale(link)
        assert prefixed.count("/en-US") == 1, prefixed
        assert "//" not in prefixed, prefixed
        assert prefixed != "/en-US//en-US/app/agentsec/learner_path"
    assert prefix_locale("/app/agentsec/learner_path") == "/en-US/app/agentsec/learner_path"


def test_home_and_arena_point_at_your_path_without_a_locale():
    home = (VIEWS / "ws_agentsec_home.xml").read_text(encoding="utf-8")
    arena = (VIEWS / "ws_agentsec_arena.xml").read_text(encoding="utf-8")
    assert "[Your path](/app/agentsec/learner_path)" in home
    assert "/app/agentsec/learner_path" in arena
    assert "/en-US/app/agentsec/learner_path" not in home
    assert "/en-US/app/agentsec/learner_path" not in arena


def test_learner_path_catalog_links_are_locale_relative():
    source = PATH_JS.read_text(encoding="utf-8")
    hrefs = re.findall(r'"href":\s*"([^"]+)"', source)
    assert len(hrefs) >= 30, len(hrefs)
    for href in hrefs:
        assert href.startswith("/app/agentsec/"), href
        assert prefix_locale(href).count("/en-US") == 1


def test_nav_uses_view_names_and_not_hand_built_urls():
    nav = NAV.read_text(encoding="utf-8")
    assert '<view name="learner_path">' in nav
    assert "/en-US/" not in nav
    assert "<a href=" not in nav


def test_attack_service_rewriter_contract_is_unchanged():
    """These links cross origins and must keep the locale `learnerHref` keys on."""
    ui = (ROOT / "src" / "agentsec" / "static" / "agentsec-ui.js").read_text(encoding="utf-8")
    assert 'url.indexOf("/en-US/") === 0' in ui
    for path in ATTACK_SERVICE_OWNED:
        assert "/en-US/" in path.read_text(encoding="utf-8"), path


def test_curriculum_attack_service_url_is_recorded_as_attack_service_owned():
    curriculum = json.loads((LEARNING / "academy" / "curriculum.json").read_text(encoding="utf-8"))
    assert curriculum["attack_service_url"].startswith("/en-US/app/agentsec/open_attack")
