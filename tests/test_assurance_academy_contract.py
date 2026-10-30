"""Source-level rules for the Academy-native assurance screens (browser behaviour is in tests/ui/test_assurance_academy_browser.py)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "academy-ui/src/assurance" / n for n in ("live.ts", "liveParts.tsx", "Overview.tsx", "Finding.tsx")]
SRC = {p.name: p.read_text(encoding="utf-8") for p in FILES}


def test_event_text_is_rendered_as_text_and_nothing_is_evaluated():
    for name, s in SRC.items():
        assert "dangerouslySetInnerHTML" not in s and "innerHTML" not in s and "eval(" not in s and "new Function" not in s, name


def test_the_screens_read_only_the_assurance_routes_and_send_no_search_text():
    live = SRC["live.ts"]
    urls = re.findall(r"[\"`](/api/[^\"`$]*)", live)
    assert urls and all(u.startswith("/api/assurance") for u in urls)
    for name, s in SRC.items():
        assert not re.search(r"method:\s*\"(POST|PUT|PATCH|DELETE)\"|\bpost\(", s), name
        assert "/api/" not in s.replace("/api/assurance", "") or name == "live.ts" and all(u.startswith("/api/assurance") for u in urls)


def test_the_three_evidence_classes_have_separate_views_and_the_class_is_always_shown():
    over, parts = SRC["Overview.tsx"], SRC["liveParts.tsx"]
    assert "ClassTabs" in over and "ClassBadge" in over and "Banner" in over
    for tab in ('"live"', '"recorded"', '"fixtures"'):
        assert tab in parts
    assert "not your lab's current security posture" in parts and "never real evidence" in parts


def test_an_unavailable_or_empty_view_has_no_numbers_and_says_it_is_not_a_pass():
    over, live = SRC["Overview.tsx"], SRC["live.ts"]
    assert 'data?.state === "unavailable"' in over and 'data?.state === "empty"' in over and 'data?.state === "ok" &&' in over      # tiles render only in the ok state
    assert live.count("not a pass") >= 5 and "No operations yet" in over


def test_the_drawer_is_an_accessible_modal_dialog():
    p = SRC["liveParts.tsx"]
    for needle in ('role="dialog"', 'aria-modal="true"', "aria-labelledby", '"Escape"', "e.shiftKey", "opener?.focus"):
        assert needle in p, needle


def test_the_workshop_run_is_adopted_only_for_live_findings():
    f = SRC["Finding.tsx"]
    assert "w.adoptable" in f and "adoptRunForWorkshop" in f
    store = (ROOT / "academy-ui/src/store.ts").read_text(encoding="utf-8")
    assert "[0-9a-f]{8}-[0-9a-f]{4}" in store.split("adoptRunForWorkshop")[1]                    # only a well-formed run id is ever stored
