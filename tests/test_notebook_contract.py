"""The Academy notebook cell: what the committed bundle must contain and what it must never offer. (Behaviour in a browser is exercised at checkpoint 3.)"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "academy-ui/src/mission/Notebook.tsx").read_text(encoding="utf-8")


def bundle() -> str:
    return "".join(p.read_text(encoding="utf-8") for p in (ROOT / "src/agentsec/static/learn/assets").glob("*.js"))


def test_cells_run_only_server_built_templates_and_the_scratchpad_is_never_submitted():
    posts = [ln for ln in SRC.splitlines() if "post(`" in ln or "api<Result>(`" in ln]
    assert posts and all("/search" in ln for ln in posts)
    assert "scratch" in SRC and not any("scratch" in ln for ln in posts)                      # the draft SPL is stored and copied, never posted
    assert 'rows={5} spellCheck={false}' in SRC and "NOT EXECUTED HERE" in SRC
    assert "readOnly" not in SRC and "contentEditable" not in SRC


def test_every_cell_shows_state_provenance_and_the_exact_spl():
    for needle in ("cellState(", "evidence class not reported", "result?.window", "Copy the SPL", "you cannot edit it", "Your conclusion", "what do you expect to see"):
        assert needle in SRC, needle
    for state in ("not ready", "ready", "running", "completed", "empty", "failed", "unavailable"):
        assert f'"{state}"' in SRC, state


def test_unavailable_search_is_reported_as_unavailable_not_as_a_result_or_a_verifier_problem():
    assert 'e === "search_unavailable"' in SRC and "nothing was searched" in SRC
    assert "host verifier" not in SRC.split("function problem")[1].split("}\n")[0].split("not_installed")[0]     # the new first message does not blame a verifier


def test_the_committed_bundle_carries_the_notebook_changes():
    b = bundle()
    for needle in ("search_unavailable", "Copy the SPL", "Your conclusion", "nothing was searched"):
        assert needle in b, needle
