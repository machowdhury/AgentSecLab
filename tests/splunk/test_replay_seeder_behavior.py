"""Behavioural contract for the REPLAY specimen seeder in splunk_hec_init.sh.

The static tests in test_replay_specimen_contract.py check that the script
*mentions* seeding, idempotence and search-based verification. Mentioning is not
doing: those assertions would still pass if the loop were inverted. This file
runs the real shell functions, under the same ``sh -eu`` the container uses, and
replaces only the network edges (curl, the management search, sleep) so each
outcome can be driven and the HTTP traffic inspected.

What must hold, because a learner's EVIDENCE tab depends on it:

  * absent pack      -> posted exactly once, then proven searchable by search
  * fully indexed    -> nothing posted (re-posting would double every count)
  * partially there  -> refuse and post nothing (a human decision, not a retry)
  * HEC non-200      -> failure
  * HEC 200 but the events never become searchable -> failure.
    HEC ACCEPTANCE IS NOT EVIDENCE READINESS.
  * an unreadable search answer is never mistaken for success
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "splunk_hec_init.sh"
PACK_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "specimens"
PACKS = sorted(PACK_DIR.glob("*.jsonl"))

#: Everything above the first top-level call is function and variable
#: definitions. Anything below it talks to a real Splunk.
ENTRY_MARKER = "\nwait_for_mgmt_api || exit 1"


def _definitions() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    assert ENTRY_MARKER in text, "seeder entry point moved; update the harness"
    return text.split(ENTRY_MARKER, 1)[0]


def _run(tmp_path: Path, pack: Path, *, initial: int, hec_code: str, after_post: str, call: str = "seed_one_specimen"):
    """Run ``call`` against ``pack`` with the network stubbed.

    initial     rows the index reports before anything is posted
    hec_code    HTTP status the raw endpoint returns
    after_post  "all" -> posting makes every event searchable
                "none" -> HEC says 200 but nothing ever becomes searchable
                "garbage" -> the search answers with unparseable text
    """
    state = tmp_path / "indexed"
    posts = tmp_path / "posts.log"
    state.write_text(str(initial))
    posts.write_text("")
    expected = sum(1 for line in pack.read_text(encoding="utf-8").splitlines() if line.strip())

    harness = tmp_path / "harness.sh"
    harness.write_text(
        _definitions()
        + textwrap.dedent(
            f"""
            # --- stubs: only the network edges are replaced ---------------------
            sleep() {{ :; }}
            mgmt_request() {{
              if [ "{after_post}" = "garbage" ]; then
                printf 'not a number\\n<html>oops</html>\\n'
              else
                printf '"count"\\n"%s"\\n' "$(cat {state})"
              fi
            }}
            curl() {{
              # Record the call, apply the scenario, answer with the status code.
              for arg in "$@"; do
                case "$arg" in
                  *collector/raw*)
                    echo "POST $arg" >> {posts}
                    if [ "{after_post}" = "all" ] && [ "{hec_code}" = "200" ]; then
                      echo {expected} > {state}
                    fi
                    printf '%s' "{hec_code}"
                    return 0
                    ;;
                esac
              done
              printf '000'
            }}
            {call} "{pack}"
            """
        ),
        encoding="utf-8",
    )
    # Dummy values satisfy the script's "must be set" guard. The stubs never
    # send them anywhere; they are not credentials for anything.
    env = {
        "PATH": "/usr/bin:/bin",
        "SPLUNK_PASSWORD": "stubbed-no-network",
        "SPLUNK_HEC_TOKEN": "stubbed-no-network",
    }
    proc = subprocess.run(
        ["sh", "-eu", str(harness)], capture_output=True, text=True, env=env, timeout=30
    )
    return proc, posts.read_text().splitlines(), expected


@pytest.fixture(params=PACKS, ids=lambda p: p.stem[:8])
def pack(request):
    return request.param


def test_there_are_packs_to_test():
    assert PACKS, "no committed specimen packs found"


def test_absent_specimen_is_posted_once_and_proven_searchable(tmp_path, pack):
    proc, posts, expected = _run(tmp_path, pack, initial=0, hec_code="200", after_post="all")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert len(posts) == 1, "an absent pack must be posted exactly once"
    assert "collector/raw" in posts[0], "bodies must go to the raw endpoint, verbatim"
    assert f"VERIFIED searchable ({expected}/{expected})" in proc.stdout


def test_fully_indexed_specimen_is_never_reposted(tmp_path, pack):
    # The index already holds exactly as many events as the pack has lines.
    expected = sum(1 for line in pack.read_text(encoding="utf-8").splitlines() if line.strip())
    proc, posts, _ = _run(tmp_path, pack, initial=expected, hec_code="200", after_post="all")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert posts == [], "re-posting an indexed pack would duplicate every event"
    assert "No action" in proc.stdout


def test_partial_specimen_is_refused_not_topped_up(tmp_path, pack):
    proc, posts, expected = _run(tmp_path, pack, initial=2, hec_code="200", after_post="all")
    assert proc.returncode != 0
    assert posts == [], "a partial pack must not be re-posted; duplicates corrupt counts"
    assert "PARTIAL" in proc.stdout


def test_hec_rejection_is_a_failure(tmp_path, pack):
    proc, posts, _ = _run(tmp_path, pack, initial=0, hec_code="500", after_post="all")
    assert proc.returncode != 0
    assert "HTTP 500" in proc.stdout


def test_hec_acceptance_without_searchable_events_is_a_failure(tmp_path, pack):
    """HEC ACCEPTANCE != INDEXED EVIDENCE. A 200 is a queue receipt."""
    proc, posts, expected = _run(tmp_path, pack, initial=0, hec_code="200", after_post="none")
    assert proc.returncode != 0, "a 200 with nothing searchable must not pass"
    assert len(posts) == 1
    assert "HEC accepted the payload but only" in proc.stdout
    assert "VERIFIED" not in proc.stdout


def test_unreadable_search_answer_is_never_mistaken_for_success(tmp_path, pack):
    proc, posts, _ = _run(tmp_path, pack, initial=0, hec_code="200", after_post="garbage")
    assert proc.returncode != 0
    assert "VERIFIED" not in proc.stdout


def test_an_empty_pack_is_refused(tmp_path):
    empty = tmp_path / "00000000-0000-0000-0000-000000000000.jsonl"
    empty.write_text("\n  \n")
    proc, posts, _ = _run(tmp_path, empty, initial=0, hec_code="200", after_post="all")
    assert proc.returncode != 0
    assert posts == []
    assert "empty" in proc.stdout


def test_seeding_the_whole_root_fails_if_any_specimen_fails(tmp_path):
    """One unsearchable specimen must fail the deployment, loudly."""
    root = tmp_path / "root" / "LAB-X" / "specimens"
    root.mkdir(parents=True)
    shutil.copy(PACKS[0], root / PACKS[0].name)
    state = tmp_path / "indexed"
    state.write_text("0")
    harness = tmp_path / "root.sh"
    harness.write_text(
        _definitions()
        + textwrap.dedent(
            f"""
            SPECIMEN_ROOT="{tmp_path / 'root'}"
            sleep() {{ :; }}
            mgmt_request() {{ printf '"count"\\n"0"\\n'; }}
            curl() {{ printf '200'; }}
            seed_replay_specimens
            """
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["sh", "-eu", str(harness)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "SPLUNK_PASSWORD": "stubbed-no-network", "SPLUNK_HEC_TOKEN": "stubbed-no-network"},
        timeout=30,
    )
    assert proc.returncode != 0
    assert "are not searchable" in proc.stdout
