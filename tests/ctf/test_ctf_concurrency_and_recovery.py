"""CTF ledger under REAL separate processes (multiprocessing 'spawn', one service instance each, one shared state directory):
concurrent redemption, a process killed between the ledger append and the head write, and damaged ledger/head files.
Documented limits (also in docs/CTF.md): the MAC'd head detects truncation and partial writes; it does NOT detect deleting BOTH ledger files or restoring an older matched pair."""
from __future__ import annotations

import json
import multiprocessing as mp
import shutil

import pytest

from tests.ctf_support import FAKE
from tests.ctf_worker import FAKE2, crash_worker, redeem_worker, service

CTX = mp.get_context("spawn")
ROUNDS = 20


def verified(svc, cid=FAKE.id):
    code, a = svc.start(cid)
    assert code == 201
    assert svc.run(a["attempt_id"], {"posture": "baseline"})[0] == 200
    code, body = svc.verify(a["attempt_id"])
    assert code == 200 and body["state"] == "VERIFIED", body
    return a["attempt_id"], body["receipt"]


def race(state, jobs):
    """jobs: [(aid, receipt)], one process each, released together. Returns [(aid, status, body)]."""
    barrier, out = CTX.Barrier(len(jobs)), CTX.Queue()
    ps = [CTX.Process(target=redeem_worker, args=(str(state), aid, r, barrier, out)) for aid, r in jobs]
    [p.start() for p in ps]
    res = [out.get(timeout=60) for _ in ps]
    [p.join(30) for p in ps]
    assert all(p.exitcode == 0 for p in ps)
    return res


def ledger(state):
    return [json.loads(x) for x in (state / "ledger.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("rnd", range(ROUNDS))
def test_same_receipt_redeemed_simultaneously_by_four_instances_scores_once(tmp_path, rnd):
    state = tmp_path / "ctf"
    aid, receipt = verified(service(state))
    res = race(state, [(aid, receipt)] * 4)
    assert all(s in (200, 409) for _, s, _ in res), res                          # never a 5xx or a partial state
    oks = [b for _, s, b in res if s == 200]
    assert oks and all(b == oks[0] for b in oks), oks                               # every success is byte-for-byte the same answer
    assert oks[0]["awarded"] == FAKE.points and oks[0]["seq"] == 1
    assert [b for _, s, b in res if s == 409] == [{"error": "already_redeemed"}] * sum(s == 409 for _, s, _ in res)   # a late arrival: documented idempotent refusal
    entries = ledger(state)
    assert len(entries) == 1 and entries[0]["awarded"] == FAKE.points and entries[0]["receipt"]["nonce"] == receipt["nonce"]
    for _ in range(2):                                                               # consistent from other fresh instances
        sb = service(state).scoreboard()
        assert sb["ledger_intact"] and sb["total"] == FAKE.points and len(sb["rows"]) == 1
    assert service(state).redeem(aid, receipt) == (409, {"error": "already_redeemed"})


@pytest.mark.parametrize("rnd", range(ROUNDS))
def test_two_receipts_for_the_same_challenge_race_only_one_scores(tmp_path, rnd):
    state = tmp_path / "ctf"
    s0 = service(state)
    (a1, r1), (a2, r2) = verified(s0), verified(s0)
    res = race(state, [(a1, r1), (a1, r1), (a2, r2), (a2, r2)])
    assert all(s in (200, 409) for _, s, _ in res), res
    by = {a: [b for x, s, b in res if x == a and s == 200] for a in (a1, a2)}
    assert all(len(set(map(json.dumps, v))) <= 1 for v in by.values())               # deterministic per receipt
    awarded = {a: v[0]["awarded"] for a, v in by.items() if v}
    assert sorted(awarded.values()) == [0, FAKE.points] or list(awarded.values()) == [FAKE.points]   # the loser awards 0 (policy: one score per challenge)
    entries = ledger(state)
    assert len(entries) == 1 and sum(e["awarded"] for e in entries) == FAKE.points
    sb = service(state).scoreboard()
    assert sb["total"] == FAKE.points and len(sb["rows"]) == 1 and sb["ledger_intact"]


# ---------------------------------------------------------------- interrupted writes
def crash(state, aid, receipt):
    p = CTX.Process(target=crash_worker, args=(str(state), aid, receipt, "before_head"))
    p.start(); p.join(60)
    assert p.exitcode == 97, p.exitcode                                              # really killed at the seam, not a normal return


def test_kill_between_append_and_head_write_first_entry_heals_without_double_spend(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    (a1, r1), (a2, r2) = verified(s0), verified(s0)
    crash(state, a1, r1)
    assert len(ledger(state)) == 1 and not (state / "ledger.head").exists()          # line is durable, head is missing
    assert service(state).scoreboard()["ledger_intact"] is False                     # read-only paths fail closed until the next write heals
    code, body = service(state).redeem(a1, r1)                                       # the client retries the same receipt
    assert code == 200 and body["awarded"] == FAKE.points and body["seq"] == 1       # healed, finished, NOT spent twice
    assert len(ledger(state)) == 1
    code, body = service(state).redeem(a2, r2)
    assert code == 200 and body["awarded"] == 0                                      # policy: second receipt for the challenge is history
    sb = service(state).scoreboard()
    assert sb["ledger_intact"] and sb["total"] == FAKE.points and len(ledger(state)) == 1


def test_kill_after_a_later_append_heals_when_the_head_is_exactly_one_behind(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0)
    assert s0.redeem(a1, r1)[0] == 200
    a2, r2 = verified(s0, FAKE2.id)
    crash(state, a2, r2)
    assert len(ledger(state)) == 2 and json.loads((state / "ledger.head").read_text())["count"] == 1
    assert service(state).scoreboard()["total"] == 0                                 # fail closed while the head lags
    code, body = service(state).redeem(a2, r2)
    assert code == 200 and body["seq"] == 2 and len(ledger(state)) == 2
    sb = service(state).scoreboard()
    assert sb["ledger_intact"] and sb["total"] == FAKE.points + FAKE2.points


def test_a_head_two_behind_or_forged_does_not_heal(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    for cid in (FAKE.id, FAKE2.id):
        a, r = verified(s0, cid); assert s0.redeem(a, r)[0] == 200
    old = (state / "ledger.head").read_text()
    h = json.loads(old)
    h["count"] = 1                                                                   # edited head: MAC no longer matches
    (state / "ledger.head").write_text(json.dumps(h))
    assert service(state).scoreboard()["ledger_intact"] is False
    a3, r3 = verified(s0, FAKE.id)
    assert service(state).redeem(a3, r3) == (503, {"error": "ledger_integrity_failed"})
    assert len(ledger(state)) == 2                                                   # nothing was appended


def test_truncated_or_partial_last_line_fails_closed_and_nothing_is_appended(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0); assert s0.redeem(a1, r1)[0] == 200
    a2, r2 = verified(s0, FAKE2.id); assert s0.redeem(a2, r2)[0] == 200
    raw = (state / "ledger.jsonl").read_bytes()
    first, second = raw.splitlines(keepends=True)
    for cut in (second[: len(second) // 2], second[:1], second[:-2]):                # partial JSON line, one byte, a line that lost its closing brace and newline
        (state / "ledger.jsonl").write_bytes(first + cut)
        sb = service(state).scoreboard()
        assert sb["ledger_intact"] is False and sb["total"] == 0 and sb["rows"] == []
        a3, r3 = verified(service(state), FAKE.id)
        assert service(state).redeem(a3, r3) == (503, {"error": "ledger_integrity_failed"})
        assert (state / "ledger.jsonl").read_bytes() == first + cut                    # no append, no repair, no double-spend


def test_a_last_line_that_only_lost_its_newline_is_complete_and_the_next_append_stays_on_its_own_line(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0); assert s0.redeem(a1, r1)[0] == 200
    (state / "ledger.jsonl").write_bytes((state / "ledger.jsonl").read_bytes().rstrip(b"\n"))
    assert service(state).scoreboard()["total"] == FAKE.points                      # the entry and its MAC are complete: nothing was lost
    a2, r2 = verified(s0, FAKE2.id); assert service(state).redeem(a2, r2)[0] == 200
    assert len(ledger(state)) == 2 and service(state).scoreboard()["total"] == FAKE.points + FAKE2.points


def test_whole_last_line_removed_is_detected_as_head_ahead(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    for cid in (FAKE.id, FAKE2.id):
        a, r = verified(s0, cid); assert s0.redeem(a, r)[0] == 200
    first = (state / "ledger.jsonl").read_bytes().splitlines(keepends=True)[0]
    (state / "ledger.jsonl").write_bytes(first)                                     # clean one-line rollback; the MAC'd head still says 2
    assert service(state).scoreboard()["ledger_intact"] is False
    a3, r3 = verified(s0, FAKE2.id)
    assert service(state).redeem(a3, r3) == (503, {"error": "ledger_integrity_failed"})


def test_partial_head_file(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0); assert s0.redeem(a1, r1)[0] == 200
    head = (state / "ledger.head").read_text()
    (state / "ledger.head").write_text(head[: len(head) // 2])                       # one entry + unparseable head: indistinguishable from a crash before the first head write
    assert service(state).scoreboard()["ledger_intact"] is False
    a2, r2 = verified(s0, FAKE2.id)
    assert service(state).redeem(a2, r2)[0] == 200                                    # healed under the lock by the next redeem; the chain was valid
    assert service(state).scoreboard()["total"] == FAKE.points + FAKE2.points and len(ledger(state)) == 2
    head = (state / "ledger.head").read_text()
    (state / "ledger.head").write_text(head[: len(head) // 2])                       # two entries + unparseable head: NOT healed (fails closed)
    a3, r3 = verified(s0, FAKE.id)
    assert service(state).redeem(a3, r3) == (503, {"error": "ledger_integrity_failed"}) and service(state).scoreboard()["total"] == 0


# ---------------------------------------------------------------- documented limits (characterisation: these are NOT detected)
def test_documented_limit_deleting_both_ledger_files_is_not_detected(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0); assert s0.redeem(a1, r1)[0] == 200
    (state / "ledger.jsonl").unlink(); (state / "ledger.head").unlink()
    sb = service(state).scoreboard()
    assert sb["ledger_intact"] is True and sb["total"] == 0                          # looks like a fresh ledger: the loss of the score is silent
    a2, r2 = verified(s0); assert service(state).redeem(a2, r2)[:1] == (200,)        # a NEW attempt scores again (the old attempt record still says redeemed)
    assert service(state).redeem(a1, r1) == (409, {"error": "already_redeemed"})


def test_documented_limit_restoring_an_older_matched_pair_is_not_detected(tmp_path):
    state = tmp_path / "ctf"
    s0 = service(state)
    a1, r1 = verified(s0); assert s0.redeem(a1, r1)[0] == 200
    shutil.copy(state / "ledger.jsonl", tmp_path / "old.jsonl"); shutil.copy(state / "ledger.head", tmp_path / "old.head")
    a2, r2 = verified(s0, FAKE2.id); assert s0.redeem(a2, r2)[0] == 200
    shutil.copy(tmp_path / "old.jsonl", state / "ledger.jsonl"); shutil.copy(tmp_path / "old.head", state / "ledger.head")
    sb = service(state).scoreboard()
    assert sb["ledger_intact"] is True and sb["total"] == FAKE.points                # the second score vanished and nothing noticed
