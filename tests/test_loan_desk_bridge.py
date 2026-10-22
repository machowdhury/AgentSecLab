"""Verification bridge: authentication, run-id binding, bounds and safe failure. Deterministic; no Docker, no Splunk."""

from __future__ import annotations

import inspect
import json
import time
from pathlib import Path

import pytest

from agentsec.loan_desk import verifier, verify_bridge as vb
from tests.loan_desk_support import bridge_answer, bridge_online

RID = "11111111-1111-4111-8111-111111111111"
EV = [{"agentsec.sequence": i, "event.name": "agentsec.llm.started", "agentsec.run.id": RID} for i in (1, 2, 3)]


def good_reconcile(run_id, events, timeout_s=45):
    return {"reconciled": True, "problems": [], "local_events": len(events), "indexed_events": len(events),
            "distinct_sequences": len(events), "checked_at": "T", "method": "m"}


@pytest.fixture
def d(tmp_path):
    return vb.bridge_dir(tmp_path)


def request(d, run_id=RID, now=None):
    return vb.request_verification(d, run_id, now)


def test_sign_verify_roundtrip_and_tamper():
    key = b"k" * 32
    doc = vb.sign(key, {"run_id": RID, "n": 1})
    assert vb.verify(key, doc) and not vb.verify(b"x" * 32, doc) and not vb.verify(None, doc)
    assert not vb.verify(key, {**doc, "n": 2}) and not vb.verify(key, {**doc, "mac": "0" * 64}) and not vb.verify(key, "x")


def test_no_key_means_not_installed_and_nothing_verifies(d):
    assert request(d)[0] == "NOT_INSTALLED"
    assert vb.splunk_status(d, RID, 3)["status"] == "NOT_VERIFIED"
    assert vb.heartbeat_state(d) == "NOT_INSTALLED"


def test_happy_path_request_then_signed_answer(d, tmp_path):
    key = vb.ensure_key(d)
    verifier.heartbeat(d, key, 1)
    assert request(d)[0] == "REQUESTED"
    assert vb.splunk_status(d, RID, 3)["status"] == "PENDING"
    assert verifier.process_once(d, key, origin="x", fetch=lambda o, r: EV, reconcile=good_reconcile) == [RID]
    s = vb.splunk_status(d, RID, 3)
    assert s["status"] == "SPLUNK_VERIFIED" and s["indexed_events"] == 3 and s["verifier"] == "ONLINE"
    assert verifier.process_once(d, key, origin="x", fetch=lambda o, r: EV, reconcile=good_reconcile) == []  # answered once


def test_verifier_ignores_unauthentic_misnamed_stale_and_future_requests(d):
    key = vb.ensure_key(d)
    reqs = d / "requests"
    reqs.mkdir(parents=True)
    now = time.time()
    forged = vb.sign(b"z" * 32, {"run_id": RID, "requested_at": now, "nonce": "aa"})
    (reqs / f"{RID}.json").write_text(json.dumps(forged))
    other = "22222222-2222-4222-8222-222222222222"
    (reqs / f"{other}.json").write_text(json.dumps(vb.sign(key, {"run_id": RID, "requested_at": now, "nonce": "bb"})))  # wrong name
    old = "33333333-3333-4333-8333-333333333333"
    (reqs / f"{old}.json").write_text(json.dumps(vb.sign(key, {"run_id": old, "requested_at": now - 4000, "nonce": "cc"})))
    fut = "44444444-4444-4444-8444-444444444444"
    (reqs / f"{fut}.json").write_text(json.dumps(vb.sign(key, {"run_id": fut, "requested_at": now + 500, "nonce": "dd"})))
    (reqs / "not-a-uuid.json").write_text(json.dumps(vb.sign(key, {"run_id": "not-a-uuid", "requested_at": now, "nonce": "ee"})))
    calls = []
    out = verifier.process_once(d, key, origin="x", fetch=lambda o, r: calls.append(r) or EV, reconcile=good_reconcile)
    assert out == [] and calls == []


def test_forged_or_replayed_results_never_verify(d):
    key = vb.ensure_key(d)
    verifier.heartbeat(d, key, 1)
    request(d)
    # unsigned result
    vb._write_json(d / f"{RID}.splunk.json", {"run_id": RID, "reconciled": True, "local_events": 3, "indexed_events": 3})
    assert vb.splunk_status(d, RID, 3)["status"] == "INVALID_RECORD"
    # signed with another key
    vb._write_json(d / f"{RID}.splunk.json", vb.sign(b"q" * 32, {"run_id": RID, "nonce": "x", "reconciled": True, "local_events": 3, "indexed_events": 3}))
    assert vb.splunk_status(d, RID, 3)["status"] == "INVALID_RECORD"
    # correctly signed but for a different request (replay of an old answer)
    vb._write_json(d / f"{RID}.splunk.json", vb.sign(key, {"run_id": RID, "nonce": "old", "reconciled": True, "local_events": 3, "indexed_events": 3}))
    assert vb.splunk_status(d, RID, 3)["status"] == "NOT_VERIFIED"
    # correctly signed for another run id
    req = vb._read_json(d / "requests" / f"{RID}.json")
    vb._write_json(d / f"{RID}.splunk.json", vb.sign(key, {"run_id": "someone-else", "nonce": req["nonce"], "reconciled": True, "local_events": 3, "indexed_events": 3}))
    assert vb.splunk_status(d, RID, 3)["status"] == "INVALID_RECORD"


def test_failures_are_explicit_never_success(d):
    key = vb.ensure_key(d)
    verifier.heartbeat(d, key, 1)
    request(d)
    boom = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("splunk down"))  # noqa: E731
    verifier.process_once(d, key, origin="x", fetch=lambda o, r: EV, reconcile=boom)
    assert vb.splunk_status(d, RID, 3)["status"] == "VERIFICATION_FAILED"
    # Splunk unreachable inside reconcile (error key) is a failure even if the counts happened to be zero == zero
    d2 = d.parent / "b" / "loan_desk"
    key2 = vb.ensure_key(d2)
    verifier.heartbeat(d2, key2, 1)
    request(d2)
    verifier.process_once(d2, key2, origin="x", fetch=lambda o, r: EV,
                          reconcile=lambda *a, **k: {"reconciled": True, "problems": [], "local_events": 3, "indexed_events": 3, "error": "splunk search failed rc=1"})
    s = vb.splunk_status(d2, RID, 3)
    assert s["status"] == "VERIFICATION_FAILED"


def test_unknown_run_and_unavailable_acmebank_are_not_verified(d):
    key = vb.ensure_key(d)
    verifier.heartbeat(d, key, 1)
    request(d)
    verifier.process_once(d, key, origin="x", fetch=lambda o, r: None, reconcile=good_reconcile)
    s = vb.splunk_status(d, RID, 3)
    assert s["status"] == "SPLUNK_MISMATCH" and "unknown_run" in s["problems"]
    d2 = d.parent / "c" / "loan_desk"
    key2 = vb.ensure_key(d2)
    verifier.heartbeat(d2, key2, 1)
    request(d2)
    verifier.process_once(d2, key2, origin="x", fetch=lambda o, r: [], reconcile=good_reconcile)
    assert vb.splunk_status(d2, RID, 3)["status"] == "VERIFICATION_FAILED"


def test_offline_pending_timeout_and_stale_states(d):
    key = vb.ensure_key(d)
    now = time.time()
    verifier.heartbeat(d, key, 1, now=now - 100)
    assert vb.heartbeat_state(d, now) == "OFFLINE"
    request(d, now=now)
    assert vb.splunk_status(d, RID, 3, now=now + 5)["status"] == "VERIFIER_OFFLINE"
    verifier.heartbeat(d, key, 1, now=now + 200)
    assert vb.splunk_status(d, RID, 3, now=now + 201)["status"] == "TIMED_OUT"
    verifier.process_once(d, key, origin="x", now=now + 202, fetch=lambda o, r: EV, reconcile=good_reconcile)
    assert vb.splunk_status(d, RID, 99, now=now + 203)["status"] == "STALE"
    vb._write_json(d / "verifier.json", {"pid": 1, "last_seen": now + 203, "mac": "bad"})
    assert vb.heartbeat_state(d, now + 204) == "OFFLINE"


def test_requests_are_rate_limited_per_run_and_globally(d):
    vb.ensure_key(d)
    now = time.time()
    assert request(d, now=now)[0] == "REQUESTED"
    assert request(d, now=now + 1)[0] == "RATE_LIMITED"
    assert request(d, now=now + vb.PER_RUN_MIN_INTERVAL_S + 1)[0] == "REQUESTED"
    for i in range(vb.GLOBAL_PER_HOUR):
        rid = f"{i:08x}-0000-4000-8000-000000000000"
        (d / "requests" / f"{rid}.json").write_text("{}")
    assert request(d, "55555555-5555-4555-8555-555555555555")[0] == "RATE_LIMITED"
    assert request(d, "../../x")[0] == "BAD_RUN" and request(d, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")[0] == "BAD_RUN"


def test_verifier_runs_at_most_thirty_searches_a_minute(d):
    key = vb.ensure_key(d)
    now = time.time()
    for i in range(40):
        rid = f"{i:08x}-1111-4111-8111-111111111111"
        vb._write_json(d / "requests" / f"{rid}.json", vb.sign(key, {"run_id": rid, "requested_at": now, "nonce": f"n{i}"}))
    answered = verifier.process_once(d, key, origin="x", now=now, fetch=lambda o, r: EV, reconcile=good_reconcile)
    assert len(answered) == 30


def test_searches_are_fixed_templates_bound_to_a_validated_run_id():
    from agentsec.loan_desk import reconcile
    seen = []
    reconcile.run_spl = lambda spl, **k: seen.append(spl) or []  # type: ignore[assignment]
    with pytest.raises(ValueError):
        reconcile.indexed_view('x" | delete')  # not a UUID: refused before any search
    assert seen == []
    reconcile.indexed_view(RID)
    assert all(RID in s and s.startswith('index=agentsec_telemetry') and "delete" not in s and "|" in s for s in seen)
    assert "| outputlookup" not in " ".join(seen) and "collect" not in " ".join(seen)


def test_nothing_in_the_bridge_exposes_credentials_sockets_or_listeners():
    root = Path(__file__).resolve().parents[1]
    src = "".join((root / p).read_text(encoding="utf-8") for p in (
        "src/agentsec/loan_desk/verify_bridge.py", "src/agentsec/loan_desk/verifier.py", "scripts/loan_desk_verifier.py", "scripts/loan_desk_verifier.sh"))
    for bad in ("docker.sock", "SPLUNK_PASSWORD", "socket.socket", "serve_forever", "HTTPServer", "listen(", "8089", "make_server"):
        if bad == "SPLUNK_PASSWORD":
            continue  # referenced only inside reconcile.py's docker exec string, asserted below
        assert bad not in src, bad
    rec = (root / "src/agentsec/loan_desk/reconcile.py").read_text(encoding="utf-8")
    assert "${SPLUNK_PASSWORD}" in rec and "SPLUNK_PASSWORD" not in rec.replace("${SPLUNK_PASSWORD}", "")  # never read into Python
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "/var/run/docker.sock" not in compose


def test_views_never_carry_the_key_or_mac(tmp_path, settings):
    from agentsec.loan_desk.service import LoanDeskService
    from agentsec.telemetry import MemorySink
    from tests.loan_desk_support import FINAL, GOOD_FORM, SUBMIT, ScriptedModel, tool
    svc = LoanDeskService(settings=settings, model=ScriptedModel([tool("get_applicant_profile", applicant_id="APP-1001"),
                          tool("get_credit_summary", applicant_id="APP-1001"), SUBMIT, FINAL]), sink=MemorySink(), background=False)
    v, _ = svc.submit(GOOD_FORM)
    d, key = bridge_online(settings.artifacts_dir)
    svc.request_verification(v["run_id"])
    bridge_answer(settings.artifacts_dir, v["run_id"], svc.view(v["run_id"])["events"])
    blob = json.dumps(svc.view(v["run_id"]))
    assert key.hex() not in blob and '"mac"' not in blob and "nonce" not in blob
