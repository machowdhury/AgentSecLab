"""Verification bridge: receipt authenticity, run-id binding, bounds and safe failure. Deterministic; no Docker, no Splunk.

The in-process tests run with AGENTSEC_RECEIPTS_ISOLATION=off (conftest) because the read-only mount is a container
property; test_loan_desk_verifier_security.py covers the isolation check and the real process lifecycle.
"""

from __future__ import annotations

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
            "distinct_sequences": len(events), "checked_at": "T", "method": "m",
            "by_event_local": {"agentsec.llm.started": 3}, "by_event_indexed": {"agentsec.llm.started": 3}}


@pytest.fixture
def d(tmp_path):
    d = vb.bridge_dir(tmp_path)
    (d / vb.RECEIPTS).mkdir(parents=True)
    (d / vb.REQUESTS).mkdir(parents=True)
    return d


@pytest.fixture
def key():
    return vb.load_or_create_key(vb.state_dir())


def request(d, run_id=RID, now=None):
    return vb.request_verification(d, run_id, now)


def answer(d, key, **kw):
    kw.setdefault("fetch", lambda o, r: EV)
    kw.setdefault("reconcile", good_reconcile)
    return verifier.process_once(d, key, origin="x", **kw)


def test_sign_verify_roundtrip_and_tamper():
    k = b"k" * 32
    doc = vb.sign(k, {"run_id": RID, "n": 1})
    assert vb.verify(k, doc) and not vb.verify(b"x" * 32, doc) and not vb.verify(None, doc)
    assert not vb.verify(k, {**doc, "n": 2}) and not vb.verify(k, {**doc, "mac": "0" * 64}) and not vb.verify(k, "x")


def test_no_receipts_dir_means_not_installed_and_nothing_verifies(tmp_path):
    d = vb.bridge_dir(tmp_path / "none")
    assert request(d)[0] == "NOT_INSTALLED"
    assert vb.splunk_status(d, RID, 3)["status"] == "NOT_VERIFIED"
    assert vb.heartbeat_state(d) == "NOT_INSTALLED"


def test_happy_path_request_then_receipt(d, key):
    verifier.heartbeat(d, key, 1)
    assert request(d)[0] == "REQUESTED"
    assert vb.splunk_status(d, RID, 3)["status"] == "PENDING"
    assert answer(d, key) == [RID]
    s = vb.splunk_status(d, RID, 3)
    assert s["status"] == "SPLUNK_VERIFIED" and s["indexed_events"] == 3 and s["verifier"] == "ONLINE"
    assert answer(d, key) == []  # answered once


def test_receipt_states_its_scope_and_binds_the_request_and_both_evidence_digests(d, key):
    verifier.heartbeat(d, key, 1)
    request(d)
    answer(d, key)
    rec = vb.read_json_safe(d / vb.RECEIPTS / f"{RID}.splunk.json")
    assert vb.verify(key, rec)
    assert "not proof the events are true" in rec["scope"]
    assert rec["evidence_digest_local"] == rec["evidence_digest_indexed"] and rec["request_digest"] and rec["verifier_version"]


def test_verifier_ignores_misnamed_stale_and_future_requests(d, key):
    now = time.time()
    other = "22222222-2222-4222-8222-222222222222"
    vb.write_json_atomic(d / vb.REQUESTS / f"{other}.json", {"run_id": RID, "requested_at": now, "nonce": "aabbccdd"})  # wrong name
    old = "33333333-3333-4333-8333-333333333333"
    vb.write_json_atomic(d / vb.REQUESTS / f"{old}.json", {"run_id": old, "requested_at": now - 4000, "nonce": "aabbccdd"})
    fut = "44444444-4444-4444-8444-444444444444"
    vb.write_json_atomic(d / vb.REQUESTS / f"{fut}.json", {"run_id": fut, "requested_at": now + 500, "nonce": "aabbccdd"})
    vb.write_json_atomic(d / vb.REQUESTS / "not-a-uuid.json", {"run_id": "not-a-uuid", "requested_at": now, "nonce": "aabbccdd"})
    calls = []
    assert answer(d, key, fetch=lambda o, r: calls.append(r) or EV) == [] and calls == []


def test_a_receipt_is_never_verified_unless_it_answers_the_current_request(d, key):
    verifier.heartbeat(d, key, 1)
    request(d)
    vb.write_json_atomic(d / vb.RECEIPTS / f"{RID}.splunk.json", {"run_id": RID, "reconciled": True, "local_events": 3, "indexed_events": 3})
    assert vb.splunk_status(d, RID, 3)["status"] == "INVALID_RECORD"  # no nonce
    vb.write_json_atomic(d / vb.RECEIPTS / f"{RID}.splunk.json", {"run_id": RID, "nonce": "deadbeef00", "reconciled": True, "local_events": 3, "indexed_events": 3})
    assert vb.splunk_status(d, RID, 3)["status"] == "PENDING"  # a replayed answer is for another request
    req = vb.read_json_safe(d / vb.REQUESTS / f"{RID}.json")
    vb.write_json_atomic(d / vb.RECEIPTS / f"{RID}.splunk.json", {"run_id": "someone-else", "nonce": req["nonce"], "reconciled": True, "local_events": 3, "indexed_events": 3})
    assert vb.splunk_status(d, RID, 3)["status"] == "INVALID_RECORD"


def test_failures_are_explicit_never_success(d, key):
    verifier.heartbeat(d, key, 1)
    request(d)
    boom = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("splunk down"))  # noqa: E731
    answer(d, key, reconcile=boom)
    assert vb.splunk_status(d, RID, 3)["status"] == "VERIFICATION_FAILED"
    d2 = d.parent / "b" / "loan_desk"
    (d2 / vb.RECEIPTS).mkdir(parents=True)
    verifier.heartbeat(d2, key, 1)
    request(d2)
    answer(d2, key, reconcile=lambda *a, **k: {"reconciled": True, "problems": [], "local_events": 3, "indexed_events": 3, "error": "splunk search failed rc=1"})
    assert vb.splunk_status(d2, RID, 3)["status"] == "VERIFICATION_FAILED"  # zero-equals-zero with an error is still a failure


def test_unknown_run_and_unavailable_acmebank_are_not_verified(d, key):
    verifier.heartbeat(d, key, 1)
    request(d)
    answer(d, key, fetch=lambda o, r: None)
    s = vb.splunk_status(d, RID, 3)
    assert s["status"] == "SPLUNK_MISMATCH" and "unknown_run" in s["problems"]
    d2 = d.parent / "c" / "loan_desk"
    (d2 / vb.RECEIPTS).mkdir(parents=True)
    verifier.heartbeat(d2, key, 1)
    request(d2)
    answer(d2, key, fetch=lambda o, r: [])
    assert vb.splunk_status(d2, RID, 3)["status"] == "VERIFICATION_FAILED"


def test_offline_pending_timeout_stale_and_stopped_states(d, key):
    now = time.time()
    verifier.heartbeat(d, key, 1, now=now - 100)
    assert vb.heartbeat_state(d, now) == "OFFLINE"
    request(d, now=now)
    assert vb.splunk_status(d, RID, 3, now=now + 5)["status"] == "VERIFIER_OFFLINE"
    verifier.heartbeat(d, key, 1, now=now + 200)
    assert vb.splunk_status(d, RID, 3, now=now + 201)["status"] == "TIMED_OUT"
    answer(d, key, now=now + 202)
    assert vb.splunk_status(d, RID, 99, now=now + 203)["status"] == "STALE"
    verifier.heartbeat(d, key, 1, now=now + 203, state="stopped")
    assert vb.heartbeat_state(d, now + 204) == "OFFLINE"  # a cleanly stopped verifier is offline, not online-but-late


def test_requests_are_rate_limited_per_run_and_globally(d):
    now = time.time()
    assert request(d, now=now)[0] == "REQUESTED"
    assert request(d, now=now + 1)[0] == "RATE_LIMITED"
    assert request(d, now=now + vb.PER_RUN_MIN_INTERVAL_S + 1)[0] == "REQUESTED"
    for i in range(vb.GLOBAL_PER_HOUR):
        (d / vb.REQUESTS / f"{i:08x}-0000-4000-8000-000000000000.json").write_text("{}")
    assert request(d, "55555555-5555-4555-8555-555555555555")[0] == "RATE_LIMITED"
    assert request(d, "../../x")[0] == "BAD_RUN" and request(d, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")[0] == "BAD_RUN"


def test_verifier_runs_at_most_thirty_searches_a_minute(d, key):
    now = time.time()
    for i in range(40):
        rid = f"{i:08x}-1111-4111-8111-111111111111"
        vb.write_json_atomic(d / vb.REQUESTS / f"{rid}.json", {"run_id": rid, "requested_at": now, "nonce": f"{i:08x}"})
    assert len(answer(d, key, now=now)) == 30


def test_searches_are_fixed_templates_bound_to_a_validated_run_id():
    from agentsec.loan_desk import reconcile
    seen = []
    reconcile.run_spl = lambda spl, **k: seen.append(spl) or []  # type: ignore[assignment]
    with pytest.raises(ValueError):
        reconcile.indexed_view('x" | delete')
    assert seen == []
    reconcile.indexed_view(RID)
    assert all(RID in s and s.startswith('index=agentsec_telemetry') and "delete" not in s and "|" in s for s in seen)
    assert "| outputlookup" not in " ".join(seen) and "collect" not in " ".join(seen)


def test_nothing_in_the_bridge_exposes_credentials_sockets_or_listeners():
    root = Path(__file__).resolve().parents[1]
    src = "".join((root / p).read_text(encoding="utf-8") for p in (
        "src/agentsec/loan_desk/verify_bridge.py", "src/agentsec/loan_desk/verifier.py", "scripts/loan_desk_verifier.py", "scripts/loan_desk_verifier.sh"))
    for bad in ("docker.sock", "socket.socket", "serve_forever", "HTTPServer", "listen(", "8089", "make_server", "SPLUNK_PASSWORD"):
        assert bad not in src, bad
    rec = (root / "src/agentsec/loan_desk/reconcile.py").read_text(encoding="utf-8")
    assert "${SPLUNK_PASSWORD}" in rec and "SPLUNK_PASSWORD" not in rec.replace("${SPLUNK_PASSWORD}", "")  # never read into Python
    assert "/var/run/docker.sock" not in (root / "docker-compose.yml").read_text(encoding="utf-8")


def test_views_never_carry_the_key_mac_or_nonce(tmp_path, settings):
    from agentsec.loan_desk.service import LoanDeskService
    from agentsec.telemetry import MemorySink
    from tests.loan_desk_support import FINAL, GOOD_FORM, SUBMIT, ScriptedModel, tool
    svc = LoanDeskService(settings=settings, model=ScriptedModel([tool("get_applicant_profile", applicant_id="APP-1001"),
                          tool("get_credit_summary", applicant_id="APP-1001"), SUBMIT, FINAL]), sink=MemorySink(), background=False)
    v, _ = svc.submit(GOOD_FORM)
    d, key = bridge_online(settings.artifacts_dir)
    (d / vb.RECEIPTS).mkdir(parents=True, exist_ok=True)
    svc.request_verification(v["run_id"])
    bridge_answer(settings.artifacts_dir, v["run_id"], len(svc.view(v["run_id"])["events"]) if isinstance(svc.view(v["run_id"])["events"], list) else svc.view(v["run_id"])["events"])
    blob = json.dumps(svc.view(v["run_id"]))
    assert key.hex() not in blob and '"mac"' not in blob and "nonce" not in blob


def test_reverifying_shows_pending_not_the_stale_answer_then_the_new_answer(d, key):
    verifier.heartbeat(d, key, 1)
    now = time.time()
    request(d, now=now)
    answer(d, key, now=now + 1)
    assert vb.splunk_status(d, RID, 3, now=now + 2)["status"] == "SPLUNK_VERIFIED"
    later = now + vb.PER_RUN_MIN_INTERVAL_S + 2
    verifier.heartbeat(d, key, 1, now=later)
    assert request(d, now=later)[0] == "REQUESTED"
    assert vb.splunk_status(d, RID, 3, now=later + 1)["status"] == "PENDING"
    answer(d, key, now=later + 2)
    assert vb.splunk_status(d, RID, 3, now=later + 3)["status"] == "SPLUNK_VERIFIED"
    later2 = later + vb.PER_RUN_MIN_INTERVAL_S + 2
    verifier.heartbeat(d, key, 1, now=later2)
    request(d, now=later2)
    answer(d, key, now=later2 + 1, reconcile=lambda *a, **k: {"reconciled": False, "problems": ["count_mismatch local=3 indexed=1"], "local_events": 3, "indexed_events": 1})
    assert vb.splunk_status(d, RID, 3, now=later2 + 2)["status"] == "SPLUNK_MISMATCH"
