"""CTF core: registry, attempt ids, state machine, ownership, receipts, ledger, scoreboard, reset, limits, gating, fuzz. Fake scenario only."""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import threading
import uuid
from pathlib import Path

import pytest
from flask import Flask

from agentsec.ctf import receipts, registry
from agentsec.ctf.registry import Challenge
from agentsec.ctf.service import LIMITS
from agentsec.ctf.store import ATTEMPT_ID, CtfStore, StoreError
from agentsec.ctf.web import register_ctf
from tests.ctf_support import FAKE, Clock, FakeScenario, make_service

ROOT = Path(__file__).resolve().parents[2]


def run_ok(svc, posture="baseline"):
    code, a = svc.start(FAKE.id)
    assert code == 201
    assert svc.run(a["attempt_id"], {"posture": posture})[0] == 200
    return a["attempt_id"]


def verified(svc):
    aid = run_ok(svc)
    code, body = svc.verify(aid)
    assert code == 200 and body["state"] == "VERIFIED", body
    return aid, body["receipt"]


# ------------------------------------------------------------ registry
def test_registry_validation_and_public_view_has_no_hint_or_answer():
    c = FAKE
    assert set(c.public()) == {"id", "title", "difficulty", "points", "technique", "control_boundary", "objective", "learning_outcome",
                               "simulation", "simulation_note", "engine", "hint_policy", "max_steps"}
    for bad in (dict(id="Bad Id"), dict(difficulty="Easy"), dict(points=0), dict(points=True), dict(simulation="MAYBE"), dict(max_steps=9)):
        with pytest.raises(ValueError):
            registry.validate(Challenge(**{**c.__dict__, **bad}))


# ------------------------------------------------------------ ids
def test_attempt_id_entropy_and_format(tmp_path):
    svc, _ = make_service(tmp_path)
    ids = {svc.start(FAKE.id)[1]["attempt_id"] for _ in range(15)}
    assert len(ids) == 15 and all(ATTEMPT_ID.match(i) for i in ids)
    assert all(len(i) == 32 for i in ids)       # 24 random bytes = 192 bits
    # base64url of 24 bytes: the alphabet is the full 64, so a sample is not low-entropy
    assert len(set("".join(ids))) > 40


# ------------------------------------------------------------ state machine
def test_state_machine_new_running_verified_and_failed(tmp_path):
    svc, _ = make_service(tmp_path)
    _, a = svc.start(FAKE.id)
    aid = a["attempt_id"]
    assert a["state"] == "NEW" and svc.verify(aid)[0] == 409                      # nothing to verify yet
    assert svc.run(aid, {"posture": "baseline"})[1]["state"] == "RUNNING"
    assert svc.run(aid, {"posture": "baseline"})[1]["error"] == "all_steps_done"
    code, v = svc.verify(aid)
    assert v["state"] == "VERIFIED" and v["receipt"]["points"] == 10
    again = svc.verify(aid)[1]
    assert again["replay"] is True and again["receipt"]["points"] == v["receipt"]["points"] and again["verdict"] == v["verdict"]   # final verdict; receipt only re-signed
    assert svc.run(aid, {"posture": "baseline"})[0] == 409
    bad = run_ok(svc, "hardened")
    assert svc.verify(bad)[1]["state"] == "FAILED" and svc.verify(bad)[1]["receipt"] is None


def test_unknown_or_malformed_ids_are_404_not_errors(tmp_path):
    svc, _ = make_service(tmp_path)
    for aid in ("x", "../../etc/passwd", "A" * 31, "A" * 33, "A" * 31 + "!", "", None, 5, "A" * 32):
        assert svc.get(aid)[0] == 404 and svc.run(aid, {})[0] == 404 and svc.reset(aid)[0] == 404 and svc.redeem(aid, {})[0] == 404
    assert svc.start("nope")[0] == 404 and svc.start("../x")[0] == 404 and svc.challenge(3)[0] == 404


# ------------------------------------------------------------ ownership / isolation
def test_runs_are_bound_to_their_attempt_and_cannot_be_claimed_by_another(tmp_path):
    svc, _ = make_service(tmp_path)
    a1, a2 = run_ok(svc), None
    r1 = svc.get(a1)[1]["runs"][0]["run_id"]
    _, a2rec = svc.start(FAKE.id)                         # starting again resets a1? a1 is RUNNING -> RESET, so use a second challenge-less path
    a2 = a2rec["attempt_id"]
    assert svc.get(a1)[1]["state"] == "RESET"
    svc.run(a2, {"posture": "baseline"})
    assert svc.verify(a2, [r1])[1]["error"] == "run_not_owned"                  # another attempt's run id
    assert svc.verify(a2, "x")[1]["error"] == "run_not_owned"
    assert svc.verify(a2, [])[1]["error"] == "run_not_owned"
    assert svc.verify(a2, [svc.get(a2)[1]["runs"][0]["run_id"]])[1]["state"] == "VERIFIED"


def test_bundle_tampering_is_rejected(tmp_path):
    svc, clock = make_service(tmp_path)
    for mutate in (lambda b, rec: b.update(attempt_id="B" * 32), lambda b, rec: b.update(challenge_id="other"),
                   lambda b, rec: b.update(created_at=rec["created_at"] - 1),                 # created before the attempt
                   lambda b, rec: b["events"].append({"agentsec.run.id": str(uuid.uuid4())}),     # an event from a foreign run
                   lambda b, rec: b.update(run_id=str(uuid.uuid4()))):
        aid = run_ok(svc)
        rec = svc.store.load(aid)
        bundle = svc._live[aid][rec["runs"][0]["run_id"]]
        mutate(bundle, rec)
        code, body = svc.verify(aid)
        assert code == 403 and body["error"] == "run_not_owned", body
        assert svc.get(aid)[1]["state"] == "RUNNING"


def test_run_id_reused_by_two_attempts_is_rejected(tmp_path):
    svc, _ = make_service(tmp_path)
    a = run_ok(svc)
    rid = svc.get(a)[1]["runs"][0]["run_id"]
    b = svc.start(FAKE.id)[1]["attempt_id"]
    svc.run(b, {"posture": "baseline"})
    rec = svc.store.load(b)
    old = rec["runs"][0]["run_id"]
    svc._live[b][rid] = {**svc._live[b].pop(old), "run_id": rid}       # force b to carry a's run id
    for e in svc._live[b][rid]["events"]:
        e["agentsec.run.id"] = rid
    rec["runs"][0]["run_id"] = rid
    svc.store.save(rec)
    svc.reset(a)                                                       # a is history, but its record still names the run
    assert svc.verify(b)[1]["error"] == "run_not_owned"


def test_verification_is_deterministic(tmp_path):
    svc, _ = make_service(tmp_path)
    sc = FakeScenario()
    _, bundle = sc.execute({"posture": "baseline"}, 0)
    assert all(sc.verify([bundle]) == sc.verify([copy.deepcopy(bundle)]) for _ in range(5))


def test_client_cannot_supply_a_flag_or_extra_fields(tmp_path):
    svc, _ = make_service(tmp_path)
    _, a = svc.start(FAKE.id)
    for payload in ({"posture": "baseline", "success": True}, {"flag": "x"}, {}, {"posture": "yolo"}, {"posture": ["baseline"]}, "baseline", None, [1]):
        assert svc.run(a["attempt_id"], payload)[0] == 400
    assert svc.get(a["attempt_id"])[1]["state"] == "NEW"


def test_restart_loses_live_evidence_and_verification_refuses(tmp_path):
    svc, _ = make_service(tmp_path)
    aid = run_ok(svc)
    svc2, _ = make_service(tmp_path)                                   # same state dir, empty memory
    assert svc2.verify(aid)[0] == 410


def test_attempt_expiry(tmp_path):
    svc, clock = make_service(tmp_path)
    aid = run_ok(svc)
    clock.advance(3601)
    assert svc.verify(aid)[1]["error"] == "attempt_not_active" and svc.get(aid)[1]["expired"] is True


# ------------------------------------------------------------ receipts
def test_receipt_signs_verifies_and_pins_fields(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    assert receipts.authentic(svc.store.key, r) and set(r) == receipts.FIELDS
    assert r["verdict"] == "VERIFIED" and r["splunk"] == "NOT VERIFIED" and len(r["run_ids"]) == 1
    for k, v in (("points", 11), ("challenge_id", "fake-two"), ("attempt_id", "C" * 32), ("run_ids", [str(uuid.uuid4())]), ("issued_at", r["issued_at"] + 1),
                 ("nonce", "0" * 32), ("verdict", "FAILED"), ("participant", "someone"), ("key_id", "00000000"), ("evidence_sha256", "0" * 64)):
        assert not receipts.authentic(svc.store.key, {**r, k: v}), k
    for junk in (None, [], "x", {**r, "extra": 1}, {k: v for k, v in r.items() if k != "mac"}, {**r, "points": 10.0}, {**r, "points": True}, {**r, "mac": "0" * 64}):
        assert not receipts.authentic(svc.store.key, junk)
    other = CtfStore(tmp_path / "other")
    assert not receipts.authentic(other.key, r)                        # another key


def test_receipt_tampering_replay_wrong_challenge_expiry_and_reset(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    assert svc.redeem(aid, {**r, "points": 999})[1]["error"] == "invalid_receipt"
    code, ok = svc.redeem(aid, r)
    assert code == 200 and ok["awarded"] == 10
    assert svc.redeem(aid, r) == (409, {"error": "already_redeemed"})   # replay
    # wrong attempt: a genuinely signed receipt for attempt A presented against attempt B
    aid2, r2 = verified(svc)
    assert svc.redeem(aid2, r)[1]["error"] == "receipt_mismatch"
    # forged-but-signed receipt for another challenge (simulating a key holder) is refused against this attempt
    forged = receipts.issue(svc.store.key, attempt_id=aid2, challenge_id="fake-two", run_ids=[str(uuid.uuid4())], points=10, evidence_sha256="0" * 64, now=int(clock()))
    assert svc.redeem(aid2, forged)[1]["error"] == "receipt_mismatch"
    # a signed receipt whose nonce is not the one issued for the attempt
    other = receipts.issue(svc.store.key, attempt_id=aid2, challenge_id=FAKE.id, run_ids=r2["run_ids"], points=10, evidence_sha256="0" * 64, now=int(clock()))
    assert svc.redeem(aid2, other)[1]["error"] == "attempt_not_redeemable"
    # expiry
    clock.advance(receipts.RECEIPT_TTL_S + 1)
    assert svc.redeem(aid2, r2)[0] == 410
    # reset kills redemption
    aid3, r3 = verified(svc)
    svc.reset(aid3)
    assert svc.redeem(aid3, r3)[1]["error"] == "attempt_not_redeemable"
    # a receipt from the future
    aid4, r4 = verified(svc)
    clock.advance(-1000)
    assert svc.redeem(aid4, r4)[0] == 410


# ------------------------------------------------------------ ledger concurrency
def test_ledger_double_spend_across_threads(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    results = []

    def spend():
        results.append(svc.store.consume(r, now=int(clock()))[0])

    ts = [threading.Thread(target=spend) for _ in range(24)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("OK") == 1 and results.count("REPLAY") == 23
    assert len(svc.store.read_ledger()[0]) == 1


def test_ledger_double_spend_through_service_and_two_service_instances(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    svc_b, _ = make_service(tmp_path, clock=clock)
    out = []
    ts = [threading.Thread(target=lambda s=s: out.append(s.redeem(aid, r)[0])) for s in (svc, svc_b) * 6]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert set(out) <= {200, 409} and out.count(200) >= 1           # a racing instance may complete the same receipt idempotently; points are spent once
    assert len(svc.store.read_ledger()[0]) == 1 and svc.scoreboard()["total"] == 10


def test_one_score_per_challenge_and_scoreboard_reverifies(tmp_path):
    svc, clock = make_service(tmp_path)
    a1, r1 = verified(svc)
    assert svc.redeem(a1, r1)[0] == 200
    a2, r2 = verified(svc)
    code, second = svc.redeem(a2, r2)
    assert code == 200 and second["awarded"] == 0                       # history, not a second score
    board = svc.scoreboard()
    assert board["total"] == 10 and len(board["rows"]) == 1 and board["ledger_intact"] and board["rows"][0]["attempt_id"] == a1
    # tamper with the ledger: edit a line's points -> entry dropped, total falls, integrity flagged
    lines = svc.store.ledger_path.read_text().splitlines()
    e = json.loads(lines[0])
    e["receipt"]["points"] = 500
    svc.store.ledger_path.write_text(json.dumps(e) + "\n" + "\n".join(lines[1:]) + "\n")
    board = svc.scoreboard()
    assert board["total"] == 0 and board["ledger_intact"] is False


def test_scoreboard_ignores_a_ledger_line_with_a_valid_entry_mac_but_forged_receipt(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    forged = {**r, "points": 999}                                       # receipt MAC no longer matches
    body = {"seq": 1, "prev": "0" * 64, "consumed_at": int(clock()), "receipt": forged, "awarded": 999}
    entry = {**body, "mac": svc.store._entry_mac(body)}                 # even a key holder's entry MAC cannot launder a bad receipt
    svc.store.ledger_path.write_text(json.dumps(entry, sort_keys=True) + "\n")
    board = svc.scoreboard()
    assert board["total"] == 0 and board["invalid_entries"] == 1


# ------------------------------------------------------------ reset / retry
def test_reset_invalidates_and_retry_gets_a_new_id(tmp_path):
    svc, _ = make_service(tmp_path)
    aid = run_ok(svc)
    assert svc.reset(aid)[1]["state"] == "RESET" and svc.reset(aid)[0] == 200      # idempotent
    assert aid not in svc._live
    assert svc.run(aid, {"posture": "baseline"})[0] == 409 and svc.verify(aid)[0] == 409
    nxt = svc.start(FAKE.id)[1]["attempt_id"]
    assert nxt != aid and svc.get(nxt)[1]["state"] == "NEW"
    assert svc.get(aid)[1]["state"] == "RESET"                                      # history kept


def test_reset_after_redeem_keeps_points(tmp_path):
    svc, _ = make_service(tmp_path)
    aid, r = verified(svc)
    svc.redeem(aid, r)
    svc.reset(aid)
    assert svc.scoreboard()["total"] == 10


# ------------------------------------------------------------ limits
def test_rate_limits_are_enforced_and_documented(tmp_path):
    assert LIMITS["start"] == (20, 3600) and LIMITS["reset"] == (20, 3600)
    svc, clock = make_service(tmp_path)
    codes = [svc.start(FAKE.id)[0] for _ in range(22)]
    assert codes[:20] == [201] * 20 and codes[20:] == [429, 429]
    clock.advance(3601)
    assert svc.start(FAKE.id)[0] == 201


def test_attempt_store_is_bounded(tmp_path, monkeypatch):
    import agentsec.ctf.store as st
    monkeypatch.setattr(st, "MAX_ATTEMPTS", 3)
    svc, clock = make_service(tmp_path)
    ids = []
    for _ in range(3):
        a, r = verified(svc)
        ids.append(a)
        clock.advance(1)
    assert svc.start(FAKE.id)[0] == 201                                 # unredeemed VERIFIED history is prunable, so the store cannot stay full
    assert len(svc.store.all_attempts()) <= 3


# ------------------------------------------------------------ files
def test_file_permissions_and_symlink_refusal(tmp_path):
    svc, _ = make_service(tmp_path)
    aid, r = verified(svc)
    svc.redeem(aid, r)
    root = svc.store.root
    mode = lambda p: stat.S_IMODE(p.stat().st_mode)
    assert mode(root) == 0o700 and mode(root / "attempts") == 0o700
    assert mode(root / "ctf.key") == 0o600 and mode(root / "ledger.jsonl") == 0o600 and mode(root / "attempts" / f"{aid}.json") == 0o600
    # a symlinked attempt record is not read
    target = tmp_path / "evil.json"
    target.write_text(json.dumps({"attempt_id": "Z" * 32}))
    (root / "attempts" / ("Z" * 32 + ".json")).symlink_to(target)
    assert svc.store.load("Z" * 32) is None
    # symlinked state dir / key refused
    link = tmp_path / "link"
    link.symlink_to(root)
    with pytest.raises(StoreError):
        CtfStore(link)
    root2 = tmp_path / "r2"
    root2.mkdir()
    (root2 / "ctf.key").symlink_to(target)
    with pytest.raises(StoreError):
        CtfStore(root2)


def test_key_file_is_created_0600_not_logged_and_loose_modes_are_tightened(tmp_path, caplog):
    store = CtfStore(tmp_path / "k")
    p = tmp_path / "k" / "ctf.key"
    os.chmod(p, 0o644)
    again = CtfStore(tmp_path / "k")
    assert again.key == store.key and stat.S_IMODE(p.stat().st_mode) == 0o600
    p.write_text("not-hex\n")
    with pytest.raises(StoreError):
        CtfStore(tmp_path / "k")
    assert store.key.hex() not in caplog.text


def test_ledger_is_a_regular_file_only(tmp_path):
    store = CtfStore(tmp_path / "l")
    store.ledger_path.symlink_to(tmp_path / "nowhere")
    assert store.read_ledger() == ([], True)
    with pytest.raises(OSError):
        store.consume({"nonce": "n", "attempt_id": "a", "challenge_id": "c", "participant": "p", "points": 1}, now=1)


# ------------------------------------------------------------ http: gating, csrf, size, no secrets
@pytest.fixture
def http(tmp_path):
    svc, clock = make_service(tmp_path)
    app = Flask(__name__)
    register_ctf(app, service=svc)
    from agentsec.request_guard import install_request_guard
    install_request_guard(app)
    return app.test_client(), svc


def test_non_loopback_is_refused_unless_opted_in_through_the_gateway(http, monkeypatch):
    c, _ = http
    assert c.get("/api/ctf/challenges").status_code == 200
    for kw in ({"environ_base": {"REMOTE_ADDR": "10.0.0.5"}},
               {"headers": {"Host": "evil.example.com"}},
               {"headers": {"Host": "127.0.0.1.evil.com"}},
               {"environ_base": {"REMOTE_ADDR": "::ffff:10.0.0.1"}}):
        assert c.get("/api/ctf/challenges", **kw).status_code == 403
    gw = {"environ_base": {"REMOTE_ADDR": "172.18.0.4"}, "headers": {"Host": "lab.example", "X-Remote-User": "alice", "X-AgentSec-Gateway-Secret": "gw-secret-value-0123456"}}
    assert c.get("/api/ctf/challenges", **gw).status_code == 403                       # header alone is not enough
    monkeypatch.setenv("AGENTSEC_CTF_ALLOW_GATEWAY", "1")
    assert c.get("/api/ctf/challenges", **gw).status_code == 403                       # opt-in without a configured secret
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", "gw-secret-value-0123456")
    assert c.get("/api/ctf/challenges", **gw).status_code == 200
    assert c.get("/api/ctf/challenges", environ_base=gw["environ_base"], headers={"Host": "lab.example"}).status_code == 403   # opt-in alone is not enough
    assert c.get("/api/ctf/challenges", environ_base={"REMOTE_ADDR": "::1"}, headers={"Host": "[::1]:5001"}).status_code == 200
    assert c.get("/api/ctf/challenges", environ_base={"REMOTE_ADDR": "::ffff:127.0.0.1"}).status_code == 200


def test_post_hardening_json_only_size_csrf_and_generic_errors(http):
    c, svc = http
    base = "/api/ctf/challenges/fake-one/attempts"
    assert c.post(base, data="x", content_type="text/plain").status_code == 415
    assert c.post(base, json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post(base, json={}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    r = c.post(base, json={})
    assert r.status_code == 201 and r.headers["Cache-Control"] == "no-store"
    aid = r.get_json()["attempt_id"]
    assert c.post(f"/api/ctf/attempts/{aid}/run", data="{" + '"posture":"' + "a" * 5000 + '"}', content_type="application/json").status_code in (400, 413)
    assert c.post(f"/api/ctf/attempts/{aid}/run", data='{"posture":"baseline","posture":"hardened"}', content_type="application/json").status_code == 400
    assert c.post(f"/api/ctf/attempts/{aid}/run", data="{not json", content_type="application/json").status_code == 400
    assert c.post(f"/api/ctf/attempts/{aid}/verify", json={"x": 1}).status_code == 400
    assert c.post(f"/api/ctf/attempts/{aid}/redeem", json={}).status_code == 400
    assert c.post(f"/api/ctf/attempts/{aid}/reset", json={"x": 1}).status_code == 400
    assert c.get("/api/ctf/attempts/..%2f..%2fetc").status_code in (404, 400)
    assert c.get("/api/ctf/attempts/" + "A" * 32).status_code == 404
    key_hex = svc.store.key.hex()
    for path in ("/api/ctf/health", "/api/ctf/scoreboard", "/api/ctf/challenges", f"/api/ctf/attempts/{aid}"):
        assert key_hex not in c.get(path).get_data(as_text=True)


def test_health_states_the_labels(http):
    body = http[0].get("/api/ctf/health").get_json()
    assert body["tenancy"] == "NOT MULTI-USER" and body["hosting"] == "NOT PUBLIC HOSTING" and "LOCAL" in body["exposure"]


def test_internal_errors_are_generic(http, monkeypatch):
    c, svc = http
    monkeypatch.setattr(svc, "list_challenges", lambda: 1 / 0)
    r = c.get("/api/ctf/challenges")
    assert r.status_code == 500 and r.get_json() == {"error": "internal_error"}


# ------------------------------------------------------------ fuzz
@pytest.mark.parametrize("payload", [None, 1, 1.5, True, [], {}, "", "\x00", "A" * 100_000, {"posture": None}, {"posture": {"$ne": 1}}, {"posture": "baseline\x00"},
                                     {"posture": "BASELINE"}, {"posture": " baseline"}, {"": ""}, {"posture": "baseline", "__proto__": 1}, [[[]]]])
def test_run_fuzz_never_crashes_or_succeeds(tmp_path, payload):
    svc, _ = make_service(tmp_path)
    _, a = svc.start(FAKE.id)
    code, body = svc.run(a["attempt_id"], payload)
    assert code == 400 and svc.get(a["attempt_id"])[1]["state"] == "NEW"


@pytest.mark.parametrize("receipt", [None, 1, [], "x", {}, {"mac": 1}, {"a": "b" * 10000}, True])
def test_redeem_fuzz(tmp_path, receipt):
    svc, _ = make_service(tmp_path)
    aid = run_ok(svc)
    assert svc.redeem(aid, receipt)[0] == 400


def test_no_static_asset_or_registry_view_contains_verification_material():
    """No flag/answer material: nothing in the CTF static assets or the public registry JSON names a decisive marker."""
    markers = ("also invoke lookup_customer_tier", "vulnerable_profile_fail_open", "ambient_deputy", "PRE-APPROVED", "use this exact note",
               "metadata_derived_authority", "caller_identity_derived_authority", "identity_claim_is_not_grant")
    files = [p for pat in ("static/ctf*", "templates/ctf/*") for p in (ROOT / "src/agentsec").glob(pat) if p.is_file()]
    from agentsec.ctf.challenges import default_scenarios
    blobs = [p.read_text() for p in files] + [json.dumps(s.challenge.public()) for s in default_scenarios().values()]
    for blob in blobs:
        for m in markers:
            assert m not in blob, m


# ------------------------------------------------------------ review fixes (M1, M2, L1, L2, L3)
def test_gateway_path_needs_the_shared_secret_not_just_the_identity_header(http, monkeypatch):
    c, _ = http
    peer = {"environ_base": {"REMOTE_ADDR": "203.0.113.9"}}
    spoof = {**peer, "headers": {"Host": "lab.example", "X-Remote-User": "alice"}}
    monkeypatch.setenv("AGENTSEC_CTF_ALLOW_GATEWAY", "1")
    assert c.get("/api/ctf/challenges", **spoof).status_code == 403                      # opt-in + header, no secret configured
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", "s3cret-shared-value-123")
    assert c.get("/api/ctf/challenges", **spoof).status_code == 403                      # secret configured, not presented
    for bad in ("wrong", "s3cret-shared-value-12", "", "s3cret-shared-value-1234"):
        assert c.get("/api/ctf/challenges", **peer, headers={"Host": "lab.example", "X-Remote-User": "a", "X-AgentSec-Gateway-Secret": bad}).status_code == 403
    assert c.get("/api/ctf/challenges", **peer, headers={"Host": "lab.example", "X-AgentSec-Gateway-Secret": "s3cret-shared-value-123"}).status_code == 403   # no identity
    ok = {**peer, "headers": {"Host": "lab.example", "X-Remote-User": "a", "X-AgentSec-Gateway-Secret": "s3cret-shared-value-123"}}
    assert c.get("/api/ctf/challenges", **ok).status_code == 200
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", "short")                           # too short to count as configured
    assert c.get("/api/ctf/challenges", **{**peer, "headers": {"Host": "x", "X-Remote-User": "a", "X-AgentSec-Gateway-Secret": "short"}}).status_code == 403


def test_gateway_secret_from_file(http, monkeypatch, tmp_path):
    c, _ = http
    f = tmp_path / "sec"
    f.write_text("  file-secret-value-9999 \n")
    os.chmod(f, 0o644)
    monkeypatch.setenv("AGENTSEC_CTF_ALLOW_GATEWAY", "1")
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET_FILE", str(f))
    h = {"Host": "x", "X-Remote-User": "a", "X-AgentSec-Gateway-Secret": "file-secret-value-9999"}
    assert c.get("/api/ctf/challenges", environ_base={"REMOTE_ADDR": "198.51.100.1"}, headers=h).status_code == 403   # group/world-readable file refused
    os.chmod(f, 0o600)
    assert c.get("/api/ctf/challenges", environ_base={"REMOTE_ADDR": "198.51.100.1"}, headers=h).status_code == 200
    monkeypatch.delenv("AGENTSEC_CTF_GATEWAY_SECRET_FILE")
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", "  file-secret-value-9999\n")                                 # env value is stripped too
    assert c.get("/api/ctf/challenges", environ_base={"REMOTE_ADDR": "198.51.100.1"}, headers=h).status_code == 200


def test_redeem_refuses_an_already_redeemed_attempt_even_with_a_fresh_receipt(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    assert svc.redeem(aid, r)[0] == 200
    fresh = receipts.issue(svc.store.key, attempt_id=aid, challenge_id=FAKE.id, run_ids=r["run_ids"], points=10, evidence_sha256="0" * 64, now=int(clock()))
    assert svc.redeem(aid, fresh) == (409, {"error": "already_redeemed"})


def test_ledger_truncation_and_rollback_fail_the_scoreboard_closed(tmp_path):
    svc, _ = make_service(tmp_path)
    a, r = verified(svc)
    svc.redeem(a, r)
    saved = svc.store.ledger_path.read_bytes()
    assert svc.scoreboard()["total"] == 10
    svc.store.ledger_path.write_bytes(b"")                                  # truncation
    board = svc.scoreboard()
    assert board["total"] == 0 and board["rows"] == [] and board["ledger_intact"] is False and "integrity" in board["error"]
    svc.store.ledger_path.write_bytes(saved)
    assert svc.scoreboard()["total"] == 10
    svc.store.head_path.unlink()                                            # head removed
    assert svc.scoreboard()["ledger_intact"] is False
    b, r2 = verified(svc)
    assert svc.redeem(b, r2)[0] == 200                                      # head missing with one valid line = crash window: healed, then spent once


def test_ledger_rollback_to_an_older_valid_prefix_is_detected(tmp_path):
    svc, _ = make_service(tmp_path, scenarios=None)
    svc.scenarios["fake-two"] = type("S", (FakeScenario,), {"challenge": type(FAKE)(**{**FAKE.__dict__, "id": "fake-two"})})()
    a, ra = verified(svc)
    svc.redeem(a, ra)
    older = svc.store.ledger_path.read_bytes()
    svc.store.ledger_path.write_bytes(older)
    code, aid2 = svc.start("fake-two")[0], svc.start("fake-two")[1]["attempt_id"]
    svc.run(aid2, {"posture": "baseline"})
    rb = svc.verify(aid2)[1]["receipt"]
    assert svc.redeem(aid2, rb)[0] == 200 and svc.scoreboard()["total"] == 20
    svc.store.ledger_path.write_bytes(older)                                # roll back to the valid one-line prefix
    assert svc.scoreboard()["ledger_intact"] is False and svc.scoreboard()["total"] == 0


def test_verify_replay_on_an_unredeemed_attempt_reissues_a_fresh_receipt(tmp_path):
    svc, clock = make_service(tmp_path)
    aid, r = verified(svc)
    clock.advance(receipts.RECEIPT_TTL_S + 5)
    assert svc.redeem(aid, r)[0] == 410
    again = svc.verify(aid)[1]
    assert again["replay"] and again["receipt"]["nonce"] != r["nonce"] and again["receipt"]["issued_at"] > r["issued_at"]
    assert svc.redeem(aid, r)[1]["error"] == "attempt_not_redeemable"       # the old receipt is dead
    assert svc.redeem(aid, again["receipt"])[0] == 200 and svc.scoreboard()["total"] == 10
    assert svc.verify(aid)[1]["receipt"]["nonce"] == again["receipt"]["nonce"]   # redeemed: no further re-issue


def test_concurrent_first_use_creates_one_complete_key(tmp_path):
    root = tmp_path / "race"
    keys, errs = [], []

    def go():
        try:
            keys.append(CtfStore(root).key)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    ts = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs and len(set(keys)) == 1 and len(keys[0]) == 32
    assert not list(root.glob(".key-*"))


def test_attempt_store_prunes_non_scoring_records_so_it_cannot_stay_full(tmp_path, monkeypatch):
    import agentsec.ctf.store as st
    monkeypatch.setattr(st, "MAX_ATTEMPTS", 4)
    svc, clock = make_service(tmp_path)
    for _ in range(3):
        a, r = verified(svc)                    # VERIFIED, never redeemed: non-scoring
        clock.advance(1)
    a, r = verified(svc)
    svc.redeem(a, r)                            # the one scoring record
    assert svc.start(FAKE.id)[0] == 201         # room made by pruning unredeemed VERIFIED history
    assert svc.store.load(a) is not None and svc.scoreboard()["total"] == 10


def test_ledger_stays_small_one_line_per_scored_challenge(tmp_path):
    svc, _ = make_service(tmp_path)
    for _ in range(5):
        a, r = verified(svc)
        svc.redeem(a, r)
    assert len(svc.store.read_ledger()[0]) == 1 and svc.scoreboard()["total"] == 10
    import agentsec.ctf.store as st
    assert st.MAX_ENTRIES_BYTES_OK if hasattr(st, "MAX_ENTRIES_BYTES_OK") else st.MAX_LEDGER_ENTRIES * 1200 <= st.MAX_LEDGER_BYTES


def test_crash_between_ledger_append_and_head_write_self_heals_without_double_spend(tmp_path, monkeypatch):
    svc, _ = make_service(tmp_path)
    aid, r = verified(svc)
    real = svc.store._write_head
    monkeypatch.setattr(svc.store, "_write_head", lambda *a: (_ for _ in ()).throw(OSError("simulated crash")))
    assert svc.redeem(aid, r)[0] == 503                                   # line appended, head not written, record not marked
    assert svc.scoreboard()["ledger_intact"] is False                     # fails closed until the retry heals it
    monkeypatch.setattr(svc.store, "_write_head", real)
    code, body = svc.redeem(aid, r)                                       # same receipt retried
    assert code == 200 and body["awarded"] == 10
    board = svc.scoreboard()
    assert board["total"] == 10 and board["ledger_intact"] is True and len(svc.store.read_ledger()[0]) == 1
    assert svc.redeem(aid, r) == (409, {"error": "already_redeemed"})


def test_a_second_receipt_after_a_crash_heals_the_head_and_the_chain_continues(tmp_path, monkeypatch):
    svc, _ = make_service(tmp_path)
    svc.scenarios["fake-two"] = type("S", (FakeScenario,), {"challenge": type(FAKE)(**{**FAKE.__dict__, "id": "fake-two"})})()
    a, ra = verified(svc)
    svc.redeem(a, ra)
    svc.start("fake-two")
    b = svc.start("fake-two")[1]["attempt_id"]
    svc.run(b, {"posture": "baseline"})
    rb = svc.verify(b)[1]["receipt"]
    real = svc.store._write_head
    monkeypatch.setattr(svc.store, "_write_head", lambda *a: (_ for _ in ()).throw(OSError("x")))
    assert svc.redeem(b, rb)[0] == 503
    monkeypatch.setattr(svc.store, "_write_head", real)
    assert svc.redeem(b, rb)[0] == 200 and svc.scoreboard()["total"] == 20 and svc.scoreboard()["ledger_intact"]


def test_a_head_two_behind_or_tampered_does_not_self_heal(tmp_path):
    svc, _ = make_service(tmp_path)
    a, ra = verified(svc)
    svc.redeem(a, ra)
    head = json.loads(svc.store.head_path.read_text())
    head["count"] = 0
    svc.store.head_path.write_text(json.dumps(head))                      # MAC no longer matches
    b, rb = verified(svc)
    assert svc.redeem(b, rb)[1]["error"] == "ledger_integrity_failed"
