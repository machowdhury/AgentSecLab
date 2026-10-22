"""Batch 6 verifier security and lifecycle. Replaces the Batch 5 strict-xfail probes: each defect is now a passing test.

Process tests start the real scripts against scratch directories (never the running lab's artifacts or state).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from agentsec.loan_desk import verifier, verify_bridge as vb

ROOT = Path(__file__).resolve().parents[1]
SH = ROOT / "scripts" / "loan_desk_verifier.sh"
EV = [{"agentsec.sequence": 1, "event.name": "x"}]
OK = lambda rid, ev, timeout_s=45: {"reconciled": True, "problems": [], "local_events": 1, "indexed_events": 1}  # noqa: E731


@pytest.fixture
def d(tmp_path):
    d = vb.bridge_dir(tmp_path / "art")
    (d / vb.RECEIPTS).mkdir(parents=True)
    (d / vb.REQUESTS).mkdir()
    return d


@pytest.fixture
def key():
    return vb.load_or_create_key(vb.state_dir())


def run(d, key, **kw):
    return verifier.process_once(d, key, origin="x", fetch=lambda o, r: EV, reconcile=OK, **kw)


# ---- trust boundary
def test_key_is_outside_the_artifacts_tree_private_and_never_in_a_mounted_path(tmp_path, d, key):
    state = vb.state_dir()
    assert (state / "receipt.key").stat().st_mode & 0o777 == 0o600 and state.stat().st_mode & 0o777 == 0o700
    assert tmp_path / "art" not in state.parents and not any(p.name.startswith(".bridge") or p.suffix == ".key" for p in d.rglob("*"))


def test_isolation_check_refuses_verified_when_receipts_are_writable_from_the_container(d, key, monkeypatch):
    monkeypatch.delenv(vb.ISOLATION_ENV, raising=False)  # enforce
    rid = str(uuid.uuid4())
    verifier.heartbeat(d, key, 1)
    vb.request_verification(d, rid)
    run(d, key)
    assert not vb.receipts_isolated(d)  # we can write here, exactly like a container with a writable mount
    s = vb.splunk_status(d, rid, 1)
    assert s["status"] == "NOT_VERIFIED" and "writable" in s["detail"]
    assert vb.heartbeat_state(d) == "OFFLINE"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_read_only_receipts_dir_allows_verified_and_blocks_any_forgery(d, key, monkeypatch):
    monkeypatch.delenv(vb.ISOLATION_ENV, raising=False)
    rid = str(uuid.uuid4())
    verifier.heartbeat(d, key, 1)
    vb.request_verification(d, rid)
    run(d, key)
    os.chmod(d / vb.RECEIPTS, 0o555)  # what the read-only bind mount does inside the container
    try:
        assert vb.receipts_isolated(d) and vb.splunk_status(d, rid, 1)["status"] == "SPLUNK_VERIFIED"
        with pytest.raises(PermissionError):  # the "compromised container" cannot create or replace a receipt
            vb.write_json_atomic(d / vb.RECEIPTS / f"{rid}.splunk.json", {"run_id": rid, "nonce": "x", "reconciled": True})
        other = str(uuid.uuid4())
        with pytest.raises(PermissionError):
            vb.write_json_atomic(d / vb.RECEIPTS / f"{other}.splunk.json", {"run_id": other})
    finally:
        os.chmod(d / vb.RECEIPTS, 0o755)


def test_receipt_at_rest_is_checked_with_the_host_key_only(d, key, tmp_path):
    rid = str(uuid.uuid4())
    vb.request_verification(d, rid)
    run(d, key)
    path = d / vb.RECEIPTS / f"{rid}.splunk.json"
    assert verifier.check_receipt(path, key)[0]
    assert not verifier.check_receipt(path, b"z" * 32)[0]
    doc = vb.read_json_safe(path)
    vb.write_json_atomic(path, {**doc, "reconciled": False if doc["reconciled"] else True})
    ok, msg = verifier.check_receipt(path, key)
    assert not ok and "does not verify" in msg


# ---- malformed input never kills the verifier
@pytest.mark.parametrize("over", [{"requested_at": "abc"}, {"requested_at": None}, {"requested_at": float("nan")},
                                  {"requested_at": True}, {"nonce": None}, {"nonce": 7}, {"nonce": "ZZ"}, {"extra": 1}])
def test_malformed_requests_are_quarantined_not_fatal(d, key, over):
    rid = str(uuid.uuid4())
    body = {"run_id": rid, "requested_at": time.time(), "nonce": "aabbccdd", **over}
    vb.write_json_atomic(d / vb.REQUESTS / f"{rid}.json", body)
    good = str(uuid.uuid4())
    vb.write_json_atomic(d / vb.REQUESTS / f"{good}.json", {"run_id": good, "requested_at": time.time(), "nonce": "aabbccee"})
    assert run(d, key) == [good]  # the good one is still served
    assert not (d / vb.REQUESTS / f"{rid}.json").exists() and any((d / "rejected").iterdir())


def test_symlink_fifo_oversize_and_binary_requests_are_never_followed(d, key, tmp_path):
    secret = tmp_path / "elsewhere.json"
    rid1 = str(uuid.uuid4())
    secret.write_text('{"run_id": "%s", "requested_at": %s, "nonce": "aabbccdd"}' % (rid1, time.time()))
    os.symlink(secret, d / vb.REQUESTS / f"{rid1}.json")
    rid2 = str(uuid.uuid4())
    os.mkfifo(d / vb.REQUESTS / f"{rid2}.json")
    rid3 = str(uuid.uuid4())
    (d / vb.REQUESTS / f"{rid3}.json").write_bytes(b"\xff" * 5_000_000)
    rid4 = str(uuid.uuid4())
    (d / vb.REQUESTS / f"{rid4}.json").write_text("{" * 100000)
    t = time.time()
    assert run(d, key) == [] and time.time() - t < 5


def test_one_bad_fetch_or_write_error_does_not_stop_the_other_requests(d, key):
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    for r, n in ((a, "aabbccd1"), (b, "aabbccd2")):
        vb.write_json_atomic(d / vb.REQUESTS / f"{r}.json", {"run_id": r, "requested_at": time.time(), "nonce": n})
    def fetch(o, r):
        if r == min(a, b):
            raise RuntimeError("boom")
        return EV
    assert verifier.process_once(d, key, origin="x", fetch=fetch, reconcile=OK) == [max(a, b)]


def test_nonce_memory_is_bounded(d, key):
    import collections
    seen = collections.OrderedDict((f"n{i}", 0) for i in range(verifier.MAX_SEEN + 50))
    rid = str(uuid.uuid4())
    vb.write_json_atomic(d / vb.REQUESTS / f"{rid}.json", {"run_id": rid, "requested_at": time.time(), "nonce": "aabbccdd"})
    run(d, key, seen=seen)
    assert len(seen) <= verifier.MAX_SEEN


# ---- atomic publication
def test_writes_use_unique_temp_names_and_leave_no_partial_files(tmp_path):
    names = []
    real = os.replace
    os.replace = lambda a, b: (names.append(Path(a).name), real(a, b))[1]
    try:
        for i in range(3):
            vb.write_json_atomic(tmp_path / "x.json", {"i": i})
    finally:
        os.replace = real
    assert len(set(names)) == 3 and [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_a_failed_write_cleans_its_temp_file_and_keeps_the_old_content(tmp_path):
    vb.write_json_atomic(tmp_path / "x.json", {"v": 1})
    with pytest.raises(TypeError):
        vb.write_json_atomic(tmp_path / "x.json", {"v": object()})
    assert vb.read_json_safe(tmp_path / "x.json") == {"v": 1} and [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_concurrent_writers_never_corrupt_the_published_file(tmp_path):
    import threading
    errs = []
    def w(n):
        try:
            for i in range(60):
                vb.write_json_atomic(tmp_path / "c.json", {"w": n, "i": i})
        except Exception as e:  # noqa: BLE001
            errs.append(e)
    ts = [threading.Thread(target=w, args=(n,)) for n in range(6)]
    [t.start() for t in ts]
    stop = time.time() + 3
    while any(t.is_alive() for t in ts) and time.time() < stop:
        assert vb.read_json_safe(tmp_path / "c.json") in (None, *[{"w": n, "i": i} for n in range(6) for i in range(60)])
    [t.join() for t in ts]
    assert not errs and vb.read_json_safe(tmp_path / "c.json")["i"] == 59


# ---- process lifecycle (real scripts, scratch dirs)
@pytest.fixture
def lab(tmp_path):
    env = {**os.environ, "AGENTSEC_ARTIFACTS_HOST_DIR": str(tmp_path / "art"), "AGENTSEC_VERIFIER_STATE_DIR": str(tmp_path / "state"),
           "PYTHON": sys.executable, "ACMEBANK_ORIGIN": "http://127.0.0.1:1"}
    yield env, tmp_path
    subprocess.run(["sh", str(SH), "stop"], env=env, capture_output=True)


def sh(env, cmd):
    return subprocess.run(["sh", str(SH), cmd], env=env, capture_output=True, text=True, timeout=30)


def pid_of(tmp):
    return int((tmp / "state" / "verifier.pid").read_text())


def test_start_status_stop_and_clean_shutdown_marks_the_heartbeat_stopped(lab):
    env, tmp = lab
    if subprocess.run(["which", "docker"], capture_output=True).returncode:
        pytest.skip("start refuses without docker on PATH")
    assert "started" in sh(env, "start").stdout and "running" in sh(env, "status").stdout
    hb = vb.read_json_safe(tmp / "art" / "loan_desk" / "receipts" / "verifier.json")
    assert hb and hb["state"] == "running"
    p = pid_of(tmp)
    assert "stopped" in sh(env, "stop").stdout
    with pytest.raises(ProcessLookupError):
        os.kill(p, 0)
    assert vb.read_json_safe(tmp / "art" / "loan_desk" / "receipts" / "verifier.json")["state"] == "stopped"
    assert not (tmp / "state" / "verifier.pid").exists() and "not running" in sh(env, "status").stdout


def test_concurrent_starts_leave_exactly_one_verifier_and_a_correct_pidfile(lab):
    env, tmp = lab
    if subprocess.run(["which", "docker"], capture_output=True).returncode:
        pytest.skip("start refuses without docker on PATH")
    procs = [subprocess.Popen(["sh", str(SH), "start"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    [p.wait(timeout=30) for p in procs]
    time.sleep(1.5)
    out = subprocess.run(["pgrep", "-f", f"loan_desk_verifier.py --artifacts {tmp}/art"], capture_output=True, text=True).stdout.split()
    assert len(out) == 1 and int(out[0]) == pid_of(tmp)
    assert "Traceback" not in (tmp / "state" / "verifier.log").read_text()


def test_kill9_leaves_a_stale_pidfile_that_status_ignores_and_start_replaces(lab):
    env, tmp = lab
    if subprocess.run(["which", "docker"], capture_output=True).returncode:
        pytest.skip("start refuses without docker on PATH")
    sh(env, "start")
    old = pid_of(tmp)
    os.kill(old, signal.SIGKILL)
    time.sleep(0.5)
    assert "not running" in sh(env, "status").stdout
    assert "started" in sh(env, "start").stdout and pid_of(tmp) != old


def test_stop_never_signals_an_unrelated_process_with_a_stale_pidfile(lab):
    env, tmp = lab
    victim = subprocess.Popen(["sleep", "60"])
    try:
        (tmp / "state").mkdir(exist_ok=True)
        (tmp / "state" / "verifier.pid").write_text(str(victim.pid))
        out = sh(env, "stop")
        time.sleep(0.3)
        assert victim.poll() is None and "stale pidfile ignored" in out.stdout
        assert "not running" in sh(env, "status").stdout
    finally:
        victim.kill()
        victim.wait()


def test_a_garbage_pidfile_is_harmless(lab):
    env, tmp = lab
    (tmp / "state").mkdir(exist_ok=True)
    for junk in ("", "abc", "1; rm -rf /", "-1", "0"):
        (tmp / "state" / "verifier.pid").write_text(junk)
        assert sh(env, "stop").returncode == 0


def test_crash_recovery_a_restarted_verifier_answers_requests_left_pending(lab, monkeypatch):
    env, tmp = lab
    d = vb.bridge_dir(tmp / "art")
    key_dir = tmp / "state"
    key_dir.mkdir(exist_ok=True)
    os.chmod(key_dir, 0o700)
    monkeypatch.setenv("AGENTSEC_VERIFIER_STATE_DIR", str(key_dir))
    key = vb.load_or_create_key(key_dir)
    (d / vb.RECEIPTS).mkdir(parents=True)
    rid = str(uuid.uuid4())
    vb.request_verification(d, rid)  # request made while no verifier runs
    run(d, key)  # a verifier answers after "restart"
    assert vb.read_json_safe(d / vb.RECEIPTS / f"{rid}.splunk.json")["reconciled"] is True


def test_replayed_request_is_not_answered_twice(d, key):
    rid = str(uuid.uuid4())
    vb.request_verification(d, rid)
    assert run(d, key) == [rid]
    saved = vb.read_json_safe(d / vb.REQUESTS / f"{rid}.json")
    vb.write_json_atomic(d / vb.REQUESTS / f"{rid}.json", saved)  # same nonce re-presented
    assert run(d, key) == []


def test_compose_mounts_receipts_read_only_and_never_sets_the_isolation_override():
    import re
    c = (ROOT / "docker-compose.yml").read_text()
    assert len(re.findall(r"\./artifacts/loan_desk/receipts:/app/artifacts/loan_desk/receipts:ro", c)) == 2
    assert vb.ISOLATION_ENV not in c and "receipt.key" not in c and ".bridge.key" not in c
    assert "internal" not in vb.ISOLATION_ENV  # sanity: the env name is the only override
