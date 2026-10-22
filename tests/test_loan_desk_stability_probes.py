"""Batch 5 stability probes: known verifier/bridge defects, pinned as strict xfails.

Each test states the SAFE behaviour. It fails today (xfail, strict), so the suite stays green and the test turns
red-on-purpose the day someone fixes the defect and should delete the marker. Findings: docs/reviews/batch5/STABILITY_FINDINGS.md.
"""
from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from agentsec.loan_desk import verifier as V
from agentsec.loan_desk import verify_bridge as vb

ROOT = Path(__file__).resolve().parents[1]


def _answer(d, key):
    return V.process_once(d, key, origin="http://127.0.0.1:1", fetch=lambda o, r: [{"agentsec.sequence": 1, "event.name": "x"}],
                          reconcile=lambda r, e, timeout_s: {"reconciled": True, "problems": [], "local_events": 1, "indexed_events": 1})


@pytest.mark.xfail(strict=True, reason="B5-V1: a validly signed request with a malformed field raises out of process_once and kills the loop")
@pytest.mark.parametrize("over", [{"requested_at": "abc"}, {"requested_at": None}, {"nonce": None}])
def test_malformed_signed_request_is_skipped_not_fatal(tmp_path, over):
    d = tmp_path / "loan_desk"
    key = vb.ensure_key(d)
    rid = str(uuid.uuid4())
    body = {"run_id": rid, "requested_at": time.time(), "nonce": "n"}
    body.update(over)
    body = {k: v for k, v in body.items() if v is not None or k != "nonce"}
    vb._write_json(d / "requests" / f"{rid}.json", vb.sign(key, body))
    _answer(d, key)  # must not raise


@pytest.mark.xfail(strict=True, reason="B5-V2: a symlinked request file is followed")
def test_symlinked_request_is_ignored(tmp_path):
    d = tmp_path / "loan_desk"
    key = vb.ensure_key(d)
    rid = str(uuid.uuid4())
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(__import__("json").dumps(vb.sign(key, {"run_id": rid, "requested_at": time.time(), "nonce": "z"})))
    (d / "requests").mkdir(parents=True)
    os.symlink(elsewhere, d / "requests" / f"{rid}.json")
    assert rid not in _answer(d, key)


@pytest.mark.xfail(strict=True, reason="B5-V3: heartbeat and result writers share one fixed .tmp name, so two writers race")
def test_atomic_write_uses_a_unique_temp_name(tmp_path):
    seen = []
    real = os.replace
    try:
        os.replace = lambda a, b: (seen.append(Path(a).name), real(a, b))[1]
        vb._write_json(tmp_path / "x.json", {"a": 1})
        vb._write_json(tmp_path / "x.json", {"a": 2})
    finally:
        os.replace = real
    assert len(set(seen)) == 2


@pytest.mark.xfail(strict=True, reason="B5-V4: `stop` signals whatever process now owns the pidfile's pid")
def test_stop_does_not_kill_an_unrelated_process(tmp_path):
    victim = subprocess.Popen(["sleep", "60"])
    try:
        d = tmp_path / "loan_desk"
        d.mkdir()
        (d / "verifier.pid").write_text(str(victim.pid))
        subprocess.run(["sh", str(ROOT / "scripts" / "loan_desk_verifier.sh"), "stop"], env={**os.environ, "AGENTSEC_ARTIFACTS_HOST_DIR": str(tmp_path)},
                       capture_output=True, check=False)
        time.sleep(0.3)
        assert victim.poll() is None
    finally:
        victim.kill()
        victim.wait()
