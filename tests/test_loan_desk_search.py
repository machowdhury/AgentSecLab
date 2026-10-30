"""Notebook search gateway: fixed templates, validated parameters, verifier-built SPL, bounded signed results, read-only isolation."""

from __future__ import annotations

import os
import subprocess

import pytest

from agentsec.loan_desk import search as srch
from agentsec.loan_desk import verify_bridge as vb
from agentsec.loan_desk.verifier import process_searches

RUN = "00000000-0000-4000-8000-000000000001"
KEY = b"k" * 32


class FakeBackend:
    name = "fake"

    def __init__(self, outcome=None):
        self.calls, self.outcome = [], outcome or srch.Outcome(True, ["event.name", "events"], [["agentsec.run.completed", "1"]], False, None, 7)

    def run(self, spl, *, timeout_s, max_rows):
        self.calls.append((spl, timeout_s, max_rows))
        return self.outcome


@pytest.fixture()
def bridge(tmp_path, monkeypatch):
    monkeypatch.setenv(vb.ISOLATION_ENV, "off")  # in-process: the real isolation is a read-only mount (covered below)
    d = tmp_path / "loan_desk"
    (d / vb.RECEIPTS).mkdir(parents=True)
    vb.heartbeat_state  # noqa: B018
    return d


def test_spl_is_built_from_the_template_with_run_constraint_and_validated_params():
    spl, clean = srch.get_template("events_by_field").build(RUN, {"field": "gen_ai.tool.name", "limit": 7})
    assert spl.startswith('index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-24h "agentsec.run.id"="' + RUN + '"')
    assert "'gen_ai.tool.name'" in spl and spl.endswith("| head 7") and clean == {"field": "gen_ai.tool.name", "limit": 7}


@pytest.mark.parametrize("tpl,params", [
    ("nope", {}), ("events_by_field", {"field": "_raw"}), ("events_by_field", {"field": 'event.name" | delete'}), ("events_by_field", {"limit": 51}),
    ("events_by_field", {"limit": "5"}), ("events_by_field", {"limit": True}), ("events_by_field", {"extra": 1}), ("events_by_field", "x"),
])
def test_bad_templates_and_parameters_are_refused(tpl, params):
    with pytest.raises(srch.SearchError):
        srch.get_template(tpl).build(RUN, params)


@pytest.mark.parametrize("run", ["", "x", "AAAAAAAA-0000-4000-8000-000000000001", RUN + " | delete", "../" + RUN])
def test_run_id_must_be_a_lowercase_uuid(run):
    with pytest.raises(srch.SearchError):
        srch.get_template("events_by_field").build(run, {})


def test_docker_backend_passes_spl_as_env_not_shell_text():
    seen = {}
    def runner(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        return subprocess.CompletedProcess(argv, 0, "event.name,events\nx,1\n", "")
    spl = 'index=a "$(touch /tmp/pwn)" ";id" "$IFS"'
    out = srch.DockerExecBackend("c1", runner).run(spl, timeout_s=9, max_rows=5)
    argv = seen["argv"]
    assert out.ok and out.rows == [["x", "1"]] and argv[0] == "docker" and "AGENTSEC_SPL=" + spl in argv
    script = argv[-1]
    assert "touch" not in script and "$AGENTSEC_SPL" in script and "-max_time 9" in script and "-maxout 6" in script
    assert seen["kw"].get("shell") is not True and seen["kw"]["timeout"] == 14


def test_docker_backend_applies_the_read_only_policy_before_running_anything():
    calls = []
    out = srch.DockerExecBackend("c1", lambda argv, **kw: calls.append(argv)).run("index=a | outputlookup x.csv", timeout_s=9, max_rows=5)
    assert not out.ok and out.error == "search_failed" and calls == []


def test_backend_failure_codes_are_fixed_strings():
    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)
    assert srch.DockerExecBackend("c1", boom).run("x", timeout_s=1, max_rows=1).error == "timeout"
    bad = lambda a, **k: subprocess.CompletedProcess(a, 1, "", "secret detail")  # noqa: E731
    o = srch.DockerExecBackend("c1", bad).run("x", timeout_s=1, max_rows=1)
    assert (o.ok, o.error) == (False, "search_failed") and "secret" not in repr(o)


def test_results_are_bounded_plain_strings():
    big = "a" * 5000
    text = "WARNING: x\nc1,c2\n" + "\n".join(f'{big},{i}' for i in range(200))
    cols, rows, trunc = srch.shape_csv(text)
    assert cols == ["c1", "c2"] and len(rows) == srch.MAX_ROWS and trunc and len(rows[0][0]) == srch.MAX_CELL


def _request(d, **over):
    code, det = vb.request_search(d, RUN, over.pop("template", "events_by_field"), over.pop("params", {"field": "event.name", "limit": 5}))
    assert code == "REQUESTED"
    return det["search_id"]


def test_verifier_answers_with_a_signed_bounded_receipt_and_builds_the_spl_itself(bridge):
    sid = _request(bridge)
    be = FakeBackend()
    assert process_searches(bridge, KEY, backend=be) == [sid]
    spl, timeout_s, rows = be.calls[0]
    assert RUN in spl and timeout_s == srch.SEARCH_TIMEOUT_S and rows == srch.MAX_ROWS
    receipt = vb.read_json_safe(bridge / vb.RECEIPTS / "search" / f"{sid}.json", vb.MAX_SEARCH_FILE_BYTES)
    assert vb.verify(KEY, receipt) and receipt["spl"] == spl and receipt["rows"] == [["agentsec.run.completed", "1"]]
    assert vb.search_status(bridge, RUN, sid)["status"] == "READY"
    assert process_searches(bridge, KEY, backend=be) == []  # answered once


def test_verifier_never_trusts_the_request_for_template_or_params(bridge):
    sdir = bridge / vb.REQUESTS / "search"
    vb.write_json_atomic(sdir / "00000000000000aa.json", {"run_id": RUN, "search_id": "00000000000000aa", "template": "events_by_field",
                          "params": {"field": "_raw | delete index=*"}, "requested_at": __import__("time").time()})
    be = FakeBackend()
    assert process_searches(bridge, KEY, backend=be) == ["00000000000000aa"] and be.calls == []
    st = vb.search_status(bridge, RUN, "00000000000000aa")
    assert st["status"] == "FAILED" and st["error"] == "refused"


def test_malformed_and_foreign_search_requests_are_quarantined_or_ignored(bridge):
    sdir = bridge / vb.REQUESTS / "search"
    vb.write_json_atomic(sdir / "00000000000000bb.json", {"run_id": RUN, "search_id": "00000000000000bb", "template": "t", "params": {}, "requested_at": 1, "extra": 1})
    be = FakeBackend()
    assert process_searches(bridge, KEY, backend=be) == [] and be.calls == [] and not (sdir / "00000000000000bb.json").exists()


def test_status_requires_the_request_to_belong_to_the_run(bridge):
    sid = _request(bridge)
    other = "11111111-2222-3333-4444-555555555555"
    assert vb.search_status(bridge, other, sid)["status"] == "UNKNOWN_SEARCH"


def test_writable_receipts_refuse_results(bridge, monkeypatch):
    sid = _request(bridge)
    monkeypatch.delenv(vb.ISOLATION_ENV)
    if os.access(bridge / vb.RECEIPTS, os.W_OK):
        assert vb.search_status(bridge, RUN, sid)["status"] == "UNAVAILABLE"


def test_per_run_rate_limit(bridge):
    codes = [vb.request_search(bridge, RUN, "events_by_field", {})[0] for _ in range(vb.SEARCH_PER_RUN_PER_MIN + 2)]
    assert codes[: vb.SEARCH_PER_RUN_PER_MIN] == ["REQUESTED"] * vb.SEARCH_PER_RUN_PER_MIN and codes[-1] == "RATE_LIMITED"


def test_no_verifier_means_not_installed_not_a_fake_result(tmp_path):
    assert vb.request_search(tmp_path / "loan_desk", RUN, "events_by_field", {})[0] == "NOT_INSTALLED"


OTHER = "11111111-2222-3333-4444-555555555555"


def test_every_template_builds_with_the_run_constraint_and_only_validated_text():
    for t in srch.TEMPLATES.values():
        spl, _ = t.build(RUN, {}, OTHER if t.runs == 2 else None)
        assert spl.startswith("index=agentsec_telemetry sourcetype=\"otel:agentic:json\" earliest=-24h") and RUN in spl
        assert (OTHER in spl) == (t.runs == 2) and "{" not in spl and "|  " not in spl


def test_comparisons_need_two_distinct_runs_and_single_run_templates_refuse_a_second():
    cmp_ = srch.TEMPLATES["compare_decisions"]
    for other in (None, RUN, "x", 5, "AAAAAAAA-2222-3333-4444-555555555555"):
        with pytest.raises(srch.SearchError):
            cmp_.build(RUN, {}, other)
    with pytest.raises(srch.SearchError):
        srch.TEMPLATES["decisions"].build(RUN, {}, OTHER)


def test_comparison_request_round_trips_through_the_verifier(bridge):
    code, det = vb.request_search(bridge, RUN, "compare_decisions", {"limit": 5}, compare_run=OTHER)
    assert code == "REQUESTED"
    be = FakeBackend(srch.Outcome(True, ["tool", "verdict", "baseline", "defended"], [["t", "ALLOW / x", "1", "0"]], False, None, 3))
    assert process_searches(bridge, KEY, backend=be) == [det["search_id"]] and OTHER in be.calls[0][0]
    st = vb.search_status(bridge, RUN, det["search_id"])
    assert st["status"] == "READY" and st["compare_run_id"] == OTHER


def test_a_forged_comparison_request_with_a_bad_second_run_is_quarantined(bridge):
    sdir = bridge / vb.REQUESTS / "search"
    vb.write_json_atomic(sdir / "00000000000000cc.json", {"run_id": RUN, "search_id": "00000000000000cc", "template": "compare_decisions", "params": {},
                          "requested_at": __import__("time").time(), "compare_run_id": "../etc/passwd"})
    be = FakeBackend()
    assert process_searches(bridge, KEY, backend=be) == [] and be.calls == []
