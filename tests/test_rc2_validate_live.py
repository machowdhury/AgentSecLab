"""The Checkpoint 6 validator, tested offline: it must pass when Splunk's rows equal the in-memory twin and fail when they do not, and it must never print a credential."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from agentsec import splunk_client as sc
from agentsec.academy_assurance import AssuranceService
from agentsec.academy_investigation import CELLS, InvestigationService
from agentsec.loan_desk import search as srch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rc2_validate_live", ROOT / "scripts/rc2_validate_live.py")
V = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(V)


def a_live_like_finding():
    svc = AssuranceService()
    ds = svc._recorded()                                           # the recorded runs stand in for events read from Splunk: the comparison is the same
    f = next(x for x in ds.findings if x["mode"] == "ATTACK" and x["hop"] is not None)
    return svc, ds, f


def twin_remote(ds, f):
    """What a correct Splunk returns: the same rows, with Splunk's formatting (multivalue joined by newlines, booleans lowercase, extra whitespace)."""
    inv = InvestigationService(AssuranceService(), None)
    ctx = inv._ctx(f)
    table = {cell.spl(ctx, cell.clean(ctx, {k: v for k, v in p.items() if k in {q["name"] for q in cell.params(ctx)}})): (cell, p) for cell in CELLS.values()
             for p in ({"scope": "run", "limit": 50}, {"limit": 50})}

    def run(spl):
        cell, p = table[spl]
        clean = cell.clean(ctx, {k: v for k, v in p.items() if k in {q["name"] for q in cell.params(ctx)}})
        rows = [[v.replace(", ", "\n") for v in r] for r in cell.local(ds.runs[f["run_id"]]["events"], ctx, clean)]
        return list(cell.columns), rows
    return run


def test_parity_passes_when_splunks_rows_equal_the_twin_in_splunks_formatting():
    svc, ds, f = a_live_like_finding()
    out = V.parity_for_run(InvestigationService(svc, None), ds, f, twin_remote(ds, f))
    assert out and all(r["status"] == "PASS" for r in out), out
    assert {r["cell"] for r in out} == set(CELLS)


def test_parity_fails_on_a_changed_row_a_missing_row_and_changed_columns():
    svc, ds, f = a_live_like_finding()
    ok = twin_remote(ds, f)
    inv = InvestigationService(svc, None)
    changed = lambda spl: (lambda c, r: (c, [[*r[0][:-1], "CHANGED"], *r[1:]] if r else r))(*ok(spl))
    dropped = lambda spl: (lambda c, r: (c, r[:-1]))(*ok(spl))
    renamed = lambda spl: (lambda c, r: (["x"] * len(c), r))(*ok(spl))
    for broken in (changed, dropped, renamed):
        out = V.parity_for_run(inv, ds, f, broken)
        assert any(r["status"] == "FAIL" for r in out), broken


def test_index_isolation_needs_a_refusal_or_an_explicit_zero_and_nothing_else():
    class C:
        def __init__(self, text=None, err=None): self.text, self.err = text, err
        def export_csv(self, spl, *, timeout_s=None, max_bytes=None):
            if self.err: raise self.err
            return self.text
    assert V.check_index_isolation(C("count\n0\n"))["status"] == "PASS"
    assert V.check_index_isolation(C('"count"\n"0"\n'))["status"] == "PASS"
    assert V.check_index_isolation(C(err=sc.SplunkError("authorization", "forbidden")))["status"] == "PASS"
    assert V.check_index_isolation(C("count\n5\n"))["status"] == "FAIL"
    assert V.check_index_isolation(C(""))["status"] == "FAIL"
    assert V.check_index_isolation(C(err=sc.SplunkError("connectivity", "connect_failed")))["status"] == "FAIL"


def test_empty_result_must_be_a_successful_search_and_old_credentials_need_a_file(tmp_path):
    class Empty:
        def export_csv(self, spl, *, timeout_s=None, max_bytes=None): return "_raw\n"
    class Broken:
        def export_csv(self, spl, *, timeout_s=None, max_bytes=None): raise sc.SplunkError("authentication", "auth_failed")
    assert V.check_empty_vs_denied(Empty(), None)["status"] == "NOT_RUN"
    assert V.check_empty_vs_denied(Broken(), None)["status"] == "FAIL"              # a refusal is not an empty result
    assert V.check_old_credential(None, None)["status"] == "NOT_RUN"


def test_main_without_provisioned_access_fails_closed_and_writes_no_secret(tmp_path, monkeypatch, capsys):
    for k in ("AGENTSEC_SPLUNK_ACCESS_DIR", "AGENTSEC_SPLUNK_REST_URL"):
        monkeypatch.delenv(k, raising=False)
    assert V.main(["--out", str(tmp_path)]) == 1
    report = json.loads((tmp_path / "rc2_validate_live.json").read_text())
    assert report["access"]["status"] == "FAIL" and "index_isolation" not in report and report["old_credential"]["status"] == "NOT_RUN"
    assert "provisioned" in capsys.readouterr().out
