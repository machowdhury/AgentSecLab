#!/usr/bin/env python3
"""RC2 Checkpoint 6 checks, run ON the lab host after the installer ran and the LIVE workshops were launched. It uses the same access the Attack Service uses
(AGENTSEC_SPLUNK_ACCESS_DIR + AGENTSEC_SPLUNK_REST_URL), so it exercises the real strict-TLS client against the real Splunk. Nothing is changed in Splunk.

  python scripts/rc2_validate_live.py --out DIR [--old-credential-file FILE] [--max-findings N]

Checks (each PASS / FAIL / NOT_RUN, with the reason; the exit code is 1 when anything FAILs):
  access            the provisioned identity can search.
  index_isolation   it cannot read another index (a refusal or an explicit zero count; silence is a FAIL).
  empty_vs_denied   an unknown run id is an EMPTY result, and a wrong credential is a refusal (never an empty result).
  notebook_parity   for every LIVE finding and every investigation cell, the rows Splunk returns for the fixed SPL equal the rows read from the same run's events
                    (what a RECORDED or fixture cell shows), so a live cell and its in-memory twin agree.
  old_credential    (with --old-credential-file, after `./agentsec splunk-access --force`) whether the previous credential still works.
No credential is printed or written to the report.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec import splunk_client as sc  # noqa: E402
from agentsec.academy_assurance import AssuranceService  # noqa: E402
from agentsec.academy_investigation import CELLS, InvestigationService  # noqa: E402
from agentsec.loan_desk import search as srch  # noqa: E402

Result = dict


def res(status: str, why: str = "", **extra) -> Result:
    return {"status": status, "why": why, **extra}


def normalize(columns: list[str], rows: list[list[str]]) -> list[tuple]:
    """Splunk joins a multivalue field with newlines, the in-memory twin with commas, and Splunk may or may not trim: compare as sorted sets of lowercase tokens per cell."""
    def cell(v: str) -> str:
        return ",".join(sorted(t.strip().lower() for t in re.split(r"[\n,]", v or "") if t.strip()))
    return sorted(tuple(cell(v) for v in r) for r in rows)


def check_access(client) -> Result:
    try:
        rows = client.export_rows("| makeresults count=1 | eval ok=1", timeout_s=30, max_rows=2)
    except sc.SplunkError as exc:
        return res("FAIL", f"{exc.stage}/{exc.code}")
    return res("PASS") if rows and str(rows[0].get("ok")) == "1" else res("FAIL", "the probe search returned no ok=1 row")


def check_index_isolation(client) -> Result:
    try:
        text = client.export_csv("search index=_internal earliest=-1h | head 1 | stats count", timeout_s=30)
    except sc.SplunkError as exc:
        return res("PASS", f"refused ({exc.stage}/{exc.code})") if exc.stage in ("authentication", "authorization") or exc.code in ("forbidden", "bad_search") else res("FAIL", f"{exc.stage}/{exc.code}: not a refusal")
    lines = [ln.strip() for ln in text.strip().splitlines()]
    return res("PASS", "explicit zero count") if lines[:2] == ["count", "0"] or lines[:2] == ['"count"', '"0"'] else res("FAIL", "the other-index probe did not return an explicit zero")


def check_empty_vs_denied(client, cfg: sc.SplunkConfig | None) -> Result:
    spl = f'index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-1h "agentsec.run.id"="{uuid.uuid4()}" | head 1 | table _raw'
    try:
        empty = srch.RestBackend(client).run(spl, timeout_s=30, max_rows=5)
    except Exception as exc:  # noqa: BLE001
        return res("FAIL", f"the empty-result probe raised {exc.__class__.__name__}")
    if not (empty.ok and empty.rows == []):
        return res("FAIL", f"an unknown run id should be an empty successful result, got ok={empty.ok} error={empty.error}")
    if cfg is None:
        return res("NOT_RUN", "no SplunkConfig to build a wrong-credential client from")
    bad = sc.SplunkRestClient(dataclasses.replace(cfg, token="x" * len(cfg.token or "x") if cfg.auth == "bearer" else "wrong-password-" + "x" * 8))
    denied = srch.RestBackend(bad).run(spl, timeout_s=30, max_rows=5)
    if denied.ok:
        return res("FAIL", "a wrong credential was accepted")
    return res("PASS", f"empty result is ok with no rows; a wrong credential is {denied.error}") if denied.error == "access_denied" else res("FAIL", f"a wrong credential read as {denied.error}, not access_denied")


def check_old_credential(cfg: sc.SplunkConfig | None, old_file: Path | None) -> Result:
    if old_file is None:
        return res("NOT_RUN", "no --old-credential-file given")
    if cfg is None:
        return res("NOT_RUN", "no SplunkConfig")
    old = old_file.read_text(encoding="utf-8").strip()
    try:
        out = srch.RestBackend(sc.SplunkRestClient(dataclasses.replace(cfg, token=old))).run("| makeresults count=1 | eval ok=1", timeout_s=30, max_rows=2)
    except Exception as exc:  # noqa: BLE001
        return res("FAIL", f"raised {exc.__class__.__name__}")
    return res("PASS", "the previous credential was refused") if (not out.ok and out.error == "access_denied") else res("FAIL", "the previous credential still works after rotation: rotation did not revoke it" if out.ok else f"unexpected result {out.error}")


def parity_for_run(inv: InvestigationService, ds, finding: dict, run_remote: Callable[[str], tuple[list[str], list[list[str]]]]) -> list[Result]:
    """Compare, for every cell and for the whole run, the rows from `run_remote(spl)` with the rows read from the run's events."""
    ctx = InvestigationService._ctx(finding)
    out = []
    if ctx is None:
        return [res("NOT_RUN", "the finding has no usable run id")]
    events = ds.runs[finding["run_id"]]["events"]
    for cell in CELLS.values():
        for params in ({"scope": "run", "limit": 50}, {"limit": 50}):
            try:
                clean = cell.clean(ctx, {k: v for k, v in params.items() if k in {p["name"] for p in cell.params(ctx)}})
            except ValueError:
                continue
            spl = cell.spl(ctx, clean)
            cols, remote = run_remote(spl)
            local = cell.local(events, ctx, clean)
            same = normalize(list(cell.columns), remote) == normalize(list(cell.columns), local) and (not cols or [c.lower() for c in cols] == [c.lower() for c in cell.columns])
            out.append(res("PASS" if same else "FAIL", "" if same else "rows differ", cell=cell.id, params=clean, finding_id=finding["finding_id"], remote_rows=len(remote), local_rows=len(local),
                           sample_remote=remote[:2] if not same else [], sample_local=local[:2] if not same else []))
    return out


def check_notebook_parity(service: AssuranceService, client, max_findings: int) -> Result:
    found = service._splunk("all")
    ds, reason = found
    if ds is None:
        return res("FAIL", f"the Academy could not read Splunk ({reason})")
    live = [f for f in ds.findings if ds.class_of.get(f["run_id"]) == "LIVE"]
    if not live:
        return res("NOT_RUN", "no LIVE finding in Splunk: launch the LIVE workshops first")
    backend = srch.RestBackend(client)
    inv = InvestigationService(service, None)

    def remote(spl: str):
        o = backend.run(spl, timeout_s=40, max_rows=srch.MAX_ROWS)
        if not o.ok:
            raise RuntimeError(o.error or "search_failed")
        return o.columns, o.rows
    results: list[Result] = []
    for f in live[:max_findings]:
        try:
            results += parity_for_run(inv, ds, f, remote)
        except RuntimeError as exc:
            results.append(res("FAIL", f"the live search failed: {exc}", finding_id=f["finding_id"]))
    bad = [r for r in results if r["status"] == "FAIL"]
    return res("PASS" if results and not bad else "FAIL", f"{len(results)} cell comparisons over {min(len(live), max_findings)} live findings; {len(bad)} differ", cells=results)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--old-credential-file")
    ap.add_argument("--max-findings", type=int, default=12)
    a = ap.parse_args(argv)
    env = dict(os.environ)
    cfg = sc.access_config(env)
    report: dict[str, Result] = {}
    if cfg is None:
        report["access"] = res("FAIL", "search access is not provisioned (AGENTSEC_SPLUNK_ACCESS_DIR / AGENTSEC_SPLUNK_REST_URL): run ./agentsec splunk-access")
        client = None
    else:
        client = sc.SplunkRestClient(cfg)
        report["access"] = check_access(client)
    if client is not None and report["access"]["status"] == "PASS":
        report["index_isolation"] = check_index_isolation(client)
        report["empty_vs_denied"] = check_empty_vs_denied(client, cfg)
        report["notebook_parity"] = check_notebook_parity(AssuranceService(env=env), client, a.max_findings)
    report["old_credential"] = check_old_credential(cfg, Path(a.old_credential_file) if a.old_credential_file else None)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rc2_validate_live.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    for k, v in report.items():
        print(f"{v['status']:8} {k}: {v['why']}")
    return 1 if any(v["status"] == "FAIL" for v in report.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
