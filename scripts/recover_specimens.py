#!/usr/bin/env python3
"""Export original REPLAY specimen packs from a RECOVERED copy of the original Splunk index (isolated container; the live
Splunk is never queried). A pack is the verbatim `_raw` of every event of one run.id, ordered by agentsec.sequence.
Method self-check: the three LAB-MCP-001 packs already committed in the repository must be reproduced byte for byte.

  AGENTSEC_SPLUNK_CONTAINER=agentsec_recover_splunk recover_specimens.py --out DIR [--ids FILE]
"""
from __future__ import annotations
import argparse, csv, hashlib, io, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.reconcile import SPLUNK_CONTAINER, UUID  # noqa: E402


def export_raw(run_id: str) -> list[str]:
    assert UUID.match(run_id)
    spl = ('index=agentsec_telemetry earliest=0 "agentsec.run.id"="%s" | eval seq=tonumber(mvindex(mvdedup(\'agentsec.sequence\'),0)) '
           '| sort 0 seq _time | table _raw' % run_id)
    inner = "/opt/splunk/bin/splunk search " + json.dumps(" ".join(spl.split())) + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv -maxout 0'
    p = subprocess.run(["docker", "exec", "-u", "splunk", SPLUNK_CONTAINER, "bash", "-lc", inner], capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise SystemExit(f"search failed for {run_id}")
    return [r["_raw"] for r in csv.DictReader(io.StringIO(p.stdout))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--ids", default="/tmp/ids.txt")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    report = {"container": SPLUNK_CONTAINER, "method_check": {}, "packs": {}}
    for pack in sorted((ROOT / "learning/level_1/LAB-MCP-001/specimens").glob("*.jsonl")):
        rid = pack.stem
        raws = export_raw(rid)
        mine = ("\n".join(raws) + "\n").encode()
        report["method_check"][rid] = {"events": len(raws), "byte_identical_to_committed": mine == pack.read_bytes(),
                                       "sha256": hashlib.sha256(mine).hexdigest()[:16]}
    ok = all(v["byte_identical_to_committed"] for v in report["method_check"].values())
    print("method check (MCP-001 committed packs reproduced byte for byte):", ok, report["method_check"])
    if not ok:
        (out / "report.json").write_text(json.dumps(report, indent=1))
        return 2
    for rid in sorted(set(Path(a.ids).read_text().split())):
        raws = export_raw(rid)
        if not raws:
            continue
        data = ("\n".join(raws) + "\n").encode()
        (out / f"{rid}.jsonl").write_bytes(data)
        report["packs"][rid] = {"events": len(raws), "sha256": hashlib.sha256(data).hexdigest()}
    (out / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(len(report["packs"]), "packs exported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
