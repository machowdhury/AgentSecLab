#!/usr/bin/env python3
"""Read-only KV_MODE compatibility emulation for hunts and dashboard panels. Changes no Splunk config.

For each search it runs (a) as-is and (b) with every field de-duplicated right after the base search, which is what
removing the duplicate search-time extraction would do to the 37 two-copy fields (it over-corrects the 10 three-copy
fields to one copy). Placeholders __X_RUN_ID__ are bound to a run id passed on the CLI. A search is SENSITIVE if the
exact (not normalised) result differs, or if it uses constructs that count or group on multivalue fields.
"""
from __future__ import annotations
import argparse, glob, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.reconcile import run_spl  # noqa: E402

DEDUP = "| foreach * [eval <<FIELD>>=mvdedup('<<FIELD>>')] "
RISK = {"count(field)": r"count\(\s*['\"]?[a-z_]+\.[a-z_.]+", "by_dotted_field": r"\bby\s+['\"]?[a-z_]+\.[a-z_.]+",
        "spath": r"\bspath\b", "mvcount": r"\bmvcount\b", "mvexpand": r"\bmvexpand\b", "dc(field)": r"\bdc\(",
        "already_dedups": r"\bmvdedup\b|\bmvindex\b", "values()": r"\bvalues\("}


def clean(t: str) -> str:
    t = re.sub(r"^\s*(//|#).*$", "", t, flags=re.M).strip()
    return t[7:] if t.startswith("search ") else t


def emulate(spl: str) -> str:
    if spl.lstrip().startswith("|"):
        return spl  # generating search (makeresults): its rows never touch index-time or search-time extraction
    head, sep, rest = spl.partition("|")
    return head + (" " if sep else "") + DEDUP + (sep + rest if sep else "")


def digest(rows):
    return hashlib.sha256(json.dumps(sorted(sorted(r.items()) for r in rows)).encode()).hexdigest()[:12]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="run id used for any __*_RUN_ID__ / __SCAN_ID__ placeholder")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", help="regex on lab/file key; merges into an existing --out file")
    ap.add_argument("--kind", choices=["unbound", "bound"], default="unbound")
    a = ap.parse_args()
    res = json.loads(Path(a.out).read_text()) if a.only and Path(a.out).exists() else {}
    for f in sorted(glob.glob(str(ROOT / "learning/level_1/*/searches/*.spl"))):
        raw = Path(f).read_text(encoding="utf-8")
        bound = "__RUN_ID__" in raw
        if bound != (a.kind == "bound"):
            continue
        key = f"{Path(f).parent.parent.name}/{Path(f).name}"
        spl = clean(re.sub(r"__[A-Z_]*(RUN_ID|SCAN_ID)__", f'"{a.run}"', raw.replace("__RUN_ID__", f'"{a.run}"')))
        if a.only and not re.search(a.only, key):
            continue
        risks = [k for k, p in RISK.items() if re.search(p, spl)]
        ent = {"risk_constructs": risks}
        try:
            base = run_spl(spl)
            emu = run_spl(emulate(spl))
            ent.update(rows=len(base), emulated_rows=len(emu), exact_same=digest(base) == digest(emu),
                       multivalue_cells=sum(1 for r in base for v in r.values() if "\n" in v))
        except Exception as exc:  # noqa: BLE001
            ent["error"] = str(exc)[:120]
        res[key] = ent
        print(key, {k: v for k, v in ent.items() if k != "risk_constructs"}, flush=True)
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
