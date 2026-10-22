#!/usr/bin/env python3
"""Seed recovered ORIGINAL scanner / external-evaluation specimens (non-otel sourcetypes) into the lab index, additively.

The run.id specimens (sourcetype otel:agentic:json) are seeded by scripts/splunk_hec_init.sh. The scanner and garak
evidence of LAB-SCANNER-RUNTIME-EVIDENCE and LAB-MULTI-STAGE-INCIDENT-001 has its own sourcetypes, so its packs live one
level deeper (specimens/scanner/, specimens/external/) and are seeded here. Each pack line is a HEC envelope recorded from
the original index: original time, host, source, sourcetype and the verbatim event text. Nothing is generated or restamped.

Safety: HTTPS with an explicit CA and verification on; additive only; idempotent (already complete -> no action); a partially
present pack is refused rather than topped up (duplicates would corrupt counts); success is proven by a search, not by HEC's 200.

  seed_envelope_specimens.py --hec-url https://localhost:8088/services/collector/event --ca .certs/hec-ca.crt \
      --env-file .env --splunk-container agentsec_splunk [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
INDEX = "agentsec_telemetry"
SUBDIRS = ("scanner", "external")


def packs(root: Path) -> list[Path]:
    out = []
    for sub in SUBDIRS:
        out += sorted((root / "learning/level_1").glob(f"*/specimens/{sub}/*.jsonl"))
    return out


def load(pack: Path) -> list[dict]:
    rows = [json.loads(x) for x in pack.read_text(encoding="utf-8").splitlines() if x.strip()]
    for i, r in enumerate(rows, 1):
        for k in ("time", "host", "source", "sourcetype", "index", "event"):
            if k not in r:
                raise ValueError(f"{pack.name} line {i}: missing {k}")
        if r["index"] != INDEX or not isinstance(r["event"], str) or not isinstance(r["time"], (int, float)):
            raise ValueError(f"{pack.name} line {i}: not a recorded envelope")
        json.loads(r["event"])  # the verbatim event text must itself be JSON
    return rows


def plan(rows: list[dict], count_fn: Callable[..., int], needle: str) -> tuple[str, int, int]:
    """Return (action, expected, present): action is skip | post | refuse."""
    src, st = rows[0]["source"], rows[0]["sourcetype"]
    lo, hi = min(r["time"] for r in rows), max(r["time"] for r in rows)
    present = count_fn(src, st, lo, hi, needle)
    expected = len(rows)
    if present == expected:
        return "skip", expected, present
    if present == 0:
        return "post", expected, present
    return "refuse", expected, present


def splunk_count_fn(container: str) -> Callable[..., int]:
    def fn(source: str, sourcetype: str, lo: float, hi: float, needle: str) -> int:
        # the pack's own id (its file name) is inside every event, so two packs ingested in the same second are not confused
        spl = (f'index={INDEX} source="{source}" sourcetype="{sourcetype}" earliest={int(lo) - 1} latest={int(hi) + 2} "{needle}" | stats count')
        inner = "/opt/splunk/bin/splunk search " + json.dumps(spl) + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
        p = subprocess.run(["docker", "exec", "-u", "splunk", container, "bash", "-lc", inner], capture_output=True, text=True)
        lines = [ln for ln in p.stdout.splitlines() if ln and not ln.startswith("WARNING")]
        return int(lines[1]) if p.returncode == 0 and len(lines) > 1 and lines[1].isdigit() else -1
    return fn


def env_value(path: Path, key: str) -> str:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip().startswith(key + "="):
            return raw.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def hec_post_fn(url: str, ca: Path, token: str) -> Callable[[dict], int]:
    ctx = ssl.create_default_context(cafile=str(ca))  # verification stays on
    def fn(row: dict) -> int:
        body = json.dumps(row, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST", headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
    return fn


def run(root: Path, count_fn, post_fn, dry_run=False, wait_s=90, sleep=time.sleep) -> int:
    failed = 0
    for pack in packs(root):
        rows = load(pack)
        needle = pack.stem
        action, expected, present = plan(rows, count_fn, needle)
        name = f"{pack.parent.name}/{pack.name}"
        if present < 0:
            print(f"{name}: Splunk could not be queried; refusing to guess")
            failed += 1
        elif action == "skip":
            print(f"{name}: already indexed ({present}/{expected}). No action.")
        elif action == "refuse":
            print(f"{name}: PARTIAL ({present}/{expected} present). Not posting; duplicates would corrupt counts.")
            failed += 1
        elif dry_run:
            print(f"{name}: would post {expected} original events (dry run)")
        else:
            bad = []
            for r in rows:
                code = post_fn(r)
                if code != 200:
                    bad.append(code)
            if bad:
                print(f"{name}: HEC returned {bad}; not claiming success")
                failed += 1
                continue
            end, got = time.time() + wait_s, 0
            while time.time() < end:
                got = count_fn(rows[0]["source"], rows[0]["sourcetype"], min(r["time"] for r in rows), max(r["time"] for r in rows), needle)
                if got == expected:
                    break
                sleep(3)
            ok = got == expected
            print(f"{name}: {'VERIFIED searchable' if ok else 'ONLY'} ({got}/{expected})")
            failed += 0 if ok else 1
    return failed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--hec-url", default="https://localhost:8088/services/collector/event")
    ap.add_argument("--ca", default=".certs/hec-ca.crt")
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--splunk-container", default="agentsec_splunk")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    root = Path(a.root)
    token = env_value(Path(a.env_file), "SPLUNK_HEC_TOKEN")
    if not token and not a.dry_run:
        raise SystemExit("SPLUNK_HEC_TOKEN missing from the env file")
    ca = Path(a.ca) if Path(a.ca).is_absolute() else root / a.ca
    if not a.dry_run and not ca.is_file():
        raise SystemExit(f"HEC CA file missing: {ca}")
    post = hec_post_fn(a.hec_url, ca, token) if not a.dry_run else (lambda r: 200)
    return 1 if run(root, splunk_count_fn(a.splunk_container), post, a.dry_run) else 0


if __name__ == "__main__":
    raise SystemExit(main())
