#!/usr/bin/env python3
"""Operator preflight for a learner session: read-only checks that the lab is ready for participants who will use only a browser.

  python3 scripts/learner_ready.py [--json]

Checks Docker and the five services, the model (Ollama + llama3.2:latest as AcmeBank sees it), Splunk (web, searchable index,
the restored REPLAY specimens), the host verifier (process identity, fresh heartbeat, read-only receipts mount in both
containers, no key reachable by a container), Academy access (every original lab discoverable) and disk space.
It never starts, stops, pulls or changes anything. Exit 0 only if every check passes; each FAIL prints the operator's fix.
Splunk is searched through the existing `docker exec` path (the admin password stays inside the container).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SERVICES = ["agentsec_acmebank", "agentsec_attack_service", "agentsec_splunk", "agentsec_otel_collector", "agentsec_ollama"]
REPLAY_LABS = ["LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005", "LAB-MCP-006", "LAB-MCP-CATALOG", "LAB-BLUE-TEAM-INCIDENT-001",
               "LAB-MULTI-STAGE-INCIDENT-001", "LAB-SCANNER-RUNTIME-EVIDENCE", "LAB-MCP-001",
               "LAB-PI-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-AGENTSEC-CAPSTONE-001"]
UU = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
results: list[dict] = []


def get(url: str, timeout: int = 8) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:  # noqa: BLE001
        return 0, ""


def sh(*cmd: str) -> tuple[int, str]:
    p = subprocess.run(list(cmd), capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def check(group: str, name: str, ok: bool, detail: str, fix: str = "") -> None:
    results.append({"group": group, "check": name, "pass": bool(ok), "detail": str(detail)[:200], "fix": "" if ok else fix})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="http://127.0.0.1:5001")
    ap.add_argument("--acmebank", default="http://127.0.0.1:5000")
    ap.add_argument("--splunk-web", default="http://127.0.0.1:8000")
    ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    # 1. Docker and services
    rc, out = sh("docker", "info", "--format", "{{.ServerVersion}}")
    check("Docker", "daemon reachable", rc == 0, out, "Start Docker Desktop and wait until it says it is running.")
    for name in SERVICES:
        rc, out = sh("docker", "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name)
        ok = rc == 0 and out.startswith("running") and "unhealthy" not in out and "starting" not in out
        check("Services", f"{name} running and healthy", ok, out if rc == 0 else "not found", "Run ./scripts/lab-up.sh and wait for READY (first Splunk boot can take 10 to 20 minutes).")

    # 2. Model
    code, body = get(f"{a.acmebank}/api/v1/loan-desk/status")
    st = json.loads(body) if code == 200 else {}
    ident = st.get("identity") or {}
    rd = st.get("readiness") or {}
    fix = (rd.get("fix") or {}).get("command") or "ollama serve"
    check("Model", "Ollama reachable from AcmeBank", bool(rd.get("ollama_reachable")), f"HTTP {code}", f"On the Ollama host run: {fix}. The lab never downloads models.")
    check("Model", f"{st.get('model', 'llama3.2:latest')} installed", bool(st.get("available")), (ident.get("digest") or "")[:12] or st.get("reason") or "", "On the Ollama host an operator runs: ollama pull llama3.2:latest (use your organisation's certificate process if the pull reports x509; never disable TLS verification).")

    # 3. Splunk
    code, _ = get(f"{a.splunk_web}/en-US/account/login")
    check("Splunk", "Splunk Web answers", code == 200, f"HTTP {code}", "Check the agentsec_splunk container; if it is starting, wait.")
    try:
        from agentsec.loan_desk.reconcile import run_spl
        n = run_spl('index=agentsec_telemetry earliest=0 | stats count')
        check("Splunk", "index agentsec_telemetry is searchable", bool(n) and int(n[0]["count"]) > 0, f"{n[0]['count']} events" if n else "no rows", "Run ./scripts/lab-ready.sh and follow its Splunk/HEC guidance.")
        missing = {}
        for lab in REPLAY_LABS:
            d = json.loads((ROOT / f"learning/level_1/{lab}/dashboard.definition.json").read_text())
            ids = sorted({i for k, v in d.get("inputs", {}).items() if "run" in k for i in UU.findall(json.dumps(v))})
            if ids:
                rows = run_spl('index=agentsec_telemetry earliest=0 (' + " OR ".join(f'"agentsec.run.id"="{i}"' for i in ids) + ') | eval r=mvindex(mvdedup(\'agentsec.run.id\'),0) | stats count by r')
                have = {r["r"] for r in rows}
                if set(ids) - have:
                    missing[lab] = len(set(ids) - have)
        check("Splunk", "REPLAY specimens offered by the 15 specimen labs are all searchable", not missing, "all present" if not missing else f"missing: {missing}",
              "Re-run the specimen seeder: docker compose ... up splunk_hec_init, then python3 scripts/seed_envelope_specimens.py (both are additive and idempotent).")
    except Exception as exc:  # noqa: BLE001
        check("Splunk", "index agentsec_telemetry is searchable", False, type(exc).__name__, "Splunk search through docker exec failed; check the agentsec_splunk container.")

    # 4. Host verifier
    if not Path(a.artifacts).is_dir() or not (Path(a.artifacts) / "loan_desk").is_dir():
        rc, src = sh("docker", "inspect", "-f", '{{range .Mounts}}{{if eq .Destination "/app/artifacts"}}{{.Source}}{{end}}{{end}}', "agentsec_acmebank")
        if rc == 0 and src:
            a.artifacts = src.replace("/host_mnt", "", 1) if src.startswith("/host_mnt/") else src
    d = Path(a.artifacts) / "loan_desk"
    state = Path.home() / ".local/state/agentsec/loan_desk"
    pidf = state / "verifier.pid"
    pid = pidf.read_text().strip() if pidf.exists() else ""
    ps = sh("ps", "-p", pid, "-o", "command=")[1] if pid.isdigit() else ""
    check("Verifier", "host verifier process is running", "loan_desk_verifier.py" in ps, ps[:90] or "no pidfile", "Run ./scripts/loan_desk_verifier.sh start")
    try:
        hb = json.loads((d / "receipts" / "verifier.json").read_text())
        age = time.time() - float(hb["last_seen"])
        check("Verifier", "heartbeat is fresh (under 20 s) and the verifier is running", hb.get("state") == "running" and 0 <= age < 20, f"age {age:.0f}s state {hb.get('state')} v{hb.get('version')}", "Run ./scripts/loan_desk_verifier.sh start (and check ~/.local/state/agentsec/loan_desk/verifier.log).")
    except Exception:  # noqa: BLE001
        check("Verifier", "heartbeat is fresh (under 20 s) and the verifier is running", False, "no heartbeat file", "Run ./scripts/loan_desk_verifier.sh start")
    for c in ("agentsec_acmebank", "agentsec_attack_service"):
        rc, out = sh("docker", "inspect", "-f", '{{range .Mounts}}{{if eq .Destination "/app/artifacts/loan_desk/receipts"}}{{if .RW}}rw{{else}}ro{{end}}{{end}}{{end}}', c)
        check("Verifier", f"{c}: receipts mount is read-only", out == "ro", out or "mount absent", "Redeploy the two containers with scripts/deploy_acmebank_attack.py deploy; without the read-only mount the page refuses to show SPLUNK-VERIFIED.")
    rc, out = sh("docker", "exec", "agentsec_acmebank", "sh", "-c", "find /app/artifacts -name '*.key' -o -name '.bridge*' | head -1")
    check("Verifier", "no signing key is reachable from the AcmeBank container", rc == 0 and out == "", out or "none", "Remove the legacy .bridge.key from artifacts/loan_desk (a backup should already exist).")

    # 5. Academy access
    code, _ = get(f"{a.attack}/academy")
    check("Academy", "Academy home", code == 200, f"HTTP {code}", "Check the agentsec_attack_service container.")
    code, body = get(f"{a.attack}/academy/missions/loan-desk")
    check("Academy", "Loan Desk mission page with objectives", code == 200 and "By the end you will be able to" in body, f"HTTP {code}", "Redeploy the Attack Service image (scripts/deploy_acmebank_attack.py).")
    for u in ["/", "/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-MEMORY-001", "/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-AGENT-DELEGATION-001", "/labs/LAB-AGENTSEC-CAPSTONE-001"]:
        code, _ = get(f"{a.attack}{u}")
        check("Attack UI", f"{u} opens", code == 200, f"HTTP {code}", "A 500 here means the Attack Service image lacks learning/academy/framework_refs.json; redeploy the current image.")
    code, body = get(f"{a.attack}/academy/path")
    code2, body2 = get(f"{a.attack}/academy/foundations")
    reg = [e["lab_id"] for e in json.loads((ROOT / "learning/academy/lab_registry_data.json").read_text())["entries"]]
    cur = json.loads((ROOT / "learning/academy/curriculum.json").read_text())
    views: dict[str, str] = {}

    def walk(x):
        if isinstance(x, dict):
            if x.get("lab_id") and x.get("view"):
                views[x["lab_id"]] = x["view"]
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(cur)
    app = ROOT / "splunk_app/agentsec"
    nav = (app / "default/data/ui/nav/default.xml").read_text()
    lp = (app / "appserver/static/agentsec_learner_path.js").read_text()
    on_academy = [l for l in reg if l in body or l in body2]
    splunk_only = [l for l in reg if l not in on_academy and views.get(l) and f'name="{views[l]}"' in nav and views[l] in lp]
    lost = [l for l in reg if l not in on_academy and l not in splunk_only]
    links_to_splunk_path = "/en-US/app/agentsec/learner_path" in body
    check("Academy", f"all {len(reg)} labs are discoverable ({len(on_academy)} on the Academy path, {len(splunk_only)} through the Splunk learning path and app navigation)",
          code == 200 and not lost and links_to_splunk_path, "none lost" if not lost else f"not discoverable: {lost}",
          "Check learning/academy/curriculum.json, the Splunk app nav and agentsec_learner_path.js in the deployed lab.")

    # 6. Disk
    free = shutil.disk_usage("/").free / 1e9
    check("Host", "at least 5 GB free disk", free >= 5, f"{free:.0f} GB free", "Free disk space before the session.")

    failed = [r for r in results if not r["pass"]]
    if a.json:
        print(json.dumps({"ready": not failed, "checks": results}, indent=1))
    else:
        group = ""
        for r in results:
            if r["group"] != group:
                group = r["group"]
                print(f"\n{group}")
            print(f"  {'PASS' if r['pass'] else 'FAIL'}  {r['check']}" + (f"  [{r['detail']}]" if r["detail"] else ""))
            if r["fix"]:
                print(f"        fix (operator): {r['fix']}")
        print(f"\n{'READY for participants' if not failed else 'NOT READY'}: {len(results) - len(failed)}/{len(results)} checks passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
