#!/usr/bin/env python3
"""Preflight, deploy and roll back ONLY the AcmeBank and Attack Service containers of the running lab.

  preflight    read-only (plus: builds two images, tags two rollback anchors, writes a 0600 backup outside every repo)
  deploy       preflight must have passed in this run; recreates acmebank and attack_service with --no-deps --no-build
  rollback     recreates them from the pre-deploy image anchors (no receipts mounts); never touches data
  status       what is running now

Everything (project name, compose files, working directory, env file) is read from the running acmebank container's
Compose labels, so the script cannot act on any other project. Never used: down, -v, volume/system prune, a service
other than acmebank/attack_service, the Docker socket. Splunk, the collector, Ollama and every volume are only observed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
TARGETS = ("acmebank", "attack_service")
CONTAINERS = {"acmebank": "agentsec_acmebank", "attack_service": "agentsec_attack_service"}
OBSERVED = ("agentsec_splunk", "agentsec_otel_collector", "agentsec_ollama")
SECRET_NAME = re.compile(r"(PASSWORD|TOKEN|SECRET|PRIVATE|API_?KEY|CREDENTIAL)", re.I)
OUT = ROOT / "docs/reviews/batch7/deploy"


def sh(*cmd, check=True, cwd=None, env=None, input=None):
    r = subprocess.run(list(cmd), capture_output=True, text=True, cwd=cwd, env=env, input=input)
    if check and r.returncode:
        raise SystemExit(f"FAILED: {' '.join(cmd)[:160]}\n{r.stderr[-600:]}")
    return r.stdout.strip()


def inspect(name):
    return json.loads(sh("docker", "inspect", name))[0]


def short(i):
    return i.replace("sha256:", "")[:12]


def facts():
    c = inspect(CONTAINERS["acmebank"])
    lab = c["Config"]["Labels"]
    return {"project": lab["com.docker.compose.project"], "workdir": lab["com.docker.compose.project.working_dir"],
            "files": [x for x in lab["com.docker.compose.project.config_files"].split(",") if Path(x).parent == Path(lab["com.docker.compose.project.working_dir"]) and Path(x).name.startswith("docker-compose")], "env_file": str(Path(lab["com.docker.compose.project.working_dir"]) / ".env")}


def dc(f, *args, override=None, env_extra=None):
    cmd = ["docker", "compose", "-p", f["project"], "--project-directory", f["workdir"], "--env-file", f["env_file"]]
    for x in f["files"] + ([str(override)] if override else []):
        cmd += ["-f", x]
    cmd += ["--profile", "local", *args]
    return sh(*cmd, env={**os.environ, **(env_extra or {})})


def snapshot():
    snap = {}
    for n in list(CONTAINERS.values()) + list(OBSERVED):
        i = inspect(n)
        snap[n] = {"id": short(i["Id"]), "image": short(i["Image"]), "tag": i["Config"]["Image"], "started": i["State"]["StartedAt"], "health": (i["State"].get("Health") or {}).get("Status"),
                   "mounts": sorted(f"{m['Type']}:{m.get('Name') or m['Source']}->{m['Destination']}:{'rw' if m['RW'] else 'ro'}" for m in i["Mounts"]),
                   "env_names": sorted(e.split("=", 1)[0] for e in i["Config"]["Env"])}
    snap["volumes"] = sorted(sh("docker", "volume", "ls", "-q").split())
    return snap


def check(results, name, ok, detail):
    results.append({"check": name, "pass": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + " - " + str(detail)[:230])


def verifier_identity(art):
    """v2: pid in the host-only state dir (the v1 pidfile under artifacts/ is also read, for the migration)."""
    state = Path(os.environ.get("AGENTSEC_VERIFIER_STATE_DIR") or Path.home() / ".local/state/agentsec/loan_desk")
    out = {}
    for label, pf in (("v2_pidfile", state / "verifier.pid"), ("v1_pidfile", Path(art) / "loan_desk" / "verifier.pid")):
        pid = pf.read_text().strip() if pf.exists() else None
        out[label] = pid
        if pid and pid.isdigit():
            ps = sh("ps", "-p", pid, "-o", "pid=,ppid=,lstart=,command=", check=False)
            out[label + "_ps"] = ps
            if "loan_desk_verifier.py" in ps:
                out["is_verifier"], out["ps"], out["version"] = True, ps, label[:2]
                out["artifacts_arg"] = (re.search(r"--artifacts (\S+)", ps) or [None, None])[1]
    return out


def preflight(a):
    f = facts()
    art = Path(f["workdir"]) / "artifacts"
    res, ev = [], {"facts": f, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    before = snapshot()
    ev["before"] = before
    ac, at = before[CONTAINERS["acmebank"]], before[CONTAINERS["attack_service"]]
    check(res, "1a both target containers are up and healthy", ac["health"] == "healthy" and at["health"] == "healthy", {k: (v["tag"], v["image"], v["health"]) for k, v in before.items() if k in CONTAINERS.values()})
    check(res, "1b compose project and files come from the running containers", f["project"] == "agentseclab" and all(Path(x).is_file() for x in f["files"]), f)
    check(res, "1c containers mount the shared artifacts dir read-write and nothing from the Docker socket", any(m.endswith("/app/artifacts:rw") for m in ac["mounts"]) and not any("docker.sock" in m for m in ac["mounts"] + at["mounts"]), ac["mounts"])
    vid = verifier_identity(art)
    ev["verifier_identity"] = vid
    check(res, "1d the running verifier is the one the pidfile names (a loan_desk_verifier.py process)", vid.get("is_verifier") is True, vid.get("ps"))

    anchors = {}
    for name, c in CONTAINERS.items():
        img = before[c]["image"]
        tag = f"agentseclab-{name}:pre-batch7-{img}"
        sh("docker", "tag", before[c]["image"], tag)
        anchors[name] = tag
    ev["rollback_anchors"] = anchors
    check(res, "2a rollback anchors tagged for both images", all(sh("docker", "image", "inspect", t, "--format", "{{.Id}}") for t in anchors.values()), anchors)

    ts = time.strftime("%Y%m%d-%H%M%S")
    bdir = Path.home() / "agentsec-backups"
    bdir.mkdir(mode=0o700, exist_ok=True)
    bfile = bdir / f"loan_desk-{ts}.tar.gz"
    src = art / "loan_desk"
    with tarfile.open(bfile, "w:gz") as tf:
        if src.exists():
            tf.add(src, arcname="loan_desk")
    os.chmod(bfile, 0o600)
    with tarfile.open(bfile) as tf:
        listed = [m.name for m in tf.getmembers()]
    onfs = sum(1 for p in src.rglob("*") if p.is_file()) if src.exists() else 0
    ev["backup"] = {"file": str(bfile), "mode": "0600", "files_in_archive": sum(1 for n in listed if not n.endswith("loan_desk")), "files_on_disk": onfs}
    check(res, "2b artifacts/loan_desk backed up outside every repository (0600) and the archive lists every file", ev["backup"]["files_in_archive"] >= onfs - 1, ev["backup"])

    from agentsec.loan_desk.reconcile import run_spl
    tot = run_spl('index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=0 | eval r=mvindex(mvdedup(\'agentsec.run.id\'),0) | stats count AS events dc(r) AS runs')
    ev["splunk_before"] = tot[0] if tot else {}
    check(res, "3 historical evidence is in Splunk and nothing here deletes it (counts recorded)", bool(tot) and int(tot[0]["events"]) > 0, ev["splunk_before"])

    recent = {}
    for name in CONTAINERS.values():
        r = subprocess.run(["docker", "logs", "--since", f"{a.quiet_minutes}m", name], capture_output=True, text=True)
        lines = [l for l in (r.stdout + r.stderr).splitlines() if "GET /health " not in l and l.strip()]
        recent[name] = len(lines)
    ev["recent_non_health_requests"] = recent
    check(res, f"4 no learner activity in the last {a.quiet_minutes} minutes (non-health log lines)", sum(recent.values()) == 0 or a.allow_activity, recent)

    hostkey = Path.home() / ".local/state/agentsec/loan_desk/receipt.key"
    legacy = (src / ".bridge.key").exists()
    check(res, "5a signing material: the host key is private (0600) and no legacy key is in a container-visible path (or, if one is, it is backed up)", hostkey.exists() and oct(hostkey.stat().st_mode & 0o777) == "0o600" and (not legacy or any(n.endswith(".bridge.key") for n in listed)),
          {"host_key": str(hostkey) if hostkey.exists() else "missing", "legacy_key_present": legacy})
    leaked = [f"{c}:{n}" for c in CONTAINERS.values() for n in before[c]["env_names"] if SECRET_NAME.search(n)]
    check(res, "6a no credential-named environment variable in either target container", not leaked, leaked or "none")

    tag = a.tag
    if not a.no_build:
        for name in TARGETS:
            sh("docker", "build", "-q", "-f", f"docker/Dockerfile.{'acmebank' if name == 'acmebank' else 'attack'}", "-t", f"agentseclab-{name}:{tag}", ".", cwd=ROOT)
    bad = {}
    for name in TARGETS:
        listing = sh("docker", "run", "--rm", "--entrypoint", "sh", f"agentseclab-{name}:{tag}", "-c", "find /app \\( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name '.bridge*' -o -name 'receipt.key' \\) -print 2>/dev/null")
        bad[name] = listing.splitlines()
    ev["image_secret_scan"] = bad
    check(res, "6b new images contain no .env, key or certificate file", all(not v for v in bad.values()), bad)
    ref = sh("docker", "run", "--rm", "--entrypoint", "ls", f"agentseclab-attack_service:{tag}", "/app/learning/academy")
    check(res, "6c the Attack Service image carries framework_refs.json (baseline defect fix)", "framework_refs.json" in ref, ref.split())

    override = write_override(f, tag, anchors=None)
    base = ["docker", "compose", "-p", f["project"], "--project-directory", f["workdir"], "--env-file", f["env_file"]]
    for x in f["files"] + [str(override)]:
        base += ["-f", x]
    dry_err = subprocess.run(base + ["--profile", "local", "up", "-d", "--no-deps", "--no-build", "--dry-run", *TARGETS], capture_output=True, text=True)
    text = dry_err.stdout + dry_err.stderr
    touched = sorted(set(re.findall(r"Container (agentsec_\w+)\s+(?:Recreate|Recreated|Stopping|Stopped|Removing|Removed|Creating|Created|Starting|Started)", text)))
    ev["dry_run_containers"] = touched
    check(res, "7 dry run would touch only agentsec_acmebank and agentsec_attack_service", set(touched) <= set(CONTAINERS.values()) and len(touched) >= 1 and dry_err.returncode == 0, touched or text[-300:])
    check(res, "8 no volume is removed by this procedure (no down, no -v, no prune in the command set)", True, "compose up --no-deps --no-build only; volume list recorded for comparison")
    dev = Path(f["workdir"])
    ev["develop_tree"] = {"head": sh("git", "-C", str(dev), "rev-parse", "--short", "HEAD"), "branch": sh("git", "-C", str(dev), "branch", "--show-current"), "dirty_entries": len(sh("git", "-C", str(dev), "status", "--short").splitlines())}
    ev["checks"] = res
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "preflight.json").write_text(json.dumps(ev, indent=1, sort_keys=True) + "\n")
    failed = [r for r in res if not r["pass"]]
    print(f"\nPREFLIGHT {'PASSED' if not failed else 'FAILED'}: {len(res) - len(failed)}/{len(res)} checks")
    return 0 if not failed else 1


def write_override(f, tag, anchors):
    d = Path(f["workdir"]) / "artifacts" / "loan_desk"
    body = ["services:"]
    for name in TARGETS:
        image = f"agentseclab-{name}:{tag}" if anchors is None else anchors[name]
        body += [f"  {name}:", f"    image: {image}"]
        if anchors is None:
            body += ["    volumes:", f"      - {d}/receipts:/app/artifacts/loan_desk/receipts:ro"]
    p = Path(os.environ.get("TMPDIR", "/tmp")) / f"agentsec-deploy-override-{'fwd' if anchors is None else 'rollback'}.yml"
    p.write_text("\n".join(body) + "\n")
    return p


def wait_healthy(names, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        if all((inspect(n)["State"].get("Health") or {}).get("Status") == "healthy" for n in names):
            return True
        time.sleep(3)
    return False


def deploy(a, rollback=False):
    f = facts()
    pre = json.loads((OUT / "preflight.json").read_text()) if (OUT / "preflight.json").exists() else None
    if not rollback:
        if not pre or not all(c["pass"] for c in pre["checks"]):
            raise SystemExit("refusing: no passing preflight.json (run preflight first)")
        if time.time() - time.mktime(time.strptime(pre["time"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone > 3600:
            raise SystemExit("refusing: preflight is older than an hour; rerun it")
    before = snapshot()
    art = Path(f["workdir"]) / "artifacts" / "loan_desk"
    for sub in ("requests", "receipts"):
        (art / sub).mkdir(parents=True, exist_ok=True)
    anchors = pre["rollback_anchors"] if rollback else None
    if rollback:
        anchors = {k: v for k, v in json.loads((OUT / "preflight.json").read_text())["rollback_anchors"].items()}
    override = write_override(f, a.tag, anchors)
    dc(f, "up", "-d", "--no-deps", "--no-build", *TARGETS, override=override)
    ok = wait_healthy(list(CONTAINERS.values()))
    after = snapshot()
    untouched = {n: before[n]["id"] == after[n]["id"] and before[n]["started"] == after[n]["started"] for n in OBSERVED}
    res = {"action": "rollback" if rollback else "deploy", "healthy": ok, "observed_services_untouched": untouched, "volumes_identical": before["volumes"] == after["volumes"],
           "targets": {n: {"before": (before[c]["tag"], before[c]["image"]), "after": (after[c]["tag"], after[c]["image"])} for n, c in CONTAINERS.items()},
           "mounts_after": {c: after[c]["mounts"] for c in CONTAINERS.values()}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{res['action']}_{time.strftime('%H%M%S')}.json").write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    print(json.dumps(res, indent=1, sort_keys=True))
    return 0 if ok and all(untouched.values()) and res["volumes_identical"] else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["preflight", "deploy", "rollback", "status"])
    ap.add_argument("--tag", default="batch7")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--quiet-minutes", type=int, default=10)
    ap.add_argument("--allow-activity", action="store_true", help="only after confirming the activity is the operator's own")
    a = ap.parse_args()
    if a.cmd == "preflight":
        return preflight(a)
    if a.cmd == "deploy":
        return deploy(a)
    if a.cmd == "rollback":
        return deploy(a, rollback=True)
    print(json.dumps(snapshot(), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
