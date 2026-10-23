#!/usr/bin/env python3
"""Inventory and verify Splunk data volumes; print (never run) a migration plan.

Splunk's /opt/splunk/etc and /opt/splunk/var are Docker volumes. Before the compose file named them they were
ANONYMOUS, so `docker compose down` then `up` silently started Splunk with new empty volumes and orphaned the old ones.
This tool finds those orphaned volumes and says what is in them, without starting Splunk and without writing anything.

  inventory [--json]   list every volume that holds Splunk var or etc data: indexes, bucket counts, event counts, time ranges,
                       version, which container (if any) uses it, and the var/etc pairing (by creation time)
  verify SRC DST       read-only: `diff -rq` of two volumes plus an index-by-index comparison
  plan ...             print an explicit, ordered migration script (stop, copy, verify, switch). Prints text only.

Event counts come from each bucket's Sources.data header (third column), which reproduced the known counts of two real
volumes exactly (2036 and 56). It is metadata, not a search: a hot bucket's header can lag until Splunk rolls or stops it.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone

HELPER_IMAGE = "busybox:1.36"  # already used by the lab; no download is attempted
SPLUNK_UID = "41812"

# Runs inside the throwaway container. Volumes are mounted read-only at /v/<n>.
COLLECTOR = r"""
n=0
for d in /v/*; do
  [ -d "$d" ] || continue
  i=${d#/v/}; kind=other
  [ -d "$d/lib/splunk" ] && kind=var
  { [ -d "$d/system" ] && { [ -f "$d/splunk.version" ] || [ -d "$d/apps" ]; }; } && kind=etc
  echo "VOL $i $kind $(du -sk "$d" 2>/dev/null | cut -f1)"
  if [ "$kind" = var ]; then
    for ix in "$d"/lib/splunk/*/; do
      [ -d "$ix/db" ] || continue
      name=$(basename "$ix"); b=0; h=0; e=0; lo=9999999999; hi=0
      for bk in "$ix"db/db_* "$ix"db/hot_v1_* "$ix"colddb/db_*; do
        [ -d "$bk" ] || continue
        b=$((b+1)); case "$bk" in *hot_v1_*) h=$((h+1));; esac
        line=$(head -1 "$bk/Sources.data" 2>/dev/null)
        c=$(echo "$line" | awk -F'\t' '{gsub(/ /,"",$3); print $3+0}'); s=$(echo "$line" | awk -F'\t' '{print $4+0}'); f=$(echo "$line" | awk -F'\t' '{print $5+0}')
        e=$((e+${c:-0})); [ "${s:-0}" -gt 0 ] && [ "$s" -lt "$lo" ] && lo=$s; [ "${f:-0}" -gt "$hi" ] && hi=$f
      done
      [ "$lo" = 9999999999 ] && lo=0
      echo "IDX $i $name buckets=$b hot=$h events=$e earliest=$lo latest=$hi kb=$(du -sk "$ix" 2>/dev/null | cut -f1)"
    done
  fi
  if [ "$kind" = etc ]; then
    ver=$(sed -n 's/^VERSION=//p' "$d/splunk.version" 2>/dev/null | head -1); bld=$(sed -n 's/^BUILD=//p' "$d/splunk.version" 2>/dev/null | head -1)
    users=$(grep -c . "$d/passwd" 2>/dev/null || echo 0)
    apps=$(ls "$d/apps" 2>/dev/null | tr '\n' ',' | cut -c1-200)
    agentsec=missing; [ -d "$d/apps/agentsec" ] && { agentsec=empty_mountpoint; [ -n "$(ls "$d/apps/agentsec" 2>/dev/null)" ] && agentsec=has_content; }
    guid=no; [ -f "$d/instance.cfg" ] && guid=yes
    hec=none; f="$d/system/local/inputs.conf"; [ -f "$f" ] && { grep -q '^\[http' "$f" && hec=http_stanza_present || hec=inputs_without_http; }
    echo "ETC $i version=${ver:-?} build=${bld:-?} users=$users instance_cfg=$guid agentsec_app=$agentsec hec=$hec apps=$apps"
  fi
done
"""


def sh(cmd: list[str], stdin: str | None = None, timeout: int = 600) -> str:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, check=True).stdout


def parse_collector(text: str, names: list[str]) -> dict[str, dict]:
    """Collector output to {volume name: facts}. names[i] is the volume mounted at /v/i."""
    vols: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "VOL":
            vols[names[int(parts[1])]] = {"kind": parts[2], "kb": int(parts[3] or 0), "indexes": {}, "etc": {}}
        elif parts[0] == "IDX":
            v = vols[names[int(parts[1])]]
            v["indexes"][parts[2]] = {k: int(x) for k, x in (p.split("=") for p in parts[3:])}
        elif parts[0] == "ETC":
            vols[names[int(parts[1])]]["etc"] = dict(p.split("=", 1) for p in parts[2:])
    return vols


def pair_by_creation(var_created: dict[str, str], etc_created: dict[str, str], max_seconds: float = 3.0) -> dict[str, str]:
    """Pair each var volume with the etc volume created at (nearly) the same instant: one container creates both."""
    def ts(s: str) -> float:
        return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))).timestamp()
    pairs: dict[str, str] = {}
    used: set[str] = set()
    for v, vs in sorted(var_created.items(), key=lambda kv: ts(kv[1])):
        best = min(((abs(ts(es) - ts(vs)), e) for e, es in etc_created.items() if e not in used), default=None)
        if best and best[0] <= max_seconds:
            pairs[v] = best[1]
            used.add(best[1])
    return pairs


def referenced_by() -> dict[str, list[str]]:
    """volume name -> container names, from each container's mount list (docker ps --filter volume= is unreliable)."""
    ids = sh(["docker", "ps", "-aq"]).split()
    out: dict[str, list[str]] = {}
    if not ids:
        return out
    fmt = "{{.Name}}|{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}},{{end}}{{end}}"
    for line in sh(["docker", "inspect", "--format", fmt, *ids]).splitlines():
        name, _, vols = line.partition("|")
        for v in filter(None, vols.split(",")):
            out.setdefault(v, []).append(name.lstrip("/"))
    return out


def collect() -> dict[str, dict]:
    names = sh(["docker", "volume", "ls", "-q"]).split()
    mounts = [x for i, n in enumerate(names) for x in ("-v", f"{n}:/v/{i}:ro")]
    text = sh(["docker", "run", "--rm", "-i", *mounts, HELPER_IMAGE, "sh", "-s"], stdin=COLLECTOR)
    vols = parse_collector(text, names)
    fmt = "{{.Name}}|{{.CreatedAt}}|{{index .Labels \"com.docker.compose.project\"}}"
    for line in sh(["docker", "volume", "inspect", "--format", fmt, *names]).splitlines():
        n, created, proj = line.split("|")
        if n in vols:
            vols[n].update(created=created, project=proj or "-")
    for n, users in referenced_by().items():
        if n in vols:
            vols[n]["containers"] = users
    return vols


def epoch_day(e: int) -> str:
    return datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%d") if e else "-"


def report(vols: dict[str, dict]) -> list[str]:
    var = {n: v for n, v in vols.items() if v["kind"] == "var"}
    etc = {n: v for n, v in vols.items() if v["kind"] == "etc"}
    pairs = pair_by_creation({n: v["created"] for n, v in var.items()}, {n: v["created"] for n, v in etc.items()})
    rev = {e: v for v, e in pairs.items()}
    rows = [f"Splunk var volumes: {len(var)}   etc volumes: {len(etc)}   (pairing is by creation time, a heuristic)", ""]
    for n, v in sorted(var.items(), key=lambda kv: kv[1]["created"]):
        use = ",".join(v.get("containers", [])) or "ORPHANED (no container)"
        rows.append(f"VAR {n[:14]}  {v['kb'] // 1024} MB  created {v['created'][:19]}  project={v['project']}  used by: {use}")
        internal = sum(s["kb"] for ix, s in v["indexes"].items() if ix.startswith("_") or ix in ("fishbucket", "historydb", "summarydb", "defaultdb", "audit"))
        for ix, s in sorted(v["indexes"].items()):
            if s["events"] and not (ix.startswith("_") or ix in ("fishbucket", "historydb", "summarydb", "defaultdb", "audit")):
                rows.append(f"    index {ix:<24} events={s['events']:<7} buckets={s['buckets']} (hot {s['hot']})  "
                            f"{epoch_day(s['earliest'])} to {epoch_day(s['latest'])}  {s['kb'] // 1024} MB")
        rows.append(f"    (Splunk internal indexes: {internal // 1024} MB, not listed)")
        e = pairs.get(n)
        rows.append(f"    paired etc: {e[:14] if e else 'none found'}")
    rows.append("")
    for n, v in sorted(etc.items(), key=lambda kv: kv[1]["created"]):
        e = v["etc"]
        rows.append(f"ETC {n[:14]}  {v['kb'] // 1024} MB  created {v['created'][:19]}  splunk {e.get('version')} build {e.get('build')}  "
                    f"users={e.get('users')}  hec={e.get('hec')}  agentsec_app={e.get('agentsec_app')}  "
                    f"used by: {','.join(v.get('containers', [])) or 'ORPHANED'}  var pair: {rev.get(n, 'none')[:14]}")
    return rows


def verify(src: str, dst: str) -> int:
    """Read-only. Returns 0 only when the files are identical AND the per-index event counts match."""
    diff = subprocess.run(["docker", "run", "--rm", "-v", f"{src}:/a:ro", "-v", f"{dst}:/b:ro", HELPER_IMAGE, "diff", "-rq", "/a", "/b"],
                          capture_output=True, text=True)
    print("diff -rq:", "IDENTICAL" if diff.returncode == 0 else f"DIFFERENCES\n{diff.stdout[:2000]}{diff.stderr[:500]}")
    vols = collect()
    a, b = vols.get(src), vols.get(dst)
    ok = diff.returncode == 0
    if a and b and a["kind"] == "var":
        same = {k: (s["events"], s["buckets"]) for k, s in a["indexes"].items()} == {k: (s["events"], s["buckets"]) for k, s in b["indexes"].items()}
        print("index events/buckets:", "MATCH" if same else "MISMATCH")
        ok = ok and same
    print("RESULT:", "VERIFIED" if ok else "NOT VERIFIED")
    return 0 if ok else 1


def migration_plan(project: str, src_etc: str, src_var: str, dst_etc: str, dst_var: str, service_stop: str) -> str:
    q = shlex.quote
    lines = ["#!/bin/sh", "# PLAN ONLY. Generated text; the tool never runs it. Read every line, then run it yourself.",
             "set -eu", f"# Sources (never modified, never deleted): {src_etc} (etc), {src_var} (var)",
             f"# Destinations (must not exist or must be empty): {dst_etc} (etc), {dst_var} (var)", ""]
    lines += ["# 0. Free space: the copy needs as much space as the sources. Check first.", f"docker system df | head -3 && df -h /var/lib/docker 2>/dev/null || true", ""]
    lines += [f"# 1. Stop (do NOT remove) Splunk so the files are quiet. Stopping keeps the container and its volumes.", service_stop, ""]
    lines += ["# 2. Create the named destinations with the labels Compose expects, refusing to reuse an existing one.",
              f"for v in {q(dst_etc)} {q(dst_var)}; do if docker volume inspect \"$v\" >/dev/null 2>&1; then echo \"REFUSING: $v already exists\" >&2; exit 1; fi; done",
              f"docker volume create --label com.docker.compose.project={q(project)} --label com.docker.compose.volume=splunk_etc {q(dst_etc)}",
              f"docker volume create --label com.docker.compose.project={q(project)} --label com.docker.compose.volume=splunk_var {q(dst_var)}", ""]
    for src, dst in ((src_etc, dst_etc), (src_var, dst_var)):
        lines += [f"# 3. COPY (not move) {src} -> {dst}, preserving owner (uid {SPLUNK_UID}) and permissions",
                  f"docker run --rm -v {q(src)}:/src:ro -v {q(dst)}:/dst {HELPER_IMAGE} sh -c 'cd /src && tar cf - . | (cd /dst && tar xpf -)'", ""]
    lines += ["# 4. VERIFY before anything points at the copies (each must print VERIFIED)",
              f"python3 scripts/splunk_volumes.py verify {q(src_etc)} {q(dst_etc)}", f"python3 scripts/splunk_volumes.py verify {q(src_var)} {q(dst_var)}", "",
              "# 5. Only now start Splunk on the NAMED volumes (compose file with splunk_etc/splunk_var), then check events with a real search.",
              "#    Keep the source volumes untouched until the owner signs off. Rollback = point compose back at the sources (see the migration doc).", ""]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory"); inv.add_argument("--json", action="store_true")
    ver = sub.add_parser("verify"); ver.add_argument("src"); ver.add_argument("dst")
    pl = sub.add_parser("plan")
    for a in ("src-etc", "src-var", "dst-etc", "dst-var"):
        pl.add_argument(f"--{a}", required=True)
    pl.add_argument("--project", default="agentseclab")
    pl.add_argument("--stop-cmd", default="docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env stop splunk")
    a = ap.parse_args(argv)
    if a.cmd == "inventory":
        vols = collect()
        print(json.dumps(vols, indent=1) if a.json else "\n".join(report(vols)))
        return 0
    if a.cmd == "verify":
        return verify(a.src, a.dst)
    print(migration_plan(a.project, a.src_etc, a.src_var, a.dst_etc, a.dst_var, a.stop_cmd), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
