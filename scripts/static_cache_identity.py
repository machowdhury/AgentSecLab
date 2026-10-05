#!/usr/bin/env python3
"""Record the Splunk app-static cache identity for the AgentSec app.

Splunk serves a Simple XML dashboard's custom JavaScript from

    /<locale>/static/@<splunk build>.<push version>-<app build>/app/agentsec/<file>

The `<app build>` segment is `[install] build` in `splunk_app/agentsec/default/app.conf`.
It is the only part of that cache key AgentSec controls. If a browser-served asset
under `splunk_app/agentsec/appserver/static/` changes while the app build stays the
same, the deployed URL is unchanged and a browser can keep an older cached copy.

This script computes a digest over those assets and compares it with
`splunk_app/static_cache_identity.json`. The lock file lives outside
`splunk_app/agentsec/` so it is not staged into the Splunk app.

    python3 scripts/static_cache_identity.py --check
    python3 scripts/static_cache_identity.py --write   # after bumping [install] build

This is a repository contract. It does not prove a deployed Splunk URL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "splunk_app" / "agentsec" / "appserver" / "static"
APP_CONF = ROOT / "splunk_app" / "agentsec" / "default" / "app.conf"
LOCK = ROOT / "splunk_app" / "static_cache_identity.json"


def app_build() -> int:
    """Read `[install] build` from the packaged app.conf."""
    section = None
    for line in APP_CONF.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section != "install":
            continue
        match = re.match(r"build\s*=\s*(\d+)\s*$", stripped)
        if match:
            return int(match.group(1))
    raise SystemExit(f"[install] build missing from {APP_CONF}")


def assets_digest() -> str:
    """Digest every browser-served file under appserver/static, path included."""
    digest = hashlib.sha256()
    for path in sorted(p for p in STATIC_DIR.rglob("*") if p.is_file()):
        digest.update(path.relative_to(STATIC_DIR).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_lock() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def write_lock() -> int:
    build = app_build()
    digest = assets_digest()
    data = load_lock()
    history = [entry for entry in data["history"] if entry["app_build"] != build]
    history.append({"app_build": build, "assets_sha256": digest})
    history.sort(key=lambda entry: entry["app_build"])
    data["app_build"] = build
    data["assets_sha256"] = digest
    data["history"] = history
    LOCK.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"app build {build} -> {digest}")
    return 0


def check_lock() -> int:
    build = app_build()
    digest = assets_digest()
    data = load_lock()
    problems = []
    if data["app_build"] != build:
        problems.append(f"lock app_build {data['app_build']} != app.conf build {build}")
    if data["assets_sha256"] != digest:
        problems.append(
            "appserver/static changed under app build "
            f"{build}. Bump [install] build in app.conf, then run "
            "python3 scripts/static_cache_identity.py --write"
        )
    for problem in problems:
        print(f"[static-cache-identity] {problem}", file=sys.stderr)
    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args()
    return write_lock() if args.write else check_lock()


if __name__ == "__main__":
    raise SystemExit(main())
