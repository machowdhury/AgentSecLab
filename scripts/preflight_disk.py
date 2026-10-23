#!/usr/bin/env python3
"""Disk check for lab-preflight.sh. Read-only. Prints rows: PASS|WARN|FAIL|INFO <message>.

Measures the filesystem that actually holds the deployment (the repository root) and Docker's storage root, and reports the
TIGHTEST of them. A RAM-backed filesystem (tmpfs, ramfs) says nothing about disk, so it is never counted: a lab run from /tmp
used to read 'plenty free' while the real disk was 95% full.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

FAIL_BELOW_KIB = 2 * 1024 * 1024     # 2 GB
WARN_BELOW_KIB = 8 * 1024 * 1024     # 8 GB planning floor (not a measured minimum)
SPLUNK_MIN_FREE_KIB = 5000 * 1024    # Splunk's default minFreeSpace; overrides are not checked here
RAM_FS = frozenset({"tmpfs", "ramfs", "devtmpfs"})


def mount_fstype(path: str, mounts_text: str) -> str:
    """Filesystem type of the longest mount point that contains path (Linux /proc/mounts format); '' if unknown."""
    real = os.path.realpath(path)
    best, best_type = "", ""
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        point = parts[1].replace("\\040", " ")
        if (real == point or real.startswith(point.rstrip("/") + "/") or point == "/") and len(point) >= len(best):
            best, best_type = point, parts[2]
    return best_type


def avail_kib(path: str) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize // 1024


def gb(kib: int) -> str:
    return f"{kib / 1024 / 1024:.1f}"


def evaluate(root: str, docker_root: str, mounts_text: str, avail=avail_kib) -> list[str]:
    rows: list[str] = []
    counted: list[tuple[str, str, int]] = []
    candidates = [("deployment directory", root)]
    if docker_root:
        if os.path.isdir(docker_root):
            candidates.append(("Docker storage root", docker_root))
        else:
            rows.append(f"INFO  Docker storage root {docker_root} is not on this host's filesystem (for example Docker Desktop's VM); "
                        "its free space is NOT MEASURED here.")
    for label, path in candidates:
        fstype = mount_fstype(path, mounts_text)
        if fstype in RAM_FS:
            rows.append(f"INFO  {label} {path} is on a RAM-backed {fstype} filesystem. It is not counted: it says nothing about disk.")
            continue
        kib = avail(path)
        counted.append((label, path, kib))
        rows.append(f"INFO  CURRENTLY AVAILABLE disk for the {label} ({path}{', ' + fstype if fstype else ''}): {gb(kib)} GB ({kib} KiB)")
    rows.append("INFO  MINIMUM SUPPORTED disk: NOT BENCHMARKED")
    rows.append("INFO  RECOMMENDED planning floor: 8 GB free before a first install. That floor is not a measured minimum.")
    if not counted:
        rows.append("WARN  free disk could NOT be measured on a real disk filesystem. Do not read this as a pass.")
        return rows
    label, path, kib = min(counted, key=lambda c: c[2])
    if kib < FAIL_BELOW_KIB:
        rows.append(f"FAIL  Insufficient free disk for AgentSec on the {label} ({path}). Available: {gb(kib)} GB. Recommended planning floor: 8 GB. "
                    "Free disk space and rerun ./scripts/lab-preflight.sh. This check does not delete Docker data.")
    elif kib < WARN_BELOW_KIB:
        rows.append(f"WARN  free disk {gb(kib)} GB on the {label} ({path}) is below the 8 GB planning floor. Splunk images are large. "
                    "This is not a measured minimum and this check does not delete Docker data.")
    else:
        rows.append(f"PASS  free disk {gb(kib)} GB on the tightest filesystem ({label}) is at or above the 8 GB planning floor (not a measured minimum)")
    if kib < 2 * SPLUNK_MIN_FREE_KIB:
        rows.append(f"INFO  Splunk's default minimum free space is 5000 MB (overrides are not checked here); with {gb(kib)} GB free, "
                    "a large image build or model pull can push the host under it and halt indexing.")
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True)
    ap.add_argument("--docker-root", default="")
    ap.add_argument("--mounts", default="/proc/mounts", help="mount table to read (Linux format); a missing file means unknown")
    a = ap.parse_args(argv)
    try:
        mounts = Path(a.mounts).read_text(encoding="utf-8")
    except OSError:
        mounts = ""
    print("\n".join(evaluate(a.root, a.docker_root.strip(), mounts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
