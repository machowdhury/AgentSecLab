#!/usr/bin/env python3
"""Run pinned Cisco mcp-scanner static YARA against LAB-MCP-CATALOG fixtures.

Does not authorize. Does not ingest Splunk. Does not start Phase 9C.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.mcp.catalog import FIXTURE_MALICIOUS, FIXTURE_NORMAL  # noqa: E402
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy  # noqa: E402
from agentsec.scanners.cisco_mcp_scanner import resolve_scanner_binary, scanner_identity  # noqa: E402
from agentsec.scanners.evidence import export_and_scan_fixture  # noqa: E402


def _copy_pack(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 9B static Cisco mcp-scanner")
    parser.add_argument(
        "--packs-root",
        default=str(ROOT / "artifacts" / "scanners"),
        help="Evidence pack root (default: artifacts/scanners)",
    )
    parser.add_argument(
        "--commit-copy",
        default=str(ROOT / "docs" / "phase9b-evidence"),
        help="Optional copy of packs for documentation (not Splunk)",
    )
    args = parser.parse_args()
    binary = resolve_scanner_binary()
    if binary is None:
        print("cisco mcp-scanner binary not found. Install pin first.", file=sys.stderr)
        return 2
    policy_before = coded_policy()
    packs_root = Path(args.packs_root)
    summary = {
        "scanner": {
            "binary": str(binary),
            "identity": scanner_identity().__dict__,
        },
        "boundary": "SCANNER FINDING != AUTHORIZATION DECISION",
        "scans": [],
    }
    for fixture in (FIXTURE_NORMAL, FIXTURE_MALICIOUS):
        pack, scan = export_and_scan_fixture(
            fixture=fixture,
            packs_root=packs_root,
            binary=binary,
        )
        row = {
            "fixture": fixture,
            "scan_id": scan.scan_id,
            "pack": str(pack),
            "artifact_sha256": scan.artifact.sha256,
            "description_sha256": scan.artifact.description_sha256,
            "bytes": scan.artifact.bytes_len,
            "exit_code": scan.exit_code,
            "timed_out": scan.timed_out,
            "finding_count": scan.finding_count,
            "classification": scan.classification,
            "llm_used": scan.llm_used,
            "network_required": scan.network_required,
            "target_executed": scan.target_executed,
            "parse_error": scan.parse_error,
            "findings": [
                {
                    "native_rule_id": f.native_rule_id,
                    "native_category": f.native_category,
                    "native_severity": f.native_severity,
                    "summary": f.summary,
                    "tool_name": f.tool_name,
                    "analyzer": f.analyzer,
                }
                for f in scan.findings
            ],
        }
        summary["scans"].append(row)
        print(json.dumps(row, indent=2))
        commit_root = Path(args.commit_copy)
        _copy_pack(pack, commit_root / f"{fixture.lower()}-{scan.scan_id}")
    policy_after = coded_policy()
    summary["policy_unchanged"] = (
        policy_before.allowed_tools == ALLOWED_TOOLS == policy_after.allowed_tools
    )
    (packs_root / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    Path(args.commit_copy).mkdir(parents=True, exist_ok=True)
    (Path(args.commit_copy) / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    if not summary["policy_unchanged"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
