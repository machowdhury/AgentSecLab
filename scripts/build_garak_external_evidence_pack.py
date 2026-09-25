#!/usr/bin/env python3
"""Build the P1A path-sanitized garak evidence pack."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from agentsec.external_evidence.garak_pack import write_garak_evidence_pack  # noqa: E402

DEFAULT_REPORT = (
    ROOT
    / "artifacts"
    / "garak-p1a"
    / "data"
    / "garak"
    / "runs"
    / "agentsec-p1a.report.jsonl"
)


def main() -> None:
    report = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_REPORT
    pack = write_garak_evidence_pack(
        native_report=report,
        packs_root=ROOT / "docs" / "p1a-evidence",
        repo_root=ROOT,
        config_ref="tools/garak/agentsec-p1a.yaml",
        ingest_timestamp="2026-09-24T23:15:00Z",
    )
    print(pack.relative_to(ROOT))


if __name__ == "__main__":
    main()
