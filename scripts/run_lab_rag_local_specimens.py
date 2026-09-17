"""Generate local LAB-RAG-001 evidence packs. Not Splunk validation.

Usage:
  .venv/bin/python scripts/run_lab_rag_local_specimens.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentsec.mcp.registry import default_registry
from agentsec.rag.fixtures import DOCUMENT_ID_MALICIOUS, DOCUMENT_ID_NORMAL
from agentsec.rag.pipeline import run_rag_retrieve
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _settings(*, profile: str):
    os.environ["AGENTSEC_OTEL_ENABLED"] = "false"
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, document_id: str):
    settings = _settings(profile=profile)
    memory = MemorySink()
    return run_rag_retrieve(
        document_id=document_id,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )


def summarize(label: str, result) -> dict:
    return {
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "document.id": result.document_id,
        "content.hash": result.content_hash,
        "context.decision": result.context_control_decision,
        "context.reason": result.context_control_reason,
        "follow_on.decision": result.follow_on_decision,
        "follow_on.reason": result.follow_on_reason,
        "lookup_customer_tier": result.lookup_customer_tier_handler_count,
        "schema": "1.6.0",
        "evidence_dir": result.evidence_dir,
        "splunk.verified": False,
    }


def main() -> None:
    rows = []
    a = _run(mode="BASELINE", profile="defended", document_id=DOCUMENT_ID_NORMAL)
    rows.append(summarize("A BASELINE", a))
    b = _run(mode="ATTACK", profile="vulnerable", document_id=DOCUMENT_ID_MALICIOUS)
    rows.append(summarize("B ATTACK", b))
    c = _run(mode="RETEST", profile="defended", document_id=DOCUMENT_ID_MALICIOUS)
    rows.append(summarize("C RETEST", c))
    print(json.dumps(rows, indent=2))
    artifacts = Path(a.evidence_dir).parent
    (artifacts / "lab-rag-001-local-summary.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    reset_settings_cache()


if __name__ == "__main__":
    main()
