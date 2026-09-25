"""Controlled failures for external evidence tooling."""

from __future__ import annotations

import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentsec.external_evidence.garak import GarakEvaluationAdapter
from agentsec.external_evidence.garak_pack import events_from_pack as garak_events
from agentsec.scanners.hec_events import events_from_pack as scanner_events
from scripts import ingest_lab_mcp_catalog_scanner_hec as ingest


def test_hec_unavailable_is_explicit(monkeypatch):
    monkeypatch.setattr(ingest, "load_env_value", lambda _key: "not-printed")

    def unavailable(*_args, **_kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(ingest.urllib.request, "urlopen", unavailable)
    with pytest.raises(RuntimeError, match="HEC unavailable; no evidence was submitted"):
        ingest.post_hec({"event": {"evidence": "bounded"}})


def test_splunk_unavailable_is_explicit(monkeypatch):
    monkeypatch.setattr(ingest, "load_env_value", lambda _key: "not-printed")
    monkeypatch.setattr(
        ingest.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Splunk unavailable",
        ),
    )
    with pytest.raises(RuntimeError, match="Splunk search unavailable or failed"):
        ingest.splunk_search("| makeresults")


def test_missing_cisco_and_garak_packs_fail_closed(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        scanner_events(tmp_path / "missing-cisco-pack")
    with pytest.raises(FileNotFoundError):
        garak_events(tmp_path / "missing-garak-pack")


def test_malformed_garak_evidence_is_rejected(tmp_path: Path):
    report = tmp_path / "malformed.jsonl"
    report.write_text("{not-json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid garak JSONL at line 1"):
        GarakEvaluationAdapter(
            report_path=report,
            raw_evidence_ref="raw/malformed.jsonl",
        ).records()
