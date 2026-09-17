"""Cisco mcp-scanner wrapper safety. Does not execute the real scanner."""

from __future__ import annotations

import inspect
import subprocess
from pathlib import Path

import pytest

from agentsec.scanners.cisco_mcp_scanner import (
    FORBIDDEN_TOKENS,
    build_static_yara_argv,
    run_static_yara_scan,
    scanner_env,
    validate_static_argv,
)
from agentsec.scanners.evidence import new_scan_id, normalize_scan, write_scan_bundle
from agentsec.scanners.models import EVIDENCE_CLASS, ScanProcessResult
from agentsec.scanners.catalog_export import write_catalog_artifact


def test_argv_is_static_yara_only(tmp_path):
    artifact = tmp_path / "tools.json"
    artifact.write_text("{}", encoding="utf-8")
    argv = build_static_yara_argv("/opt/mcp-scanner", artifact)
    assert argv[1:8] == [
        "--analyzers",
        "yara",
        "--format",
        "raw",
        "--log-level",
        "error",
        "static",
    ]
    assert argv[8:10] == ["--tools", str(artifact.resolve())]
    validate_static_argv(argv)


def test_forbidden_flags_rejected(tmp_path):
    artifact = tmp_path / "tools.json"
    artifact.write_text("{}", encoding="utf-8")
    argv = build_static_yara_argv("/opt/mcp-scanner", artifact)
    with pytest.raises(ValueError):
        validate_static_argv(argv + ["--server-url", "http://127.0.0.1"])
    with pytest.raises(ValueError):
        validate_static_argv(["mcp-scanner", "--analyzers", "yara,llm", "static", "--tools", str(artifact)])
    assert "--stdio-command" in FORBIDDEN_TOKENS


def test_wrapper_source_has_no_shell_true():
    source = inspect.getsource(run_static_yara_scan)
    assert "shell=True" not in source
    assert "shell=False" in source
    assert "subprocess.run" in source


def test_timeout_and_exit_code_handling(tmp_path, monkeypatch):
    artifact = tmp_path / "tools.json"
    artifact.write_text("{}", encoding="utf-8")

    def fake_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="mcp-scanner", timeout=1, output=b"", stderr=b"t")

    monkeypatch.setattr(subprocess, "run", fake_timeout)
    result = run_static_yara_scan(artifact, binary="/opt/mcp-scanner", timeout_sec=1)
    assert result.timed_out is True
    assert result.exit_code is None

    def fake_fail(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=["x"], returncode=7, stdout=b"[]", stderr=b"e")

    monkeypatch.setattr(subprocess, "run", fake_fail)
    result = run_static_yara_scan(artifact, binary="/opt/mcp-scanner")
    assert result.exit_code == 7
    assert result.stdout == b"[]"


def test_scanner_env_strips_secrets():
    env = scanner_env(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-test-not-a-real-key",
            "MCP_SCANNER_API_KEY": "secret",
            "SPLUNK_PASSWORD": "n",
            "HOME": "/tmp",
        }
    )
    assert "OPENAI_API_KEY" not in env
    assert "MCP_SCANNER_API_KEY" not in env
    assert "SPLUNK_PASSWORD" not in env
    assert env["PATH"] == "/usr/bin"


def test_evidence_bundle_preserves_raw_and_has_no_run_id(tmp_path):
    data, artifact = write_catalog_artifact(tmp_path / "in" / "tools.json", "NORMAL")
    process = ScanProcessResult(
        argv=("mcp-scanner", "static", "--tools", str(tmp_path / "in" / "tools.json")),
        exit_code=0,
        stdout=b'[{"tool_name":"lookup_policy","is_safe":false,"findings":[{"severity":"HIGH","threat_category":"TOOL_POISONING","summary":"hit","analyzer":"YARA"}]}]',
        stderr=b"",
        timed_out=False,
        duration_ms=12,
        binary="/opt/mcp-scanner",
    )
    scan_id = new_scan_id()
    assert "agentsec.run.id" not in scan_id
    normalized = normalize_scan(scan_id=scan_id, artifact=artifact, process=process)
    assert normalized.evidence_class == EVIDENCE_CLASS
    pack = write_scan_bundle(
        tmp_path / "packs",
        scan_id=scan_id,
        fixture="NORMAL",
        process=process,
        artifact=artifact,
        input_bytes=data,
        normalized=normalized,
    )
    assert (pack / "raw" / "scanner-output.json").read_bytes() == process.stdout
    assert (pack / "input" / "tools.json").read_bytes() == data
    manifest = (pack / "manifest.json").read_text(encoding="utf-8")
    assert '"agentsec.run.id": null' in manifest
    assert "OBSERVED_SCANNER" in manifest
    assert "native_severity" in (pack / "normalized" / "findings.json").read_text(encoding="utf-8")
