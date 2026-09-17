"""Controlled Cisco mcp-scanner static YARA wrapper.

Does not authorize. Does not connect to MCP. Does not use shell=True.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from agentsec.scanners.models import (
    DEFAULT_TIMEOUT_SEC,
    MAX_OUTPUT_BYTES,
    ScanProcessResult,
    ScannerIdentity,
)

PIN_PATH = Path(__file__).resolve().parents[3] / "tools" / "cisco-mcp-scanner" / "pin.json"
LOCAL_VENV_BIN = (
    Path(__file__).resolve().parents[3] / "tools" / "cisco-mcp-scanner" / ".venv" / "bin" / "mcp-scanner"
)

ALLOWED_ANALYZERS = ("yara",)
FORBIDDEN_TOKENS = frozenset(
    {
        "--server-url",
        "--stdio-command",
        "--stdio-arg",
        "--stdio-args",
        "--scan-known-configs",
        "--api-key",
        "--llm-api-key",
        "--endpoint-url",
        "--bearer-token",
        "--dangerously-run-mcp-servers",
        "remote",
        "stdio",
        "llm",
        "api",
        "behavioral",
        "virustotal",
        "pypi-scan",
    }
)

STRIP_ENV_PREFIXES = (
    "MCP_SCANNER",
    "OPENAI",
    "ANTHROPIC",
    "AZURE_OPENAI",
    "AWS_SECRET",
    "AWS_ACCESS",
    "SNYK",
    "SPLUNK",
    "CISCO_AI",
    "LLM_",
)
STRIP_ENV_EXACT = frozenset(
    {
        "API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SNYK_TOKEN",
        "SPLUNK_PASSWORD",
        "HEC_TOKEN",
        "MCP_SCANNER_API_KEY",
        "MCP_SCANNER_LLM_API_KEY",
    }
)


def load_pin(path: Path | None = None) -> dict:
    pin_file = path or PIN_PATH
    return json.loads(pin_file.read_text(encoding="utf-8"))


def scanner_identity(pin: dict | None = None) -> ScannerIdentity:
    data = pin if pin is not None else load_pin()
    return ScannerIdentity(
        name=data["scanner.name"],
        version=data["scanner.version"],
        repository=data["scanner.repository"],
        commit=data["github.main.commit"],
        license=data["scanner.license"],
        package=data["scanner.package"],
        cli=data["scanner.cli"],
        wheel_sha256=data.get("pypi.wheel.sha256"),
    )


def resolve_scanner_binary() -> Path | None:
    env = os.environ.get("AGENTSEC_MCP_SCANNER_BIN")
    if env:
        candidate = Path(env)
        if candidate.is_file():
            return candidate
        return None
    if LOCAL_VENV_BIN.is_file():
        return LOCAL_VENV_BIN
    found = shutil.which("mcp-scanner")
    return Path(found) if found else None


def build_static_yara_argv(binary: Path | str, artifact: Path | str) -> list[str]:
    artifact_path = Path(artifact)
    if not artifact_path.is_file():
        raise FileNotFoundError(artifact_path)
    argv = [
        str(binary),
        "--analyzers",
        "yara",
        "--format",
        "raw",
        "--log-level",
        "error",
        "static",
        "--tools",
        str(artifact_path.resolve()),
    ]
    validate_static_argv(argv)
    return argv


def validate_static_argv(argv: list[str]) -> None:
    if not argv:
        raise ValueError("empty scanner argv")
    lowered = [part.lower() for part in argv[1:]]
    joined = " ".join(lowered)
    for token in FORBIDDEN_TOKENS:
        if token.startswith("--"):
            if token in lowered:
                raise ValueError(f"forbidden scanner flag: {token}")
        elif token in lowered:
            raise ValueError(f"forbidden scanner mode: {token}")
    if "--analyzers" not in lowered:
        raise ValueError("static scan must pin --analyzers yara")
    analyzers_idx = lowered.index("--analyzers")
    if analyzers_idx + 1 >= len(lowered) or lowered[analyzers_idx + 1] != "yara":
        raise ValueError("canonical path allows only the yara analyzer")
    if "static" not in lowered or "--tools" not in lowered:
        raise ValueError("canonical path must use static --tools")
    if "llm" in joined.split() or ",llm" in joined or "llm," in joined:
        raise ValueError("LLM analyzer is not allowed on the canonical path")
    if any(part == "-c" or part == "/bin/sh" or part == "bash" for part in argv):
        raise ValueError("shell invocation is not allowed")


def scanner_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base if base is not None else os.environ)
    for key in list(env):
        upper = key.upper()
        if upper in STRIP_ENV_EXACT or any(upper.startswith(prefix) for prefix in STRIP_ENV_PREFIXES):
            env.pop(key, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_static_yara_scan(
    artifact: Path | str,
    *,
    binary: Path | str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> ScanProcessResult:
    resolved = Path(binary) if binary is not None else resolve_scanner_binary()
    if resolved is None:
        raise FileNotFoundError("cisco mcp-scanner binary not found")
    argv = build_static_yara_argv(resolved, artifact)
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_sec,
            check=False,
            shell=False,
            env=scanner_env(),
        )
        stdout = completed.stdout[:MAX_OUTPUT_BYTES]
        stderr = completed.stderr[:MAX_OUTPUT_BYTES]
        exit_code = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or b"")[:MAX_OUTPUT_BYTES]
        stderr = (exc.stderr or b"")[:MAX_OUTPUT_BYTES]
        exit_code = None
    duration_ms = int((time.monotonic() - started) * 1000)
    return ScanProcessResult(
        argv=tuple(argv),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration_ms=duration_ms,
        binary=str(resolved),
    )
