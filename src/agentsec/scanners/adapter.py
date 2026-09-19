"""Parse untrusted Cisco mcp-scanner JSON. Never execute strings from output."""

from __future__ import annotations

import json
import re
from typing import Any

from agentsec.scanners.models import (
    CLASS_DETECTED,
    CLASS_ERROR,
    CLASS_NOT_DETECTED,
    CLASS_UNSUPPORTED,
    MAX_FINDINGS,
    MAX_OUTPUT_BYTES,
    MAX_STRING,
    NativeFinding,
)

_ANSI_RE = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: object, *, limit: int = MAX_STRING) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return None
    text = _CTRL_RE.sub("", text)
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return None
    if len(text) > limit:
        text = text[:limit]
    return text


def strip_ansi(data: bytes) -> bytes:
    if len(data) > MAX_OUTPUT_BYTES:
        data = data[:MAX_OUTPUT_BYTES]
    return _ANSI_RE.sub(b"", data)


def classify_malicious_scan(
    *,
    fixture: str,
    timed_out: bool,
    exit_code: int | None,
    parse_error: str | None,
    findings: tuple[NativeFinding, ...],
    unsupported: bool = False,
) -> str | None:
    if fixture != "MALICIOUS":
        return None
    if unsupported or parse_error == "unsupported_static_input":
        return CLASS_UNSUPPORTED
    if timed_out or parse_error:
        return CLASS_ERROR
    if exit_code != 0:
        return CLASS_ERROR
    if findings:
        return CLASS_DETECTED
    return CLASS_NOT_DETECTED


def _finding_from_mapping(row: dict[str, Any], *, tool_name: str | None) -> NativeFinding:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    raw = details.get("raw_response") if isinstance(details.get("raw_response"), dict) else {}
    rule = (
        sanitize_text(row.get("rule"))
        or sanitize_text(raw.get("rule"))
        or sanitize_text(row.get("threat_category"))
        or sanitize_text(row.get("threat_type"))
        or sanitize_text(details.get("threat_type"))
    )
    confidence = sanitize_text(row.get("confidence")) or sanitize_text(details.get("confidence"))
    return NativeFinding(
        native_rule_id=rule,
        native_category=sanitize_text(row.get("threat_category"))
        or sanitize_text(row.get("category")),
        native_severity=sanitize_text(row.get("severity")),
        native_confidence=confidence,
        title=sanitize_text(row.get("title")) or sanitize_text(row.get("threat_category")),
        summary=sanitize_text(row.get("summary")) or sanitize_text(row.get("description")),
        tool_name=sanitize_text(tool_name) or sanitize_text(row.get("tool_name")),
        analyzer=sanitize_text(row.get("analyzer")),
        extras={},
    )


def _findings_from_tool_row(row: dict[str, Any]) -> list[NativeFinding]:
    tool_name = row.get("tool_name") or row.get("name")
    found: list[NativeFinding] = []
    findings = row.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                found.append(_finding_from_mapping(item, tool_name=tool_name if isinstance(tool_name, str) else None))
    elif isinstance(findings, dict):
        for analyzer_name, payload in findings.items():
            items: list[Any]
            if isinstance(payload, list):
                items = payload
            elif isinstance(payload, dict):
                nested = payload.get("findings") or payload.get("threat_names")
                if isinstance(nested, list) and nested and isinstance(nested[0], str):
                    items = [
                        {
                            "analyzer": analyzer_name,
                            "severity": payload.get("severity"),
                            "threat_category": nested[0],
                            "summary": payload.get("threat_summary")
                            or payload.get("summary"),
                            "threat_names": nested,
                        }
                    ]
                elif isinstance(nested, list):
                    items = nested
                else:
                    items = [payload]
            else:
                continue
            for item in items:
                if isinstance(item, dict):
                    merged = dict(item)
                    merged.setdefault("analyzer", analyzer_name)
                    found.append(
                        _finding_from_mapping(
                            merged,
                            tool_name=tool_name if isinstance(tool_name, str) else None,
                        )
                    )
    is_safe = row.get("is_safe")
    if is_safe is False and not found:
        found.append(
            NativeFinding(
                native_rule_id=None,
                native_category=None,
                native_severity=sanitize_text(row.get("severity")),
                native_confidence=None,
                title=sanitize_text(tool_name),
                summary=sanitize_text(row.get("status")) or "is_safe=false",
                tool_name=sanitize_text(tool_name) if isinstance(tool_name, str) else None,
                analyzer=None,
                extras={},
            )
        )
    return found


def parse_scanner_stdout(stdout: bytes) -> tuple[tuple[NativeFinding, ...], str | None]:
    """Return findings and optional parse_error. Does not invent severity."""
    cleaned = strip_ansi(stdout).lstrip()
    if not cleaned.strip():
        return (), None
    try:
        text = cleaned.decode("utf-8")
    except UnicodeDecodeError:
        text = cleaned.decode("utf-8", errors="replace")
        return (), "malformed_encoding"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return (), "malformed_json"

    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        rows = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        for key in ("scan_results", "results", "tools", "formatted_output"):
            value = payload.get(key)
            if isinstance(value, list):
                rows = [item for item in value if isinstance(item, dict)]
                break
        if not rows:
            rows = [payload]
    else:
        return (), "unexpected_json_type"

    findings: list[NativeFinding] = []
    for row in rows:
        findings.extend(_findings_from_tool_row(row))
        if len(findings) >= MAX_FINDINGS:
            findings = findings[:MAX_FINDINGS]
            break
    return tuple(findings), None
