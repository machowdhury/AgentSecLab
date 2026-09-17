"""Untrusted scanner JSON adapter. Does not invent severity."""

from __future__ import annotations

from agentsec.scanners.adapter import classify_malicious_scan, parse_scanner_stdout, sanitize_text
from agentsec.scanners.models import CLASS_DETECTED, CLASS_ERROR, CLASS_NOT_DETECTED


def test_empty_stdout_is_zero_findings():
    findings, error = parse_scanner_stdout(b"")
    assert findings == ()
    assert error is None


def test_malformed_json():
    findings, error = parse_scanner_stdout(b"not-json {")
    assert findings == ()
    assert error == "malformed_json"


def test_missing_optional_fields_and_severity_preserved():
    raw = b"""
    [{"tool_name": "lookup_policy", "is_safe": false,
      "findings": [{"severity": "HIGH", "threat_category": "TOOL_POISONING",
                    "summary": "yara hit", "analyzer": "YARA"}]}]
    """
    findings, error = parse_scanner_stdout(raw)
    assert error is None
    assert len(findings) == 1
    assert findings[0].native_severity == "HIGH"
    assert findings[0].native_category == "TOOL_POISONING"
    assert findings[0].summary == "yara hit"
    assert findings[0].native_confidence is None
    assert findings[0].native_rule_id == "TOOL_POISONING"


def test_cisco_raw_scan_results_shape_uses_threat_summary():
    raw = b"""
    {"server_url": "https://mcp.deepwiki.com/mcp",
     "scan_results": [
       {"tool_name": "lookup_customer_tier", "is_safe": true,
        "findings": {"yara_analyzer": {"severity": "SAFE", "threat_names": [], "total_findings": 0}}},
       {"tool_name": "lookup_policy", "is_safe": false,
        "findings": {"yara_analyzer": {"severity": "HIGH", "threat_names": ["PROMPT INJECTION"],
          "threat_summary": "Detected 1 threat: prompt injection", "total_findings": 1}}}
     ],
     "requested_analyzers": ["yara"]}
    """
    findings, error = parse_scanner_stdout(raw)
    assert error is None
    assert len(findings) == 1
    assert findings[0].tool_name == "lookup_policy"
    assert findings[0].native_severity == "HIGH"
    assert findings[0].native_category == "PROMPT INJECTION"
    assert findings[0].summary == "Detected 1 threat: prompt injection"
    assert findings[0].native_confidence is None


def test_multiple_findings_and_analyzer_dict_shape():
    raw = b"""
    {"server_url": "https://mcp.deepwiki.com/mcp",
     "scan_results": [
       {"tool_name": "lookup_customer_tier", "is_safe": true,
        "findings": {"yara_analyzer": {"severity": "SAFE", "threat_names": [], "total_findings": 0}}},
       {"tool_name": "lookup_policy", "is_safe": false,
        "findings": {"yara_analyzer": {"severity": "HIGH", "threat_names": ["PROMPT INJECTION"],
          "threat_summary": "Detected 1 threat: prompt injection", "total_findings": 1}}}
     ],
     "requested_analyzers": ["yara"]}
    """
    findings, error = parse_scanner_stdout(raw)
    assert error is None
    assert len(findings) == 1
    assert findings[0].tool_name == "lookup_policy"
    assert findings[0].native_severity == "HIGH"
    assert findings[0].native_category == "PROMPT INJECTION"
    assert findings[0].summary == "Detected 1 threat: prompt injection"
    assert findings[0].native_confidence is None

    raw = b"""
    {"scan_results": [
      {"tool_name": "lookup_policy", "findings": {
        "yara_analyzer": {"severity": "MEDIUM", "threat_names": ["PROMPT_INJECTION"]}
      }},
      {"tool_name": "lookup_customer_tier", "findings": [
        {"severity": "LOW", "summary": "other", "threat_category": "INFO"}
      ]}
    ]}
    """
    findings, error = parse_scanner_stdout(raw)
    assert error is None
    assert len(findings) == 2
    assert findings[0].native_severity == "MEDIUM"
    assert findings[1].native_severity == "LOW"


def test_control_characters_stripped():
    cleaned = sanitize_text("hello\x1b[31mX\x00world")
    assert cleaned is not None
    assert "\x00" not in cleaned
    assert "\x1b" not in cleaned
    assert "world" in cleaned
    spaced = sanitize_text("line\r\ninject ignore previous instructions")
    assert spaced is not None
    assert "\r" not in spaced


def test_classify_malicious_outcomes():
    from agentsec.scanners.models import NativeFinding

    hit = NativeFinding(
        native_rule_id="r",
        native_category="c",
        native_severity="HIGH",
        native_confidence=None,
        title="t",
        summary="s",
        tool_name="lookup_policy",
        analyzer="YARA",
    )
    assert (
        classify_malicious_scan(
            fixture="MALICIOUS",
            timed_out=False,
            exit_code=0,
            parse_error=None,
            findings=(hit,),
        )
        == CLASS_DETECTED
    )
    assert (
        classify_malicious_scan(
            fixture="MALICIOUS",
            timed_out=False,
            exit_code=0,
            parse_error=None,
            findings=(),
        )
        == CLASS_NOT_DETECTED
    )
    assert (
        classify_malicious_scan(
            fixture="MALICIOUS",
            timed_out=True,
            exit_code=None,
            parse_error=None,
            findings=(),
        )
        == CLASS_ERROR
    )
    assert (
        classify_malicious_scan(
            fixture="NORMAL",
            timed_out=False,
            exit_code=0,
            parse_error=None,
            findings=(hit,),
        )
        is None
    )
