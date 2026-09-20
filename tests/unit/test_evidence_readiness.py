"""Bounded evidence probe: HEC/OTLP success is not EVIDENCE_READY."""

from agentsec.evidence_readiness import wait_for_searchable_evidence


def test_timeout_is_waiting_not_blocked_or_deny(tmp_path):
    calls = {"n": 0}

    def probe(_run_id):
        calls["n"] += 1
        return {"splunk_attempted": True, "splunk_ok": True, "splunk_count": 0, "error": None}

    times = iter([0.0, 0.0, 5.0])

    result = wait_for_searchable_evidence(
        "run-timeout",
        artifacts_dir=tmp_path,
        timeout_seconds=4,
        interval_seconds=1,
        probe_fn=probe,
        sleep_fn=lambda _s: None,
        monotonic_fn=lambda: next(times, 5.0),
    )
    assert result["evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert result["evidence_timeout"] is True
    assert result["splunk_verified"] is False
    assert result["probe_error"] is None
    assert calls["n"] >= 1


def test_searchable_count_marks_ready_not_from_export_json(tmp_path):
    run_id = "run-ready"
    pack = tmp_path / run_id
    pack.mkdir()
    (pack / "events.jsonl").write_text("{}\n{}\n", encoding="utf-8")
    (pack / "export.json").write_text(
        '{"otlp.ok": true, "hec.ok": true, "splunk.verified": false}\n',
        encoding="utf-8",
    )

    result = wait_for_searchable_evidence(
        run_id,
        artifacts_dir=tmp_path,
        timeout_seconds=0,
        probe_fn=lambda _rid: {
            "splunk_attempted": True,
            "splunk_ok": True,
            "splunk_count": 2,
            "error": None,
        },
        sleep_fn=lambda _s: None,
    )
    assert result["evidence_state"] == "EVIDENCE_READY"
    assert result["splunk_verified"] is True
    assert result["local_event_count"] == 2
    assert result["completeness_ok"] is True
    assert result["otlp.ok"] is True
    assert result["hec.ok"] is True
