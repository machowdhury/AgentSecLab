"""Opt-in live Splunk proof for canonical external evidence.

Unlike payload unit tests, this test submits canonical pack events through HEC
and asserts fields returned by the local Splunk search command.
"""

from __future__ import annotations

import os

import pytest

from scripts.validate_external_evidence_e2e_splunk import run_validation


@pytest.mark.live_splunk
def test_cisco_and_garak_external_evidence_e2e():
    if os.environ.get("AGENTSEC_LIVE_SPLUNK", "").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        pytest.skip("live Splunk ingest is opt-in; set AGENTSEC_LIVE_SPLUNK=1")
    results = run_validation()
    assert "agentsec:scanner:finding" in results["counts"]
    assert "agentsec:external:evaluation" in results["counts"]
    assert "RUNTIME" in results["planes"]
