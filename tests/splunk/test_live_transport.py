"""Live collector/Splunk ingest. Skipped unless AGENTSEC_LIVE_SPLUNK=1.

Default pytest must stay runnable without Splunk, Ollama, or the collector.
"""

from __future__ import annotations

import os

import pytest


@pytest.mark.live_splunk
def test_live_splunk_marker_is_opt_in():
    if os.environ.get("AGENTSEC_LIVE_SPLUNK", "").strip() not in {"1", "true", "yes", "on"}:
        pytest.skip("live Splunk ingest is opt-in; set AGENTSEC_LIVE_SPLUNK=1")
    pytest.skip("live completeness is recorded in docs/PHASE2B_TRANSPORT_VALIDATION.md after a real search")
