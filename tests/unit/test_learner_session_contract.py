"""Execute the browser session helpers. Node is the runner; the assertions are the contract."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "src/agentsec/static/agentsec-ui.js"


def test_session_pairing_and_history_label():
    node = shutil.which("node")
    assert node, "node is required to execute the browser session contract"
    program = r"""
const fs = require("fs");
const vm = require("vm");
const window = {};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {window});
const ui = window.AgentSecUI;
const runs = [
  {mode: "RETEST", runId: "retest-new", labId: "LAB-PI-001", state: "RUN DENIED", terminal: "completed_denied", evidenceState: "WAITING_FOR_EVIDENCE", decision: "DENY", llmCallCount: 0, at: "t2"},
  {mode: "ATTACK", runId: "attack-new", labId: "LAB-PI-001", state: "RUN COMPLETED", terminal: "completed_allowed", evidenceState: "WAITING_FOR_EVIDENCE", decision: "ALLOW", llmCallCount: 4, at: "t1"},
  {mode: "ATTACK", runId: "other-lab", labId: "LAB-OTHER", state: "RUN COMPLETED", terminal: "completed_allowed", at: "t0"},
  {mode: "RETEST", runId: "old", state: "RUN DENIED", at: "t-old"}
];
const pair = ui.pairSessionRuns(runs, "LAB-PI-001");
if (!pair || pair.attack.runId !== "attack-new" || pair.retest.runId !== "retest-new") {
  throw new Error("pair mismatch " + JSON.stringify(pair));
}
if (ui.pairSessionRuns(runs, "LAB-OTHER")) {
  throw new Error("unrelated lab must not invent a RETEST pair");
}
if (ui.pairSessionRuns([{mode: "ATTACK", runId: "only", labId: "LAB-PI-001"}], "LAB-PI-001")) {
  throw new Error("a single mode must not become a comparison");
}
const text = ui.historyText(runs[1]);
if (!text.includes("LAST KNOWN CLIENT STATE: RUN COMPLETED")) throw new Error(text);
if (text.includes("RUN IN PROGRESS")) throw new Error(text);
if (!text.includes("launcher terminal=completed_allowed")) throw new Error(text);
if (!text.includes("evidence=WAITING_FOR_EVIDENCE")) throw new Error(text);
if (!text.includes("not a Splunk verdict")) throw new Error(text);
if (!text.includes("attack-new")) throw new Error(text);
const allowed = ui.learnerRunState({runtime: {terminal: "completed_allowed"}, evidence_state: "WAITING_FOR_EVIDENCE"});
const denied = ui.learnerRunState({runtime: {terminal: "completed_denied"}, evidence_state: "WAITING_FOR_EVIDENCE"});
const failed = ui.learnerRunState({runtime: {terminal: "run_failed"}});
const waiting = ui.learnerRunState({evidence_timeout: true});
const unavailable = ui.learnerRunState({probe_error: "docker_not_available"});
const open = ui.learnerRunState({evidence_state: "WAITING_FOR_EVIDENCE"});
if (allowed.state !== "RUN COMPLETED") throw new Error(allowed.state);
if (!allowed.message.includes("not proof the attack succeeded")) throw new Error(allowed.message);
if (denied.state !== "RUN DENIED") throw new Error(denied.state);
if (failed.state !== "RUN FAILED") throw new Error(failed.state);
if (waiting.state !== "CHECK TIMED OUT") throw new Error(waiting.state);
if (unavailable.state !== "EVIDENCE CHECK UNAVAILABLE") throw new Error(unavailable.state);
if (open.state !== "RUN IN PROGRESS") throw new Error(open.state);
const rehydrated = ui.applyLauncherRecord(runs[1], {runtime: {terminal: "completed_allowed"}, evidence_state: "WAITING_FOR_EVIDENCE"});
if (rehydrated.state !== "RUN COMPLETED") throw new Error(rehydrated.state);
if (rehydrated.terminal !== "completed_allowed") throw new Error(rehydrated.terminal);
const confirmed = ui.evidencePresentation({evidence_state: "EVIDENCE_READY", splunk_verified: true});
const indexing = ui.evidencePresentation({evidence_state: "WAITING_FOR_EVIDENCE", splunk_count: 0});
const probe = ui.evidencePresentation({evidence_state: "EVIDENCE_CHECK_UNAVAILABLE", probe_error: "docker_not_available"});
const timed = ui.evidencePresentation({evidence_state: "WAITING_FOR_EVIDENCE", evidence_timeout: true, splunk_count: 0});
if (confirmed.state !== "EVIDENCE CONFIRMED") throw new Error(confirmed.state);
if (indexing.state !== "WAITING FOR INDEXING") throw new Error(indexing.state);
if (probe.state !== "EVIDENCE CHECK UNAVAILABLE") throw new Error(probe.state);
if (timed.state !== "CHECK TIMED OUT") throw new Error(timed.state);
if (probe.message.toLowerCase().includes("deny")) {
  if (!probe.message.includes("not DENY") && !probe.message.includes("not a control DENY")) throw new Error(probe.message);
}
"""
    completed = subprocess.run(
        [node, "-e", program, str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
