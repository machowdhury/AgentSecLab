"""Browser-local progress is navigation state, not a security result."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "splunk_app/agentsec/appserver/static/agentsec_learner_path.js"
SESSION = ROOT / "src/agentsec/static/agentsec-ui.js"


def _node(program: str, script: Path) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    assert node, "node is required to execute the browser progress contract"
    return subprocess.run(
        [node, "-e", program, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_progress_persists_resets_and_rejects_security_words():
    program = r"""
const fs = require("fs");
const vm = require("vm");
const store = {};
const localStorage = {
  getItem(key) { return Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null; },
  setItem(key, value) { store[key] = String(value); },
  removeItem(key) { delete store[key]; }
};
const window = {localStorage};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {window, localStorage});
const progress = window.AgentSecProgress;
if (progress.STATES.join(",") !== "NOT STARTED,IN PROGRESS,INVESTIGATED") {
  throw new Error(progress.STATES.join(","));
}
if (progress.stateFor("ws_lab_pi_001") !== "NOT STARTED") throw new Error("default");
progress.setState("ws_lab_pi_001", "IN PROGRESS");
if (progress.stateFor("ws_lab_pi_001") !== "IN PROGRESS") throw new Error("persist write");
const again = {};
const window2 = {localStorage};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {window: window2, localStorage});
if (window2.AgentSecProgress.stateFor("ws_lab_pi_001") !== "IN PROGRESS") throw new Error("reload");
let rejected = false;
try { progress.setState("ws_lab_pi_001", "ALLOW"); } catch (err) { rejected = true; }
if (!rejected) throw new Error("ALLOW must not be a progress state");
if (progress.stateFor("ws_lab_pi_001") !== "IN PROGRESS") throw new Error("rejected write changed state");
progress.reset();
if (progress.stateFor("ws_lab_pi_001") !== "NOT STARTED") throw new Error("reset");
if (store["agentsec.learner.session.v1"]) throw new Error("reset touched session evidence");
"""
    completed = _node(program, SCRIPT)
    assert completed.returncode == 0, completed.stderr


def test_session_capture_keeps_lab_pairs_separate():
    program = r"""
const fs = require("fs");
const vm = require("vm");
const memory = {};
const sessionStorage = {
  getItem(key) { return Object.prototype.hasOwnProperty.call(memory, key) ? memory[key] : null; },
  setItem(key, value) { memory[key] = String(value); }
};
const elements = {};
const document = {
  getElementById(id) { return elements[id] || null; },
  addEventListener() {},
  createElement() { return {textContent: ""}; }
};
const window = {sessionStorage};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {window, document, sessionStorage});
const ui = window.AgentSecUI;
elements["session-history"] = {
  getAttribute() { return "LAB-PI-001"; },
  replaceChildren() {},
  appendChild() {}
};
elements["session-pair"] = {textContent: ""};
ui.captureLaunch({run_id: "attack-pi", runtime: {terminal: "completed_allowed"}, evidence_state: "WAITING_FOR_EVIDENCE"}, "ATTACK", "LAB-PI-001");
ui.captureLaunch({run_id: "retest-pi", runtime: {terminal: "completed_denied"}, evidence_state: "WAITING_FOR_EVIDENCE"}, "RETEST", "LAB-PI-001");
ui.captureLaunch({run_id: "attack-mcp", runtime: {terminal: "completed_allowed"}}, "ATTACK", "LAB-MCP-001");
const runs = ui.readSessionRuns();
const pi = ui.pairSessionRuns(runs, "LAB-PI-001");
const mcp = ui.pairSessionRuns(runs, "LAB-MCP-001");
if (!pi || pi.attack.runId !== "attack-pi" || pi.retest.runId !== "retest-pi") throw new Error("pi pair");
if (mcp) throw new Error("mcp must not borrow the PI retest");
if (!elements["session-pair"].textContent.includes("LAST KNOWN CLIENT STATE")) throw new Error(elements["session-pair"].textContent);
if (elements["session-pair"].textContent.includes("indexed evidence") === false) throw new Error("missing indexed distinction");
"""
    completed = _node(program, SESSION)
    assert completed.returncode == 0, completed.stderr
