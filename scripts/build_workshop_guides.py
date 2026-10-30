#!/usr/bin/env python3
"""Write learning/academy/workshop_guides.json: for every workshop, what you should see, what the defense teaches, how you know you are done and what to do when
something does not look right.

LIVE workshops take their expected results and defensive lessons from their own lab-manifest.json prediction blocks (so the guide cannot drift from the lab).
The recorded-evidence checkpoints are authored here from their committed packets; every statement below is a fact in the named packet or README. Nothing here
claims runtime enforcement for a SIMULATED / REPLAYED packet. Run: python3 scripts/build_workshop_guides.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
LEARN = ROOT / "learning"

# ---- troubleshooting, by what the learner is doing (shared; a lab adds its own only when it has a lab-specific failure)
LIVE_TROUBLE = [
    {"symptom": "The launch card says the runtime is unreachable, or the launch fails.",
     "fix": "The Attack Service or AcmeBank is not ready. Open System Status (or run ./agentsec status); wait for a first Splunk start, which takes minutes. Nothing was launched, so just try again."},
    {"symptom": "Evidence says WAITING_FOR_EVIDENCE.",
     "fix": "That is the honest default. Telemetry reaches Splunk seconds to minutes after the run. It is not a failed attack and not proof of prevention. Re-check later with Check again in the Investigate stage."},
    {"symptom": "Verification says VERIFICATION UNAVAILABLE.",
     "fix": "The Attack Service could not run the check (no Docker inside its container and no Splunk REST URL and token file configured). It is not zero rows and not verified. The Investigate stage says the same and shows no rows rather than guess; an operator can set up search access with ./agentsec splunk-access."},
    {"symptom": "Splunk shows no events for the run.id.",
     "fix": "Use index=agentsec_telemetry sourcetype=otel:agentic:json, a time range that covers the run (earliest=-1h), and the quoted field agentsec.run.id with the exact UUID from the card. Do not search index=*. HEC or OTLP success is not an indexed event."},
    {"symptom": "RETEST looks the same as ATTACK.",
     "fix": "Check the profile column: ATTACK is vulnerable and RETEST is defended, set by the server. The request must be identical. If both say vulnerable, restart the Attack Service and run RETEST again; do not change anything in the browser."},
]
REPLAY_TROUBLE = [
    {"symptom": "A search returns no rows for a recorded run.",
     "fix": "The recorded runs are historical: set the time range to All time (earliest=0). They are loaded by the splunk_hec_init job at start; check its log for 'VERIFIED searchable'. If the lab was started without Splunk, the Academy still shows the committed packets."},
    {"symptom": "An optional advanced dashboard panel is empty.",
     "fix": "The dashboard's tokens are not bound to a run you launched. Use the run.id from the recorded table in this workshop; the evidence view needs no dashboard."},
    {"symptom": "A count differs from the committed pack.",
     "fix": "The pack is the source of truth. Count physical events with stats dc(_raw), not by run id alone, and remember that an indexed copy can be partial while ingestion is running."},
]
PACKET_TROUBLE = [
    {"symptom": "Nothing runs when I open the exercise.",
     "fix": "By design. This workshop is a guided analysis of a committed, simulated evidence packet. It runs no attack, enforces nothing and sends nothing to Splunk. The packet is labelled SIMULATED / REPLAYED or DOCUMENTED."},
    {"symptom": "I cannot find the Splunk rows the packet describes.",
     "fix": "Packet content is not in the telemetry index unless the page says a recorded search is bound. Follow the recorded searches shown on the page; do not look for packet identifiers in the index."},
]
TROUBLE = {"LIVE": LIVE_TROUBLE, "REPLAY": REPLAY_TROUBLE, "PACKET": PACKET_TROUBLE}

PACKET_COMPLETE = [
    "Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why.",
    "State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows.",
]

# ---- authored guides for the recorded / packet workshops (facts from the named committed files)
AUTHORED: dict[str, dict] = {
    "LAB-A2A-AUTH-DELEGATION": dict(tier="PACKET",
        expected=["BASELINE: ALLOW tool_granted, and a separate simulated mcp.started.",
                  "ATTACK: ALLOW with vulnerable_profile_fail_open:caller_identity_derived_authority, a teaching fault, with execution.",
                  "RETEST: DENY tool_not_granted, and no execution to infer."],
        defensive=["A caller's identity is not a grant to the tool: authorization is decided per tool, scope and resource.",
                   "Authenticating an agent (here simulated) answers who is calling; it never answers what it may do."],
        completion=PACKET_COMPLETE),
    "LAB-AGENT-IDENTITY-NHI": dict(tier="REPLAY",
        expected=["The three shipped searches return what was recorded about claims, control decisions and handler starts.",
                  "An identity claim appears as a label; the control observes it and the tool decision is separate."],
        defensive=["A non-human identity claim is a label, not a grant; treat it as data.",
                   "Keep three kinds of evidence apart: committed packs, the current Splunk observation and the September documentation."],
        completion=["For each of the three searches, say what it shows and what it cannot show.",
                    "Say which of the three evidence kinds each claim in your notes rests on."]),
    "LAB-HITL-APPROVAL": dict(tier="PACKET",
        expected=["BASELINE: the submitted tool, resource and action reference match the approval (binding MATCH): ALLOW tool_granted.",
                  "ATTACK: the approval is inside its time window but the action is a different resource (executive-restricted); binding MISMATCH, yet ALLOW vulnerable_profile_fail_open:stale_approval_accepted.",
                  "RETEST: the same mismatched action is DENY approval_binding_mismatch and nothing executes."],
        defensive=["An approval is bound to one tool, resource and action reference; a valid time window alone does not authorize a different action.",
                   "The approval authority here is NOT PROVEN: the packet never shows who approved, only a simulated record."],
        completion=PACKET_COMPLETE + ["Explain why an approval inside its window can still be the wrong approval."]),
    "LAB-CREDENTIAL-LIFETIME": dict(tier="PACKET",
        expected=["BASELINE: a current credential: ALLOW tool_granted.",
                  "ATTACK: an expired credential is accepted by a teaching fault: ALLOW vulnerable_profile_fail_open:expired_credential_accepted.",
                  "RETEST: DENY expired_credential and no execution to infer."],
        defensive=["Credential expiry and approval expiry are different clocks; check each at the moment of use.",
                   "A credential that was valid when issued is not valid forever: lifetime is part of authorization."],
        completion=PACKET_COMPLETE + ["Say which clock the packet's approval uses and why it is not the credential clock."]),
    "LAB-RAG-PURPOSE": dict(tier="PACKET",
        expected=["BASELINE: purpose allowed (applicant-education): ALLOW purpose_allowed.",
                  "ATTACK: the purpose is not checked and the retrieval goes through: FAIL_OPEN vulnerable_profile_fail_open:purpose_not_checked.",
                  "RETEST: DENY purpose_not_allowed."],
        defensive=["Retrieval authorization needs the purpose, not only the principal and the document: similarity is not authorization.",
                   "A retrieval decision is not a tool decision: CTRL-MCP-001 is not invoked by retrieval."],
        completion=PACKET_COMPLETE + ["Explain why vector similarity cannot stand in for a purpose check."]),
    "LAB-RECALL-ISOLATION": dict(tier="PACKET",
        expected=["BASELINE: the owner recalls their own memory: owner_recall.",
                  "ATTACK: another user recalls it: vulnerable_profile_fail_open:cross_user_recall.",
                  "RETEST: the cross-user recall is refused: cross_user_recall_denied."],
        defensive=["Memory has an owner: recall must check the reading user, not only the writing agent (the writer is the same in every case).",
                   "Deletion and retention are NOT MEASURED in this packet; do not infer either from the recall result."],
        completion=PACKET_COMPLETE + ["Say what the packet does not measure about deletion and retention."]),
    "LAB-ASSET-INVENTORY": dict(tier="PACKET",
        expected=["The packet lists the repository's components with the files that name them, bounded to repository files.",
                  "Cisco AI BOM compatibility is NOT CLAIMED: the packet does not run that CLI."],
        defensive=["You cannot govern what you cannot inventory. Inventory is not trust, not authorization and not safety.",
                   "Presence of a component in the list says nothing about whether it is safe to grant."],
        completion=["Pick three components and say where each is named and what the inventory does not say about it.",
                    "Explain the difference between inventory and authorization."]),
    "LAB-COMPONENT-PROVENANCE": dict(tier="PACKET",
        expected=["BASELINE: ALLOW tool_granted. ATTACK: ALLOW vulnerable_profile_fail_open:known_component_treated_as_grant. RETEST: DENY provenance_is_not_a_grant.",
                  "The Ollama image pin is NOT RESOLVED: docker-compose.yml still says ollama/ollama:latest and no digest was measured."],
        defensive=["Knowing where a component came from is not a grant: provenance supports a decision, it does not make one.",
                   "A scanner finding is not authorization and an evaluation pass is not safety; pin what you can measure and say what you could not."],
        completion=PACKET_COMPLETE + ["Name one component in the packet that is pinned and one that is not, and why the difference matters."]),
    "LAB-CODE-AGENT-BOUNDS": dict(tier="PACKET",
        expected=["BASELINE: read_repository matches the grant: ALLOW tool_granted.",
                  "ATTACK: install_dependency is not granted but is let through by a teaching fault: ALLOW vulnerable_profile_fail_open:code_agent_scope_not_checked.",
                  "RETEST: DENY operation_not_granted; nothing executes."],
        defensive=["A code agent's operations are bounded by grant: reading a repository does not authorize installing a dependency.",
                   "A current credential and a valid delegation still do not authorize an operation outside the grant."],
        completion=PACKET_COMPLETE + ["Explain why a CURRENT credential does not make install_dependency allowed."]),
    "LAB-CHANGE-BOUNDS": dict(tier="PACKET",
        expected=["BASELINE: inspect_resource matches the delegated operation: ALLOW tool_granted.",
                  "ATTACK: delete_resource is submitted against an inspect-only credential and let through by a teaching fault: ALLOW vulnerable_profile_fail_open:change_scope_not_checked.",
                  "RETEST: DENY change_not_granted; nothing executes."],
        defensive=["A credential scoped to inspect is not a credential to change: bind the operation, not just the resource.",
                   "This is not a cloud account: the packet simulates the check and measures no real resource change."],
        completion=PACKET_COMPLETE + ["State the scope of the credential and the operation that was submitted, and why they differ."]),
    "LAB-SPLUNK-DEFENDER-BRIDGE": dict(tier="REPLAY",
        expected=["The ten shipped searches replay as recorded: discover, narrow, sequence, compare, check duplicates.",
                  "Some results trace to committed runs; the page marks which."],
        defensive=["Start an investigation from a question, not from a run id.",
                   "A search result is evidence about the indexed copy; it enforces nothing and a missing row is not a DENY."],
        completion=["Work through discover, narrow, sequence, compare and duplicates in order.",
                    "For two results, say whether they can be traced to a committed run and how you know."]),
    "LAB-DETECTION-ENGINEERING": dict(tier="REPLAY",
        expected=["Three recorded searches, their event counts, a broad rule and a tuned rule are replayed.",
                  "A zero-row result is shown as a result, not as an answer."],
        defensive=["Not every suspicious behavior should become an alert: tune a rule against recorded evidence before relying on it.",
                   "Zero rows is not safety: it can mean no event, no ingestion or a rule that cannot see the field."],
        completion=["Say what each of the three searches shows and what a zero-row result does and does not mean.",
                    "Explain why the tuned rule is preferable to the broad one, using the recorded counts."]),
    "LAB-SCANNER-RUNTIME-EVIDENCE": dict(tier="REPLAY",
        expected=["Scanner findings and runtime decisions are laid side by side, joined by the tool description's SHA-256.",
                  "A scanner flag and a runtime ALLOW/DENY are separate facts about the same description."],
        defensive=["A scanner finding is static evidence about a description; it is not authorization and not proof of exploitation.",
                   "Join evidence on a stable key (the description hash) before drawing a conclusion."],
        completion=["Pick two descriptions and state what the scanner says and what the runtime recorded for each.",
                    "Say what each kind of evidence can and cannot prove."]),
    "LAB-EXTERNAL-EVALUATION-GARAK": dict(tier="REPLAY",
        expected=["One adversarial probe, run once against one local model, recorded one native PASS.",
                  "The page shows exactly what was recorded and where it came from."],
        defensive=["An evaluation pass is not safety: one probe on one model is not a comprehensive evaluation.",
                   "Keep external evaluation evidence separate from runtime control evidence."],
        completion=["State what was run, how many times and against what.",
                    "Say why a PASS here is not evidence of robustness in general."]),
    "LAB-BLUE-TEAM-INCIDENT-001": dict(tier="REPLAY",
        expected=["The recorded attack run is a three-step chain (retrieve, write, recall) and a defended retest is recorded beside it.",
                  "Your timeline separates what the evidence supports, what it refutes and what it leaves open."],
        defensive=["Reconstruct from run ids and content hashes, not from narrative.",
                   "Write NOT PROVEN where the evidence stops; a missing event is not proof of absence."],
        completion=["Produce a timeline of the chain with the run ids and the decision at each step.",
                    "Fill the incident report template: supported, refuted, open."]),
    "LAB-MULTI-STAGE-INCIDENT-001": dict(tier="REPLAY",
        expected=["An attack chain, a defended retest, a baseline chain and a benign comparison are all available as recorded evidence.",
                  "You can name which control held and which did not at each stage."],
        defensive=["Separate evidence planes (events, decisions, executions) before you correlate them.",
                   "A held control is shown by a DENY before the handler plus handler count 0, not by silence in Splunk."],
        completion=["Name the controls that held and the ones that did not, with the run id for each.",
                    "State what is still unproven and what evidence would settle it."]),
    "LAB-PRIVACY-DATA-GOVERNANCE-001": dict(tier="PACKET",
        expected=["The full synthetic record and the minimized record are compared field by field.",
                  "You can say what the task needed, what the control decided and what stays unproven."],
        defensive=["Authorizing a tool call is not authorizing the data it receives: minimize what a tool is given.",
                   "All data here is synthetic; the exercise says nothing about a real privacy program."],
        completion=["List the fields the task needed and the fields it did not.",
                    "State what remains unproven about the minimized record."]),
    "LAB-THREAT-MODELING-001": dict(tier="PACKET",
        expected=["Every AcmeBank element sits on one of the seven MAESTRO layers, and the trust boundaries between layers are named.",
                  "Each layer has at least one threat, taken from the CSA article's list for that layer or marked custom with a reason (Layer 6's list is about AI security agents, which AcmeBank does not have).",
                  "At least two cross-layer attack paths chain threats across three or more layers, and your register ranks risks by inherent then residual level."],
        defensive=["A threat model starts with what you protect and where trust changes, then follows threats across layers: the dangerous paths cross layers.",
                   "Say how you know: DEMONSTRATED means a lab shows it for its own fixtures, DOCUMENTED means a file says it, ASSUMED means no evidence. A residual rating is a judgment, not a measurement."],
        completion=["Complete the MAESTRO workbench in Practice: decompose, mark boundaries, record threats on every layer, chain two cross-layer paths, judge inherent and residual risk with mitigations, and link scenarios from at least three families (MCP, prompt injection, memory, RAG, delegation).",
                    "Press Check my model: the structure criteria R1 to R5 and R7 are MET. The check cannot judge your reasoning and is not a certification.",
                    "Download your report and compare your register with the worked example, then with the official MAESTRO Threat Analyzer if you run it yourself (this lab does not run it)."]),
    "LAB-ADVANCED-CAPSTONE-MASTERY-001": dict(tier="REPLAY",
        expected=["You receive a business workflow, a time window and recorded evidence, not a run id.",
                  "Your answer states what you can prove and writes NOT PROVEN where the evidence stops."],
        defensive=["Combine the controls you learned: tool, scope, resource, result, delegation, memory and retrieval are different questions.",
                   "Do not generalise from one lab profile to production."],
        completion=["Complete the self-check against the lab's own list of steps.",
                    "Record, for each claim, the evidence it rests on. This is self-assessed and is not a certification."]),
    "LAB-LOANDESK-001": dict(tier="LIVE",
        expected=["BASELINE posture: the model files whatever note it is given; an applicant-planted instruction can reach the human underwriter queue (ALLOW: tool, scope and applicant are valid, the note content is not checked).",
                  "HARDENED retest of the same attack: DENY argument_not_allowed:note and the handler does not run; whether the business task completed is recorded separately."],
        defensive=["ALLOW is not safe: scope and applicant were valid while the content was never checked. Authorization must also constrain what an allowed tool may carry.",
                   "Separate the model's proposal, the policy decision and the executed handler: they are three facts."],
        completion=["Complete the ten steps: Understand through Explain.",
                    "Show from recorded events that the attack text reached the queue in BASELINE and did not in HARDENED, and say whether the business task completed.",
                    "Say whether your evidence is local or Splunk-verified."]),
}
LIVE_NOTE_RETEST_SAME = "Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed."


def manifest(lab: str) -> dict | None:
    p = LEARN / "level_1" / lab / "lab-manifest.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def checks_count(lab: str) -> int:
    """Same count the Academy shows (export_curriculum.checks_of), so the guide and the page cannot disagree."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import export_curriculum as ec
    p = LEARN / "level_1" / lab / "knowledge-check.md"
    return len(ec.checks_of(p)) if p.exists() else 0


def live_guide(lab: str, m: dict) -> dict:
    pred = m.get("prediction", {})
    g = lambda mode, key: (pred.get(mode) or {}).get(key)
    expected = [t for t in (
        f"BASELINE: {g('BASELINE', 'expected_evidence_defended')}" if g("BASELINE", "expected_evidence_defended") else None,
        f"ATTACK (intentionally vulnerable): {g('ATTACK', 'expected_evidence_vulnerable')}" if g("ATTACK", "expected_evidence_vulnerable") else None,
        f"RETEST (defended): {g('RETEST', 'expected_evidence_defended')}" if g("RETEST", "expected_evidence_defended") else None) if t]
    defensive = [t for t in (g("ATTACK", "defense_should"), g("RETEST", "which_control"), g("RETEST", "security_property")) if t]
    done = ["Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids.",
            LIVE_NOTE_RETEST_SAME,
            "In the Investigate stage, press Run on each notebook cell for your attack run, then say what the rows show and what they cannot (Splunk enforced nothing)."]
    n = checks_count(lab)
    if n:
        done.append(f"Answer the {n} knowledge-check questions for this workshop.")
    return dict(tier="LIVE", expected=expected, defensive=defensive, completion=done)


def build() -> dict:
    sys.path.insert(0, str(ROOT / "src"))
    from agentsec.lab_registry import load_registry
    out: dict[str, dict] = {}
    for e in load_registry()["entries"]:
        lab = e["lab_id"]
        g = AUTHORED.get(lab)
        m = manifest(lab)
        if g is None:
            if not m or "prediction" not in m:
                raise SystemExit(f"no guide source for {lab}")
            g = live_guide(lab, m)
        g = dict(g)
        tier = g.pop("tier")
        n = checks_count(lab)
        if tier != "LIVE" and n:
            g["completion"] = list(g["completion"]) + [f"Answer the {n} knowledge-check questions for this workshop."]
        g["troubleshooting"] = TROUBLE[tier]
        g["kind"] = {"LIVE": "live", "REPLAY": "recorded", "PACKET": "simulated packet"}[tier]
        out[lab] = g
    return {"schema": "agentsec.workshop_guides.v1", "note": "Learning metadata. These guides do not authorize, deny or detect. LIVE entries are read from each lab's own prediction block.", "guides": out}


if __name__ == "__main__":
    data = build()
    dest = LEARN / "academy" / "workshop_guides.json"
    dest.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {dest.relative_to(ROOT)}: {len(data['guides'])} workshops")
