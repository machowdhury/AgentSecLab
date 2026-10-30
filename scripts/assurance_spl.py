"""SPL generation for the AI Security Assurance dashboards, from learning/assurance/rules.json and controls.json.

The macros are generated, not hand-written, so the rules a learner can read in rules.json are exactly the rules Splunk runs, and the Python reference evaluator
(src/agentsec/assurance/engine.py) reads the same file. Nothing here uses the dollar sign, which would make Splunk read an argument inside a macro.
"""
from __future__ import annotations

import re

BASE_MACRO = "agentsec_assurance_units"
FINDINGS_MACRO = "agentsec_assurance_findings"
LINKED_MACRO = "agentsec_assurance_findings_linked"

UNITS = r'''`agentsec_index` "agentsec.schema.name"="agentsec.security_event"
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0), seq=tonumber(mvindex(mvdedup('agentsec.sequence'),0)), ev=mvindex(mvdedup('event.name'),0), hop=mvindex(mvdedup('agentsec.hop.index'),0), executed_flag=lower(mvindex(mvdedup('agentsec.operation.executed'),0)), mode=mvindex(mvdedup('agentsec.testbed.mode'),0), profile=mvindex(mvdedup('agentsec.security.profile'),0), attack_id=mvindex(mvdedup('agentsec.attack.id'),0), lab_marker=mvindex(mvdedup('agentsec.lab.id'),0), index_lag=_indextime-_time
| where isnotnull(run_id)
| eventstats count as raw_events, dc(seq) as seq_dc by run_id
| dedup run_id seq
| eventstats count as run_events, min(seq) as seq_min, max(seq) as seq_max, sum(eval(if(ev="agentsec.run.completed" OR ev="agentsec.run.failed",1,0))) as terminal, values(attack_id) as all_attack, values(eval(if(ev="agentsec.run.started",attack_id,null()))) as start_attack, values(lab_marker) as run_marker, values(mode) as all_mode, values(eval(if(ev="agentsec.run.started",mode,null()))) as start_mode, values(profile) as all_profile, values(eval(if(ev="agentsec.run.started",profile,null()))) as start_profile, max(index_lag) as max_index_lag, min(_time) as run_start, max(_time) as run_end by run_id
| eval attack_id=coalesce(mvindex(start_attack,0),mvindex(all_attack,0)), mode=coalesce(mvindex(start_mode,0),mvindex(all_mode,0)), profile=coalesce(mvindex(start_profile,0),mvindex(all_profile,0)), duplicates=raw_events-seq_dc, contiguous=if(seq_min=1 AND seq_max=run_events,1,0), complete=if(terminal>0 AND contiguous=1,1,0)
| lookup agentsec_recorded_runs run_id OUTPUT recorded
| eval evidence_class=case(mvfind(run_marker,"^assurance-test-fixture") >= 0,"TEST_FIXTURE", recorded="true","RECORDED", true(),"LIVE")
| lookup agentsec_attack_workshops attack_id OUTPUT workshops
| eventstats sum(eval(if((ev="agentsec.mcp.started" OR ev="agentsec.llm.started") AND executed_flag="true",1,0))) as hop_exec by run_id hop
| eval is_decision=if(ev="agentsec.control.decision",1,0)
| eventstats sum(is_decision) as n_decisions, min(eval(if(is_decision=1,_time,null()))) as first_decision_time by run_id'''


def tpl(text: str, fieldmap: dict[str, str]) -> str:
    """A narrative template with {placeholders} as an SPL string expression: "literal ". field ." literal"."""
    parts, pos = [], 0
    for m in re.finditer(r"\{(\w+)\}", text):
        if m.start() > pos:
            parts.append(quote(text[pos:m.start()]))
        parts.append(fieldmap.get(m.group(1), m.group(1)))
        pos = m.end()
    if pos < len(text):
        parts.append(quote(text[pos:]))
    return " . ".join(parts) if parts else '""'


def quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rule_case(rules: dict) -> str:
    """case() over the unit rules in ascending order, from their structured cond."""
    arms = []
    for r in sorted(rules["rules"], key=lambda x: x["order"]):
        c = r["cond"]
        terms = []
        if c.get("incomplete"):
            terms.append("incomplete=1")
        else:
            terms.append("incomplete=0")
        if "decision" in c:
            terms.append(f'decision="{c["decision"]}"')
        if "reason_prefix" in c:
            terms.append(f'match(reason,"^{c["reason_prefix"]}")')
        if "executed" in c:
            terms.append(f"executed={1 if c['executed'] else 0}")
        if c.get("unclassified"):
            arms.append(f'true(), "{r["id"]}"')
            continue
        arms.append(f'{" AND ".join(terms)}, "{r["id"]}"')
    return "case(" + ", ".join(arms) + ")"


def status_case(rules: dict) -> str:
    arms = []
    for r in sorted(rules["rules"], key=lambda x: x["order"]):
        arms.append(f'rule_id="{r["id"]}", ' + (f'"{r["status"]}"' if r["status"] else "null()"))
    return "case(" + ", ".join(arms) + ")"


FIELDS = {"run_id": "run_id", "mode": "mode", "profile": "profile", "evidence_class": "evidence_class", "control_id": "control_id", "decision": "decision", "reason": "reason",
          "hop": "hop_txt", "tool_part": "tool_part", "exec_part": "exec_part", "boundary": "boundary", "guards": "guards", "technique": "technique", "obs_note": "obs_note", "why": "why"}


def narrative_block(rules: dict) -> str:
    nar = rules["narrative"]
    lines = ['| eval hop_txt=coalesce(hop,"(missing)"), tool_part=if(isnotnull(tool) AND tool!="", " for tool ".tool, ""), exec_part=if(executed=1, ' + quote(nar["exec_part"]["executed"]) + ", " + quote(nar["exec_part"]["not_executed"]) + ")",
             '| eval guards=coalesce(guards,"operation"), technique=coalesce(technique,"this"), boundary=coalesce(boundary,"")',
             '| eval why=mvjoin(mvappend(if(NOT in(decision,"ALLOW","DENY","OBSERVE","ERROR"),"the decision value is missing or unknown",null()), if(isnull(hop),"the decision has no hop index",null()), if(terminal=0,"no terminal run event yet",null()), if(contiguous=0,"the event sequence has gaps",null())),"; ")']
    note = ", ".join(f'rule_id="{rid}", ' + tpl(nar["obs_note"][key], FIELDS) for rid, key in (("R-OBSERVE-ONLY", "OBSERVE"), ("R-ERROR", "ERROR"), ("R-FAILOPEN-NOT-EXECUTED", "FAIL_OPEN_NOT_EXECUTED")))
    lines.append(f'| eval obs_note=case({note}, true(), "")')
    lines.append('| eval nkey=if(status="VERIFIED_INEFFECTIVE" AND by_design=1, "VERIFIED_INEFFECTIVE_BY_DESIGN", status)')
    lines.append("| eval observation=" + tpl(nar["observation"], FIELDS))
    for fld in ("interpretation", "impact", "control_interpretation"):
        arms = ", ".join(f'nkey="{k}", ' + tpl(v, FIELDS) for k, v in nar[fld].items())
        lines.append(f"| eval {fld}=case({arms}, true(), \"\")")
    return "\n".join(lines)


def run_level(rules: dict) -> str:
    nd = rules["run_rules"][0]
    rt = rules["run_rules"][1]
    modes = " OR ".join(f'mode="{m}"' for m in nd["cond"]["modes"])
    nar = rules["narrative"]
    return f'''| append [ search `{BASE_MACRO}`
    | eval cid=mvindex(mvdedup('agentsec.control.id'),0), dec=mvindex(mvdedup('agentsec.control.decision'),0)
    | lookup agentsec_controls control_id AS cid OUTPUT class AS cclass
    | eval enf_deny=if(is_decision=1 AND dec="DENY" AND coalesce(cclass,"ENFORCE")!="OBSERVE",1,0), dec_exec=if(is_decision=1 AND hop_exec>0,1,0)
    | stats latest(mode) as mode, latest(profile) as profile, latest(attack_id) as attack_id, max(complete) as complete, max(n_decisions) as n_decisions, sum(enf_deny) as enf_deny, sum(dec_exec) as dec_exec, min(_time) as _time, latest(evidence_class) as evidence_class, latest(workshops) as workshops by run_id
    | where complete=1 AND ((n_decisions=0 AND ({modes})) OR (mode="{rt["cond"]["mode"]}" AND profile="{rt["cond"]["profile"]}" AND n_decisions>=1 AND dec_exec>0 AND enf_deny=0))
    | eval control_id=if(n_decisions=0,"(none)","(run)"), rule_id=if(n_decisions=0,"{nd["id"]}","{rt["id"]}"), status=if(n_decisions=0,"{nd["status"]}","{rt["status"]}"), by_design=0, decision="", reason=""
    | eval observation="Run ".run_id." (".mode." mode, ".profile." profile, ".evidence_class." evidence): ".if(n_decisions=0, {quote(nd["when"])}, {quote(rt["when"])}).".", interpretation=if(n_decisions=0, {quote(nd["explain"])}, {quote(rt["explain"])}), impact=if(n_decisions=0, {quote(nar["impact"]["INSUFFICIENT_EVIDENCE"])}, {quote(nar["impact"]["VERIFIED_INEFFECTIVE"])}), control_interpretation=if(n_decisions=0, {quote(nar["control_interpretation"]["INSUFFICIENT_EVIDENCE"])}, {quote(nar["control_interpretation"]["VERIFIED_INEFFECTIVE"])}), recommended_action=if(n_decisions=0, {quote(nar["default_action_insufficient"])}, "Check which control should have denied this retest, whether the defended profile was really applied, and whether the control matches this technique.")
    | fields run_id mode profile attack_id control_id rule_id status by_design decision reason evidence_class workshops observation interpretation impact control_interpretation recommended_action _time ]'''


def findings_macro(rules: dict) -> str:
    return f'''`{BASE_MACRO}`
| where is_decision=1
| eval control_id=coalesce(mvindex(mvdedup('agentsec.control.id'),0),"(unknown control)"), decision=mvindex(mvdedup('agentsec.control.decision'),0), reason=coalesce(mvindex(mvdedup('agentsec.control.reason'),0),""), tool=mvindex(mvdedup('gen_ai.tool.name'),0), executed=if(hop_exec>0,1,0), incomplete=if(isnull(hop) OR complete!=1,1,0)
| lookup agentsec_controls control_id OUTPUT control_name, class AS control_class, guards, boundary, technique, maestro_layers, workshops AS control_workshops, remediation, retest_check
| eval rule_id={rule_case(rules)}
| where rule_id!="R-ALLOW-EXPECTED"
| eval status={status_case(rules)}, by_design=if(rule_id="R-FAILOPEN-EXECUTED",1,0)
{narrative_block(rules)}
| eval recommended_action=if(status="INSUFFICIENT_EVIDENCE", {quote(rules["narrative"]["default_action_insufficient"])}, coalesce(remediation,"Investigate the run in Splunk with the search shown."))
| fields run_id hop mode profile attack_id control_id control_name control_class decision reason tool rule_id status by_design executed evidence_class boundary technique maestro_layers workshops control_workshops observation interpretation impact control_interpretation recommended_action retest_check _time
{run_level(rules)}
| eval status_label=case(status="VERIFIED_EFFECTIVE","Verified effective", status="VERIFIED_INEFFECTIVE","Verified ineffective", status="FINDING_OBSERVED","Finding observed", status="INSUFFICIENT_EVIDENCE","Insufficient evidence", true(),status)
| eval confidence=case(status="VERIFIED_EFFECTIVE","Verified", status="VERIFIED_INEFFECTIVE","Verified", status="FINDING_OBSERVED","Inferred", status="INSUFFICIENT_EVIDENCE","Incomplete", true(),"Unavailable")
| eval hop=coalesce(hop,"-"), finding_key=run_id."|".hop."|".control_id."|".rule_id'''


def linked_macro() -> str:
    return f'''`{FINDINGS_MACRO}`
| eval attack_key=coalesce(attack_id,"(none)")
| eventstats count(eval(mode="RETEST" AND attack_key!="(none)" AND control_id!="(none)" AND control_id!="(run)")) as n_retest, count(eval(mode="RETEST" AND attack_key!="(none)" AND status="VERIFIED_EFFECTIVE")) as n_retest_ok, values(eval(if(mode="RETEST" AND attack_key!="(none)" AND status="VERIFIED_EFFECTIVE",run_id,null()))) as retest_ok_runs, values(eval(if(mode="RETEST" AND attack_key!="(none)" AND control_id!="(none)" AND control_id!="(run)",run_id,null()))) as retest_runs by attack_key control_id evidence_class
| eval retest_outcome=case(mode!="ATTACK","NOT_APPLICABLE", attack_key="(none)","NO_RETEST", coalesce(n_retest,0)=0,"NO_RETEST", n_retest_ok>0,"VALIDATED", true(),"NOT_VALIDATED")
| eval retest_run=case(retest_outcome="VALIDATED", mvindex(retest_ok_runs,0), retest_outcome="NOT_VALIDATED", mvindex(retest_runs,0), true(), null())'''


def macros_conf(rules: dict) -> str:
    def block(name: str, body: str) -> str:
        lines = body.split("\n")
        joined = " \\\n".join(lines)
        return f"[{name}]\ndefinition = {joined}\niseval = 0\n"
    return "\n".join([
        "# ---- AI Security Assurance (GENERATED by scripts/build_assurance_app.py from learning/assurance; do not edit) ----",
        block(BASE_MACRO, UNITS), block(FINDINGS_MACRO, findings_macro(rules)), block(LINKED_MACRO, linked_macro())])


FILTER_EC = ('| eval workshops=coalesce(workshops,"") | where ((("$ec$"="*") AND evidence_class!="TEST_FIXTURE") OR ("$ec$"="ALL") OR evidence_class="$ec$")')
FILTER = ('| eval workshops=coalesce(workshops,"") | where ((("$ec$"="*") AND evidence_class!="TEST_FIXTURE") OR ("$ec$"="ALL") OR evidence_class="$ec$") AND (("$ws$"="*") OR like(workshops,"%$ws$%"))')
