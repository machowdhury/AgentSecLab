import type { Step } from "../mission/RunProgress";
import type { Evidence, LaunchRecord } from "./launch";

// Reading LAB-AGENT-GOAL-INTEGRITY-001 and LAB-AGENT-DELEGATION-001 launch records. Hop 0 is the lab's own control (goal or identity); hop 1 is the
// tool authorization by CTRL-MCP-001. Every value comes from the record. These labs call no language model and model no authentication.
export type Tone = "bad" | "good" | "warn" | "plain";
export interface Hop { "hop.index": number; "control.decision": string; "control.reason": string; "tool.name": string; "mcp.started": boolean; "operation.attempted": boolean; "operation.executed": boolean; "operation.outcome": string | null }
export type SRecord = Omit<LaunchRecord, "runtime"> & { runtime: Record<string, unknown> & { hops: Hop[]; terminal: string; blocked: boolean; block_reason: string | null } };
export const asS = (r: LaunchRecord | null | undefined) => (r ? (r as unknown as SRecord) : null);
export interface Verdict { kind: string; label: string; tone: Tone; head: string }
export interface Question { key: "classify" | "decision" | "handler"; legend: string; opts: [string, string][] }
export interface Scenario {
  lab: string; aria: string; intro: string; baselineLabel: string; baselineHint: string; compareCaption: (same: boolean) => string; compareNote: (same: boolean) => string; sameInput: (a: SRecord, r: SRecord) => boolean;
  questions: Question[]; guess: (a: SRecord, p: { classify?: string; decision?: string; handler?: string }) => string;
  interpret: (r: SRecord) => Verdict; steps: (r: SRecord, ev?: Evidence | null) => Step[]; hopStep: (h: Hop) => string;
  compareRows: (a: SRecord, r: SRecord) => [string, string, string][]; columns: [string, (r: SRecord) => string][];
}

const s = (v: unknown) => (v === null || v === undefined || v === "" ? "—" : String(v));
const n = (v: unknown) => Number(v ?? 0);
const short = (h: unknown) => (typeof h === "string" && h ? h.replace("sha256:", "").slice(0, 12) + "…" : "—");
const hop = (r: SRecord, i: number) => r.runtime?.hops?.find((h) => h["hop.index"] === i);
const failed = (r: SRecord): Verdict | null => (r.runtime_status !== "COMPLETED" || !r.runtime ? { kind: "FAILED", label: "RUN FAILED", tone: "warn", head: "The runtime did not complete, so no control result can be read." } : null);
const splunkStep = (ev?: Evidence | null): Pick<Step, "state" | "detail"> => !ev ? { state: "pending", detail: "Splunk has not been checked yet." }
  : ev.splunk_ok === false || ev.probe_error ? { state: "warn", detail: `Splunk could not be checked from this service${ev.probe_error ? ` (${ev.probe_error})` : ""}.` }
  : ev.evidence_state === "EVIDENCE_READY" ? { state: "done", detail: `Splunk returned ${ev.splunk_count ?? "≥1"} event(s) for this run.id. That is an existence check, not verification.` }
  : { state: "pending", detail: `Splunk has no events for this run.id yet (${ev.splunk_count ?? 0}). Not a failure, and not proof of prevention.` };
const telemetry = (r: SRecord): Step => ({ id: "telemetry", label: "Telemetry", icon: "terminal", state: r.local_event_count ? "done" : "warn", detail: `${r.local_event_count ?? "?"} local events recorded. Collector export reported otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.` });
const launch = (r: SRecord): Step => ({ id: "launch", label: "Launch", icon: "clock", state: r.runtime_status === "COMPLETED" ? "done" : "failed", detail: `Run minted · ${r.mode} · ${r.profile} profile · live.` });
const authz = (r: SRecord): Step => { const h = hop(r, 1); return { id: "authz", label: "Tool authorization", icon: "shield", state: h ? "done" : "warn", detail: h ? `CTRL-MCP-001 on ${h["tool.name"]}: ${h["control.decision"]} (${h["control.reason"]}).` : "No tool decision was recorded." }; };
const finish = (r: SRecord, v: Verdict, ev?: Evidence | null): Step[] => [telemetry(r), { id: "evidence", label: "Splunk evidence", icon: "search", ...splunkStep(ev) }, { id: "outcome", label: "Outcome", icon: v.tone === "good" ? "shield" : "target", state: v.tone === "warn" ? "warn" : "done", detail: v.label.toLowerCase() }];
const NOT_VERIFIED = "No. This lab has no signed verifier, so nothing here is verified. Existence checks are not verification.";
const hopTool = (h: Hop) => h["tool.name"] || "—";

// ---- Goal integrity: an authorized tool is not an authorized goal.
const goalOf = (r: SRecord) => r.runtime;
export const GOAL: Scenario = {
  lab: "LAB-AGENT-GOAL-INTEGRITY-001", aria: "Guided sequence for Goal Integrity",
  intro: "This lab calls no language model. It tests whether an untrusted instruction can change what an already-authorized tool is used for. The tool grant (lookup_policy) is the same on every run; what differs is the goal decision.",
  baselineLabel: "Run BASELINE (normal instruction)", baselineHint: "A normal instruction gives you something to compare the malicious one with.",
  questions: [
    { key: "classify", legend: "On the intentionally vulnerable ATTACK setting, CTRL-GOAL-INTEGRITY-001 will record…", opts: [["OBSERVE", "OBSERVE (note it, change nothing)"], ["DENY", "DENY (refuse the changed task)"]] },
    { key: "decision", legend: "…CTRL-MCP-001 will decide the lookup_policy tool request as…", opts: [["ALLOW", "ALLOW"], ["DENY", "DENY"]] },
    { key: "handler", legend: "…and the wrong-goal handler (lookup_policy used for extract_full_policy)…", opts: [["yes", "will run"], ["no", "will not run"]] }],
  guess: (a, p) => `You predicted ${p.classify} from the goal control, ${p.decision} from the tool control and that the wrong-goal handler ${p.handler === "yes" ? "would" : "would not"} run. Recorded: ${s(goalOf(a).goal_control_decision)}, ${s(goalOf(a).follow_on_decision)} and a wrong-goal count of ${n(goalOf(a).wrong_goal_lookup_policy_count)}.`,
  sameInput: (a, r) => goalOf(a).instruction_hash === goalOf(r).instruction_hash && goalOf(a).proposed_action === goalOf(r).proposed_action,
  compareCaption: (same) => (same ? "Same untrusted instruction and same proposed task change, different server-owned setting." : "Different instructions."),
  compareNote: (same) => `${same ? "The same instruction and the same proposed change led to a different effective action because the goal decision changed. " : ""}CTRL-MCP-001 allowed lookup_policy on both runs, so the tool grant is not what changed. A goal DENY is not a tool DENY, the lab's goal control is not proof against other instructions, and no model was involved.`,
  interpret: (r) => {
    const f = failed(r); if (f) return f;
    const g = goalOf(r), dec = s(g.goal_control_decision), wrong = n(g.wrong_goal_lookup_policy_count), inTask = n(g.in_task_lookup_policy_count);
    if (dec === "—") return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No goal decision was recorded for this run." };
    if (wrong > 0) return dec === "DENY" ? { kind: "DENIED_BUT_RAN", label: "DENIED BUT THE WRONG-GOAL HANDLER RAN", tone: "bad", head: "The goal decision was DENY but the wrong-goal handler count is above 0. That contradicts the control." }
      : { kind: "WRONG_GOAL_RAN", label: "AUTHORIZED TOOL RAN FOR AN UNAUTHORIZED GOAL", tone: "bad", head: r.profile === "vulnerable" ? `On the deliberately vulnerable setting the goal control only observed (a labelled fail-open), the effective action became ${s(g.effective_action)}, and lookup_policy ran for it (wrong-goal count ${wrong}). CTRL-MCP-001 allowed the tool: that grant was valid, but the use was not the authorized task.` : "A wrong-goal handler ran on a defended run. That is unexpected for this lab." };
    if (dec === "DENY") return inTask > 0 ? { kind: "DENIED_KEPT", label: "GOAL EXPANSION DENIED, AUTHORIZED TASK KEPT", tone: "good", head: `CTRL-GOAL-INTEGRITY-001 recorded DENY (${s(g.goal_control_reason)}). The effective action stayed ${s(g.effective_action)}, the wrong-goal count is 0, and the tool still ran for the original task (in-task count ${inTask}). CTRL-MCP-001 allowed the tool here too: a goal DENY is not an MCP DENY. This is what this run recorded, not proof against other instructions.` }
      : { kind: "DENIED_NOTHING", label: "GOAL DENIED, NO HANDLER RAN", tone: "warn", head: "The goal control denied the change but no handler ran at all, including the original task." };
    return inTask > 0 ? { kind: "NORMAL", label: "NORMAL TASK, IN-TASK TOOL USE", tone: "plain", head: `The instruction was observed and the effective action stayed ${s(g.effective_action)}. The tool ran for that task (in-task count ${inTask}, wrong-goal count 0). That is an observation, not proof the instruction is safe.` }
      : { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No handler ran for any task." };
  },
  steps: (r, ev) => { const g = goalOf(r), v = GOAL.interpret(r); return [launch(r),
    { id: "task", label: "Task and instruction", icon: "search", state: g.instruction_id ? "done" : "warn", detail: `${s(g.instruction_id)} (hash ${short(g.instruction_hash)}); task fingerprint ${short(g.task_fingerprint)}.` },
    { id: "goal", label: "Goal decision", icon: "shield", state: g.goal_control_decision ? "done" : "warn", detail: `CTRL-GOAL-INTEGRITY-001: ${s(g.goal_control_decision)} (${s(g.goal_control_reason)}). Proposed ${s(g.proposed_action)}, effective ${s(g.effective_action)}.` },
    authz(r),
    { id: "exec", label: "Execution", icon: "play", state: "done", detail: `lookup_policy handler ran ${n(g.lookup_policy_handler_count)} time(s): in-task ${n(g.in_task_lookup_policy_count)}, wrong-goal ${n(g.wrong_goal_lookup_policy_count)}. The handler counts are the authoritative record of execution.` },
    ...finish(r, v, ev)]; },
  hopStep: (h) => (h["hop.index"] === 0 ? "Goal decision (CTRL-GOAL-INTEGRITY-001)" : "Tool authorization (CTRL-MCP-001)"),
  compareRows: (a, r) => [["Setting (profile)", a.profile, r.profile], ["Instruction", s(goalOf(a).instruction_id), s(goalOf(r).instruction_id)], ["Instruction hash", short(goalOf(a).instruction_hash), short(goalOf(r).instruction_hash)],
    ["Proposed action", s(goalOf(a).proposed_action), s(goalOf(r).proposed_action)], ["Goal decision", s(goalOf(a).goal_control_decision), s(goalOf(r).goal_control_decision)], ["Goal reason", s(goalOf(a).goal_control_reason), s(goalOf(r).goal_control_reason)],
    ["Effective action", s(goalOf(a).effective_action), s(goalOf(r).effective_action)], ["Tool decision (CTRL-MCP-001)", s(goalOf(a).follow_on_decision), s(goalOf(r).follow_on_decision)],
    ["Wrong-goal handler count", String(n(goalOf(a).wrong_goal_lookup_policy_count)), String(n(goalOf(r).wrong_goal_lookup_policy_count))], ["In-task handler count", String(n(goalOf(a).in_task_lookup_policy_count)), String(n(goalOf(r).in_task_lookup_policy_count))],
    ["Outcome", GOAL.interpret(a).label, GOAL.interpret(r).label]],
  columns: [
    ["1. Proposed and effective action", (r) => `Proposed ${s(goalOf(r).proposed_action)}; effective ${s(goalOf(r).effective_action)}.`],
    ["2. Goal decision", (r) => `${s(goalOf(r).goal_control_decision)} (${s(goalOf(r).goal_control_reason)}). A decision only.`],
    ["3. Tool authorization", (r) => `${s(goalOf(r).follow_on_decision)} (${s(goalOf(r).follow_on_reason)}) for lookup_policy. Allowing the tool says nothing about the goal.`],
    ["4. Actual execution", (r) => `Handler ran ${n(goalOf(r).lookup_policy_handler_count)} time(s): in-task ${n(goalOf(r).in_task_lookup_policy_count)}, wrong-goal ${n(goalOf(r).wrong_goal_lookup_policy_count)}.`],
    ["5. Telemetry received", (r) => `${r.local_event_count ?? "?"} local events; otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.`],
    ["6. Independently verified", () => NOT_VERIFIED]],
};

// ---- Delegation: a claim is not authentication, and a delegation claim is not authorization.
const dl = (r: SRecord) => r.runtime;
export const DELEGATION: Scenario = {
  lab: "LAB-AGENT-DELEGATION-001", aria: "Guided sequence for Agent Delegation",
  intro: "This lab calls no language model and models no authentication: the agent names are labels in the record, not proven identities. It tests whether a delegation claim from one agent can obtain a tool that neither agent was granted.",
  baselineLabel: "Run BASELINE (normal request)", baselineHint: "A normal, granted request gives you something to compare the privileged claim with.",
  questions: [
    { key: "classify", legend: "On the intentionally vulnerable ATTACK setting, CTRL-IDENTITY-001 will record…", opts: [["OBSERVE", "OBSERVE (note the claim)"], ["DENY", "DENY (refuse the claim)"]] },
    { key: "decision", legend: "…CTRL-MCP-001 will decide the lookup_customer_tier request as…", opts: [["ALLOW", "ALLOW"], ["DENY", "DENY"]] },
    { key: "handler", legend: "…and the privileged handler (lookup_customer_tier)…", opts: [["yes", "will run"], ["no", "will not run"]] }],
  guess: (a, p) => `You predicted ${p.classify} from the identity control, ${p.decision} from the tool control and that the privileged handler ${p.handler === "yes" ? "would" : "would not"} run. Recorded: ${s(dl(a).identity_control_decision)}, ${s(dl(a).follow_on_decision)} and a privileged handler count of ${n(dl(a).lookup_customer_tier_handler_count)}. Authentication: ${s(dl(a).who_authenticated)}.`,
  sameInput: (a, r) => dl(a).request_fingerprint === dl(r).request_fingerprint,
  compareCaption: (same) => (same ? "Same delegation claim and request fingerprint, different server-owned setting." : "Different requests."),
  compareNote: (same) => `${same ? "The same claim produced a different outcome because CTRL-MCP-001's decision changed, not because the claim changed. " : ""}CTRL-IDENTITY-001 only observed the claim on both runs. Neither run authenticated anyone, an ALLOW is not an execution, and no model was involved.`,
  interpret: (r) => {
    const f = failed(r); if (f) return f;
    const d = dl(r), dec = s(d.follow_on_decision), priv = n(d.lookup_customer_tier_handler_count), pol = n(d.lookup_policy_handler_count);
    if (s(d.identity_control_decision) === "—") return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No identity classification was recorded for this run." };
    if (dec === "ALLOW") return priv > 0 ? { kind: "PRIVILEGED_RAN", label: "PRIVILEGED TOOL ALLOWED AND RAN", tone: "bad", head: r.profile === "vulnerable" ? `On the deliberately vulnerable setting CTRL-MCP-001 allowed lookup_customer_tier through a labelled fail-open overlay and the handler ran (count ${priv}). The claim did not grant that. Authentication: ${s(d.who_authenticated)}.` : "The privileged tool ran on a defended run. That is unexpected for this lab." }
      : pol > 0 ? { kind: "NORMAL", label: "GRANTED TOOL RAN, NO PRIVILEGED REQUEST", tone: "plain", head: `A tool the agents are actually granted (lookup_policy) ran (count ${pol}); the privileged tool did not (count 0). That is an observation, not proof the claim is safe.` }
      : { kind: "ALLOWED_NOT_RUN", label: "ALLOWED BUT NO HANDLER RAN", tone: "warn", head: "The tool request was allowed but no handler ran. An ALLOW is a decision, not an execution." };
    if (dec === "DENY") return priv > 0 ? { kind: "DENIED_BUT_RAN", label: "DENIED BUT THE HANDLER RAN", tone: "bad", head: "The decision was DENY but the privileged handler count is above 0. That contradicts the control." }
      : { kind: "DENIED_NOT_RUN", label: "PRIVILEGED TOOL DENIED, HANDLER DID NOT RUN", tone: "good", head: `CTRL-IDENTITY-001 only observed the claim (${s(d.identity_control_decision)}). CTRL-MCP-001 denied lookup_customer_tier (${s(d.follow_on_reason)}) and the privileged handler count is 0. The identity control stopped nothing; the tool decision did. Authentication: ${s(d.who_authenticated)}. A DENY is not automatically SAFE.` };
    return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No tool decision was recorded." };
  },
  steps: (r, ev) => { const d = dl(r), v = DELEGATION.interpret(r); return [launch(r),
    { id: "claim", label: "Claim received", icon: "search", state: d.claim_id ? "done" : "warn", detail: `Principal ${s(d.principal_id)}; caller ${s(d.caller_agent_id)} to callee ${s(d.callee_agent_id)}; ${s(d.claim_id)} (${s(d.claim_trust)}).` },
    { id: "identity", label: "Identity classified", icon: "shield", state: d.identity_control_decision ? "done" : "warn", detail: `CTRL-IDENTITY-001: ${s(d.identity_control_decision)} (${s(d.identity_control_reason)}). Who authenticated: ${s(d.who_authenticated)}.` },
    authz(r),
    { id: "exec", label: "Execution", icon: "play", state: "done", detail: `Privileged handler (lookup_customer_tier) ran ${n(d.lookup_customer_tier_handler_count)} time(s); lookup_policy ran ${n(d.lookup_policy_handler_count)}. The handler counts are the authoritative record of execution.` },
    ...finish(r, v, ev)]; },
  hopStep: (h) => (h["hop.index"] === 0 ? "Identity classified (CTRL-IDENTITY-001)" : "Tool authorization (CTRL-MCP-001)"),
  compareRows: (a, r) => [["Setting (profile)", a.profile, r.profile], ["Claim", s(dl(a).claim_id), s(dl(r).claim_id)], ["Request fingerprint", short(dl(a).request_fingerprint), short(dl(r).request_fingerprint)],
    ["Caller → callee", `${s(dl(a).caller_agent_id)} → ${s(dl(a).callee_agent_id)}`, `${s(dl(r).caller_agent_id)} → ${s(dl(r).callee_agent_id)}`],
    ["Identity classification (CTRL-IDENTITY-001)", s(dl(a).identity_control_decision), s(dl(r).identity_control_decision)], ["Who authenticated", s(dl(a).who_authenticated), s(dl(r).who_authenticated)],
    ["Tool decision (CTRL-MCP-001)", s(dl(a).follow_on_decision), s(dl(r).follow_on_decision)], ["Tool reason", s(dl(a).follow_on_reason), s(dl(r).follow_on_reason)],
    ["Privileged handler count", String(n(dl(a).lookup_customer_tier_handler_count)), String(n(dl(r).lookup_customer_tier_handler_count))], ["Outcome", DELEGATION.interpret(a).label, DELEGATION.interpret(r).label]],
  columns: [
    ["1. Claim as recorded", (r) => `Principal ${s(dl(r).principal_id)}; caller ${s(dl(r).caller_agent_id)}; callee ${s(dl(r).callee_agent_id)}; ${s(dl(r).claim_id)} (${s(dl(r).claim_trust)}).`],
    ["2. Identity classification", (r) => `${s(dl(r).identity_control_decision)} (${s(dl(r).identity_control_reason)}). Who authenticated: ${s(dl(r).who_authenticated)}. Observes only; it neither grants nor authenticates.`],
    ["3. Tool authorization", (r) => { const h = hop(r, 1); return h ? `${h["control.decision"]} (${h["control.reason"]}) for ${hopTool(h)}. A decision only.` : "No tool decision was recorded."; }],
    ["4. Actual execution", (r) => `Privileged handler ran ${n(dl(r).lookup_customer_tier_handler_count)} time(s); lookup_policy ran ${n(dl(r).lookup_policy_handler_count)}.`],
    ["5. Telemetry received", (r) => `${r.local_event_count ?? "?"} local events; otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.`],
    ["6. Independently verified", () => NOT_VERIFIED]],
};
export const SCENARIOS: Record<string, Scenario> = { [GOAL.lab]: GOAL, [DELEGATION.lab]: DELEGATION };
export { hopTool };
