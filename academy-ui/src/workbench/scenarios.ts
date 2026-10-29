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
  /** Multi-run labs: one launch mints several run ids. These are read from the record, never inferred. */
  ids?: (r: SRecord) => [string, string][]; links?: (r: SRecord) => [string, string][]; correlation?: (r: SRecord) => [string, boolean][];
}

const s = (v: unknown) => (v === null || v === undefined || v === "" ? "—" : String(v));
const n = (v: unknown) => Number(v ?? 0);
const short = (h: unknown) => (typeof h === "string" && h ? h.replace("sha256:", "").slice(0, 12) + "…" : "—");
const hop = (r: SRecord, i: number) => r.runtime?.hops?.find((h) => h["hop.index"] === i);
const failed = (r: SRecord): Verdict | null => (r.runtime_status !== "COMPLETED" || !r.runtime ? { kind: "FAILED", label: "RUN FAILED", tone: "warn", head: "The runtime did not complete, so no control result can be read." } : null);
const perRun = (ev: Evidence) => { const p = [["retrieve", ev.retrieve_evidence_state], ["write", ev.write_evidence_state], ["recall", ev.recall_evidence_state]].filter(([, v]) => v).map(([k, v]) => `${k} ${v}`); return p.length ? ` (${p.join(", ")})` : ""; };
const splunkStep = (ev?: Evidence | null): Pick<Step, "state" | "detail"> => !ev ? { state: "pending", detail: "Splunk has not been checked yet." }
  : ev.splunk_ok === false || ev.probe_error ? { state: "warn", detail: `Splunk could not be checked from this service${ev.probe_error ? ` (${ev.probe_error})` : ""}.` }
  : ev.evidence_state === "EVIDENCE_READY" ? { state: "done", detail: `Splunk returned events for this run.id${perRun(ev)}. That is an existence check, not verification.` }
  : { state: "pending", detail: `Splunk does not have all the events for this run.id yet${perRun(ev) || ` (${ev.splunk_count ?? 0})`}. Not a failure, and not proof of prevention.` };
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

// ---- Memory and Capstone: one launch mints several run ids (write + recall; capstone also retrieve). The top-level run_id is the RECALL run.
const top = (r: SRecord) => r as unknown as Record<string, unknown>;
const obj = (v: unknown) => (v && typeof v === "object" ? (v as Record<string, unknown>) : {});
const rid = (r: SRecord, k: "retrieve" | "write" | "recall") => s(top(r)[`${k}_run_id`]);
const sub = (r: SRecord, k: "write" | "retrieve") => obj(top(r)[`${k}_runtime`]);
const handoff = (r: SRecord) => obj(top(r).search_handoff);
const hash = (v: unknown) => (typeof v === "string" ? v : "");
function correlation(r: SRecord, withRetrieve: boolean): [string, boolean][] {
  const rt = r.runtime, w = sub(r, "write"), c = hash(rt.content_hash);
  const out: [string, boolean][] = [["The recall run names the write run as its source (source_run_id = write run id)", rid(r, "write") !== "—" && rt.source_run_id === top(r).write_run_id], ["The write and recall runs carry the same content hash", c !== "" && hash(w.content_hash) === c]];
  if (withRetrieve) out.push(["The retrieve, write and recall runs carry the same content hash", c !== "" && hash(sub(r, "retrieve").content_hash) === c]);
  return out;
}
function memVerdict(r: SRecord, cap: boolean): Verdict {
  const f = failed(r); if (f) return f;
  const rt = r.runtime, dec = s(rt.follow_on_decision), priv = n(rt.handler_invoke_count), who = cap ? "Neither the retrieved content nor the memory" : "The memory";
  if (s(rt.memory_control_decision) === "—") return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No classification of the recalled memory was recorded." };
  const broken = correlation(r, cap).filter(([, ok]) => !ok);
  if (broken.length) return { kind: "CORRELATION_BROKEN", label: "RUNS DO NOT CORRELATE", tone: "warn", head: `The runs of this launch do not line up: ${broken.map(([t]) => t.toLowerCase()).join("; ")}. Read nothing into the outcome until they do.` };
  const prefix = cap ? "RETRIEVED, STORED AND RECALLED" : "RECALLED MEMORY";
  if (dec === "ALLOW") return priv > 0 ? { kind: "RAN", label: `${prefix}: FOLLOW-ON TOOL ALLOWED AND RAN`, tone: "bad", head: r.profile === "vulnerable" ? `On the deliberately vulnerable setting CTRL-MCP-001 allowed lookup_customer_tier through a labelled fail-open overlay and the handler ran (count ${priv}). ${who} granted that.` : "The privileged tool ran on a defended run. That is unexpected for this lab." }
    : { kind: "ALLOWED_NOT_RUN", label: "ALLOWED BUT NO HANDLER RAN", tone: "warn", head: "The follow-on request was allowed but the handler count is 0. An ALLOW is a decision, not an execution." };
  if (dec === "DENY") return priv > 0 ? { kind: "DENIED_BUT_RAN", label: "DENIED BUT THE HANDLER RAN", tone: "bad", head: "The decision was DENY but the handler count is above 0. That contradicts the control." }
    : { kind: "DENIED_NOT_RUN", label: `${prefix}: FOLLOW-ON TOOL DENIED, HANDLER DID NOT RUN`, tone: "good", head: `The memory control only observed (${s(rt.memory_control_decision)}). CTRL-MCP-001 denied lookup_customer_tier (${s(rt.follow_on_reason)}) and the handler count is 0. The classification stopped nothing; the authorization decision did. A DENY is not automatically SAFE.` };
  return priv === 0 ? { kind: "NORMAL", label: `${cap ? "RETRIEVED, STORED AND RECALLED" : "STORED AND RECALLED"}, NO FOLLOW-ON`, tone: "plain", head: "The content was stored and recalled and classified (OBSERVE). No follow-on tool was requested and no handler ran. That is an observation, not proof the content is safe." }
    : { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "A handler ran without a recorded follow-on decision. Read the table below before concluding anything." };
}
const runLine = (r: SRecord, cap: boolean) => `${cap ? `Local events: retrieve ${s(top(r).local_event_count_retrieve)}, ` : "Local events: "}write ${s(top(r).local_event_count_write)}, recall ${s(top(r).local_event_count_recall)}. Per-run state: ${cap ? `retrieve ${s(top(r).retrieve_evidence_state)}, ` : ""}write ${s(top(r).write_evidence_state)}, recall ${s(top(r).recall_evidence_state)}. otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.`;

function memScenario(cap: boolean): Scenario {
  const lab = cap ? "LAB-AGENTSEC-CAPSTONE-001" : "LAB-MEMORY-001", cls = cap ? "retrieval and memory controls" : "memory control";
  const sc: Scenario = {
    lab, aria: cap ? "Guided sequence for the Lending Assistant Capstone" : "Guided sequence for Persistent Memory",
    intro: `This lab calls no language model: the ${cap ? "retrieve, write and recall steps and the tool request are" : "write, recall and tool request are"} a scripted, deterministic sequence, not an agent reasoning. One launch mints ${cap ? "three run ids (retrieve, write, recall)" : "two run ids (write, recall)"}; the run id on the card is the recall run.`,
    baselineLabel: cap ? "Run BASELINE (normal document)" : "Run BASELINE (normal memory)", baselineHint: cap ? "A normal document gives you something to compare the adversarial one with." : "A normal memory entry gives you something to compare the malicious one with.",
    questions: [
      { key: "classify", legend: cap ? "On the intentionally vulnerable ATTACK setting, the retrieved content and the later-recalled memory will each be classified as…" : "On the intentionally vulnerable ATTACK setting, CTRL-MEMORY-CONTEXT-001 will classify the recalled memory as…", opts: [["OBSERVE", "OBSERVE (record it as data)"], ["DENY", "DENY (refuse it)"]] },
      { key: "decision", legend: "…CTRL-MCP-001 will decide the follow-on lookup_customer_tier request as…", opts: [["ALLOW", "ALLOW"], ["DENY", "DENY"]] },
      { key: "handler", legend: "…and the privileged handler (lookup_customer_tier)…", opts: [["yes", "will run"], ["no", "will not run"]] }],
    guess: (a, p) => `You predicted ${p.classify} from the ${cls}, ${p.decision} from the tool control and that the privileged handler ${p.handler === "yes" ? "would" : "would not"} run. Recorded: ${s(a.runtime.memory_control_decision)}, ${s(a.runtime.follow_on_decision)} and a handler count of ${n(a.runtime.handler_invoke_count)}.`,
    sameInput: (a, r) => a.runtime.memory_id === r.runtime.memory_id && a.runtime.content_hash === r.runtime.content_hash,
    compareCaption: (same) => (same ? `Same ${cap ? "retrieved document, stored memory" : "memory"} and content hash, different server-owned setting.` : "Different content."),
    compareNote: (same) => `${same ? "The same bytes produced a different outcome because CTRL-MCP-001's decision changed, not because the content changed. " : ""}The classification was OBSERVE on both runs, so it is not what changed the outcome. A DENY is not automatically SAFE, an ALLOW is not an execution, one retest is not universal resistance, and no model was involved.`,
    interpret: (r) => memVerdict(r, cap),
    steps: (r, ev) => { const rt = r.runtime, v = memVerdict(r, cap), rr = sub(r, "retrieve"); return [launch(r),
      ...(cap ? [{ id: "retrieve", label: "Retrieve run", icon: "search", state: rid(r, "retrieve") !== "—" ? "done" : "warn", detail: `${s(top(r).document_id)}: CTRL-RAG-CONTEXT-001 ${s(rr.context_control_decision)} (${s(rr.context_control_reason)}); hash ${short(rr.content_hash)}.` } as Step] : []),
      { id: "write", label: "Write run", icon: "terminal", state: rid(r, "write") !== "—" ? "done" : "warn", detail: `Stored ${s(rt.memory_id)} (hash ${short(sub(r, "write").content_hash)}). Persisting did not grant any tool; the write run has its own run id.` },
      { id: "recall", label: "Recall run and classification", icon: "shield", state: rt.memory_control_decision ? "done" : "warn", detail: `CTRL-MEMORY-CONTEXT-001: ${s(rt.memory_control_decision)} (${s(rt.memory_control_reason)}). Source run ${short(rt.source_run_id)}.` },
      authz(r),
      { id: "exec", label: "Execution", icon: "play", state: "done", detail: `Privileged handler (lookup_customer_tier) ran ${n(rt.lookup_customer_tier_handler_count)} time(s)${cap ? ", counted once, on recall" : ""}. The handler count is the authoritative record of execution.` },
      ...finish(r, v, ev)]; },
    hopStep: (h) => (h["hop.index"] === 0 ? "Recall classified (CTRL-MEMORY-CONTEXT-001)" : "Tool authorization (CTRL-MCP-001)"),
    compareRows: (a, r) => { const c = (x: SRecord) => (correlation(x, cap).every(([, ok]) => ok) ? "held" : "did not hold");
      return [["Setting (profile)", a.profile, r.profile], ...(cap ? [["Retrieved document", s(top(a).document_id), s(top(r).document_id)] as [string, string, string], ["Retrieve classification", s(sub(a, "retrieve").context_control_decision), s(sub(r, "retrieve").context_control_decision)] as [string, string, string]] : []),
        ["Memory id", s(a.runtime.memory_id), s(r.runtime.memory_id)], ["Content hash", short(a.runtime.content_hash), short(r.runtime.content_hash)], ["Recall classification (CTRL-MEMORY-CONTEXT-001)", s(a.runtime.memory_control_decision), s(r.runtime.memory_control_decision)],
        ["Tool decision (CTRL-MCP-001)", s(a.runtime.follow_on_decision), s(r.runtime.follow_on_decision)], ["Tool reason", s(a.runtime.follow_on_reason), s(r.runtime.follow_on_reason)], ["Privileged handler count", String(n(a.runtime.handler_invoke_count)), String(n(r.runtime.handler_invoke_count))],
        ["Run correlation", c(a), c(r)], ["Outcome", memVerdict(a, cap).label, memVerdict(r, cap).label]]; },
    columns: [
      [`1. Run ids and correlation`, (r) => `${cap ? `RETRIEVE ${rid(r, "retrieve")}; ` : ""}WRITE ${rid(r, "write")}; RECALL ${rid(r, "recall")}. Memory ${s(r.runtime.memory_id)}, hash ${short(r.runtime.content_hash)}. ${correlation(r, cap).map(([t, ok]) => `${ok ? "Held" : "NOT held"}: ${t}.`).join(" ")}`],
      ["2. Content classification", (r) => `${cap ? `Retrieve: ${s(sub(r, "retrieve").context_control_decision)} (${s(sub(r, "retrieve").context_control_reason)}). Recall: ` : "Recall: "}${s(r.runtime.memory_control_decision)} (${s(r.runtime.memory_control_reason)}). Classifies only; it neither grants nor blocks a tool.`],
      ["3. Tool authorization", (r) => { const h = hop(r, 1); return h ? `${h["control.decision"]} (${h["control.reason"]}) for ${hopTool(h)}. A decision only.` : "No follow-on tool was requested."; }],
      ["4. Actual execution", (r) => { const h = hop(r, 1); return `Handler count ${n(r.runtime.handler_invoke_count)}${h ? `; started ${String(h["mcp.started"])}, executed ${String(h["operation.executed"])}` : ""}${cap ? ". Counted once, on recall." : "."}`; }],
      ["5. Telemetry received", (r) => runLine(r, cap)],
      ["6. Independently verified", () => NOT_VERIFIED]],
    ids: (r) => [...(cap ? [["RETRIEVE", rid(r, "retrieve")] as [string, string]] : []), ["WRITE", rid(r, "write")], ["RECALL", rid(r, "recall")]],
    links: (r) => { const h = handoff(r), u = (k: string) => (typeof h[k] === "string" ? (h[k] as string) : ""); return ([...(cap ? [["RETRIEVE", u("retrieve_search_url")]] : []), ["WRITE", u("write_search_url")], ["RECALL", u("recall_search_url")]] as [string, string][]).filter(([, url]) => url); },
    correlation: (r) => correlation(r, cap),
  };
  return sc;
}
export const MEMORY = memScenario(false), CAPSTONE = memScenario(true);

// ---- MCP family (LAB-MCP-003, -004, -005, -CATALOG): the same /mcp/invoke path as LAB-MCP-001, launched from the allowlist. No language model.
// Every value is read from the hops of the launch record; the browser never chooses the tool, scope, resource or profile.
interface McpCfg { control?: string; lab: string; aria: string; intro: string; what: string; follow: boolean; reasonWord: string; sameWhat: string }
const hopsOf = (r: SRecord) => r.runtime?.hops ?? [];
const FAIL_OPEN = (h: Hop) => String(h["control.reason"]).startsWith("vulnerable_profile_fail_open");
// The hop that decided the outcome: a DENY, else the labelled fail-open ALLOW (it can be the delegation hop of LAB-MCP-006), else the last hop.
const decisive = (r: SRecord) => { const h = hopsOf(r); return h.find((x) => x["control.decision"] === "DENY") ?? h.find(FAIL_OPEN) ?? h[h.length - 1]; };
// Did a handler run for the deciding step? A DENY: that hop's own flag (an earlier, legitimate call may have run). A fail-open ALLOW: that hop or any later one.
const anyRan = (r: SRecord) => { const d = decisive(r); return d ? hopsOf(r).some((x) => x["hop.index"] >= d["hop.index"] && x["operation.executed"]) : false; };
const mcpFamily = (c: McpCfg): Scenario => {
  const sc: Scenario = {
    lab: c.lab, aria: c.aria, intro: c.intro,
    baselineLabel: "Run BASELINE (granted request)", baselineHint: "A granted request gives you the normal shape to compare the attack with.",
    questions: [
      { key: "decision", legend: `On the intentionally vulnerable ATTACK setting, CTRL-MCP-001 will decide ${c.what} as…`, opts: [["ALLOW", "ALLOW"], ["DENY", "DENY"]] },
      { key: "handler", legend: "…and the handler for that request…", opts: [["yes", "will run"], ["no", "will not run"]] }],
    guess: (a, p) => { const h = decisive(a); return `You predicted ${p.decision} and that the handler ${p.handler === "yes" ? "would" : "would not"} run. Recorded: ${h ? `${h["control.decision"]} (${h["control.reason"]}), handler ${anyRan(a) ? "ran" : "did not run"}` : "no decision"}.`; },
    sameInput: (a, r) => top(a).input_fingerprint === top(r).input_fingerprint,
    compareCaption: (same) => (same ? `Same request (${c.sameWhat}), different server-owned setting.` : "Different requests."),
    compareNote: (same) => `${same ? "The same request produced a different outcome because the server-owned setting changed, not because the request changed. " : ""}A DENY is not automatically SAFE, an ALLOW is not an execution, one retest is not universal resistance, Splunk enforced nothing, and no model was involved.`,
    interpret: (r) => {
      const f = failed(r); if (f) return f;
      const h = decisive(r); if (!h) return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No tool decision was recorded for this run." };
      const dec = h["control.decision"], ran = anyRan(r), why = h["control.reason"];
      if (dec === "DENY") return ran ? { kind: "DENIED_BUT_RAN", label: "DENIED BUT THE HANDLER RAN", tone: "bad", head: "The decision was DENY but the handler ran. That contradicts the control." }
        : { kind: "DENIED_NOT_RUN", label: "DENIED, HANDLER DID NOT RUN", tone: "good", head: `CTRL-MCP-001 denied ${s(h["tool.name"])} (${why}) and the handler did not run. A DENY is not automatically SAFE.` };
      if (dec === "ALLOW" && String(why).startsWith("vulnerable_profile_fail_open")) return { kind: "FAIL_OPEN_RAN", label: "ALLOWED BY THE LABELLED FAIL-OPEN SETTING", tone: "bad", head: `On the deliberately vulnerable setting CTRL-MCP-001 allowed ${s(h["tool.name"])} (${why})${ran ? " and the handler ran" : ""}. The lab is fail-open on purpose; that is not a universal bypass.` };
      if (dec === "ALLOW") return { kind: "NORMAL", label: c.follow ? "GRANTED REQUEST RAN, NO FOLLOW-ON" : "GRANTED REQUEST RAN", tone: "plain", head: `The granted request was allowed (${why}) and ${ran ? "the handler ran" : "no handler ran"}. That is an observation, not proof of safety.` };
      return { kind: "NOT_EXERCISED", label: "NOT EXERCISED", tone: "warn", head: "No allow or deny decision was recorded." };
    },
    steps: (r, ev) => { const h = decisive(r), v = sc.interpret(r); return [launch(r),
      { id: "authz", label: "Tool authorization", icon: "shield", state: h ? "done" : "warn", detail: h ? `${c.control ?? "CTRL-MCP-001"} on ${s(h["tool.name"])}: ${h["control.decision"]} (${h["control.reason"]}).` : "No decision was recorded." },
      { id: "exec", label: "Execution", icon: "play", state: "done", detail: `${hopsOf(r).map((x) => `${s(x["tool.name"])}: handler ${x["operation.executed"] ? "ran" : "did not run"}`).join("; ") || "No hop recorded"}. The handler record is the authoritative execution record.` },
      ...finish(r, v, ev)]; },
    hopStep: (h) => (h["hop.index"] === 0 ? "Tool authorization (CTRL-MCP-001)" : `Follow-on tool authorization (${c.reasonWord})`),
    compareRows: (a, r) => { const x = decisive(a), y = decisive(r);
      return [["Setting (profile)", a.profile, r.profile], ["Decisive tool", s(x?.["tool.name"]), s(y?.["tool.name"])], [`Decision (${c.control ?? "CTRL-MCP-001"})`, s(x?.["control.decision"]), s(y?.["control.decision"])], ["Reason", s(x?.["control.reason"]), s(y?.["control.reason"])],
        ["Handler ran", String(anyRan(a)), String(anyRan(r))], ["Outcome", sc.interpret(a).label, sc.interpret(r).label]]; },
    columns: [
      ["1. Request as recorded", (r) => `${hopsOf(r).map((x) => s(x["tool.name"])).join(" then ") || "—"}; input fingerprint ${short(top(r).input_fingerprint)}.`],
      ["2. Tool authorization", (r) => { const h = decisive(r); return h ? `${h["control.decision"]} (${h["control.reason"]}) for ${s(h["tool.name"])}. A decision only.` : "No tool decision was recorded."; }],
      ["3. Actual execution", (r) => { const h = hopsOf(r).find((x) => x["hop.index"] >= (decisive(r)?.["hop.index"] ?? 0) && x["operation.executed"]) ?? decisive(r); return h ? `started ${String(h["mcp.started"])}, attempted ${String(h["operation.attempted"])}, executed ${String(h["operation.executed"])}${anyRan(r) ? "" : " for the deciding step"}.` : "No hop recorded."; }],
      ["4. Telemetry received", (r) => `${r.local_event_count ?? "?"} local events; otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.`],
      ["5. Independently verified", () => NOT_VERIFIED]],
  };
  return sc;
};
export const MCP_003 = mcpFamily({ lab: "LAB-MCP-003", aria: "Guided sequence for Scope Escalation", intro: "This lab calls no language model. The tool lookup_policy is granted at policy:read; the attack asks for the excessive scope policy:restricted:read. It tests whether a tool grant is also a scope grant.", what: "the lookup_policy request at the excessive scope", follow: false, reasonWord: "n/a", sameWhat: "tool, scope and arguments" });
export const MCP_004 = mcpFamily({ lab: "LAB-MCP-004", aria: "Guided sequence for Parameter and Resource Authorization", intro: "This lab calls no language model. The tool and scope are granted; the attack names the ungranted resource executive-restricted. It tests whether a scope grant is also a resource grant.", what: "the lookup_policy request for the ungranted resource", follow: false, reasonWord: "n/a", sameWhat: "tool, scope and arguments" });
export const MCP_005 = mcpFamily({ lab: "LAB-MCP-005", aria: "Guided sequence for Tool Result Trust", intro: "This lab calls no language model. The first call is authorized; its result carries a closed fixture asking for a second tool. It tests whether a tool result can create authority.", what: "the follow-on lookup_customer_tier request created by the result", follow: true, reasonWord: "request created by the tool result", sameWhat: "request and result hash" });
export const MCP_CATALOG = mcpFamily({ lab: "LAB-MCP-CATALOG", aria: "Guided sequence for Tool Catalog", intro: "This lab calls no language model. The first call is authorized; the tool's catalog description carries a closed marker asking for a second tool. It tests whether metadata can create authority.", what: "the follow-on lookup_customer_tier request created by the catalog description", follow: true, reasonWord: "request created by catalog metadata", sameWhat: "request and description hash" });
export const MCP_006 = mcpFamily({ control: "CTRL-DELEGATION-001", lab: "LAB-MCP-006", aria: "Guided sequence for Confused Deputy", intro: "This lab calls no language model and authenticates no agent: the caller (Credit Agent) and the deputy (Compliance Agent) are coded fixtures. It tests whether a deputy may use its own authority for a request the caller never delegated.", what: "the deputy's request for lookup_customer_tier", follow: false, reasonWord: "deputy request", sameWhat: "tool, scope and arguments" });
export const SCENARIOS: Record<string, Scenario> = { [GOAL.lab]: GOAL, [DELEGATION.lab]: DELEGATION, [MEMORY.lab]: MEMORY, [CAPSTONE.lab]: CAPSTONE, [MCP_003.lab]: MCP_003, [MCP_004.lab]: MCP_004, [MCP_005.lab]: MCP_005, [MCP_CATALOG.lab]: MCP_CATALOG, [MCP_006.lab]: MCP_006 };
export { hopTool };
