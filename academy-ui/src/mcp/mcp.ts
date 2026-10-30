import { api, post, problemText } from "../api";
import type { Step } from "../mission/RunProgress";

// Types and derivations for the MCP Tool Authorization exercise, from the EXISTING launch and evidence endpoints. Nothing is invented:
// a step that the record does not support is shown as "pending" or "warn" with the reason, never filled in.
export const LAB = "LAB-MCP-001", SPECIMEN = "MCP-002", BASELINE_SPECIMEN = "MCP-001"; // the allowlist pairs BASELINE with MCP-001 (a granted request) and ATTACK/RETEST with MCP-002

export interface McpHop {
  agent_name: string; "tool.name": string; "control.decision": string; "control.reason": string;
  "handler.invoked": boolean; "mcp.started": boolean; "mcp.completed": boolean; "mcp.failed": boolean;
  "operation.attempted": boolean; "operation.executed": boolean; "operation.outcome": string;
}
export interface McpRecord {
  run_id: string; mode: string; profile: string; specimen_id: string; runtime_status: string; evidence_state: string; local_event_count: number;
  lifecycle: string[]; note?: string; "hec.ok": boolean; "otlp.ok": boolean; splunk_verified: boolean; intentionally_vulnerable?: boolean;
  runtime: { hops: McpHop[]; actual_behavior: string; terminal: string; blocked: boolean; block_reason: string | null; handler_invoke_count: number };
  search_handoff: { search_url: string; starter_spl: string };
}
export interface McpEvidence { evidence_state: string; splunk_attempted?: boolean; splunk_ok?: boolean; splunk_count?: number; probe_error?: string | null; note?: string }
export interface McpManifest { title: string; security_question: string; control_id: string; prediction: Record<string, Record<string, string>>; limitations: string[] }

export async function loadManifest(): Promise<McpManifest | null> { const r = await api<McpManifest>(`/api/labs/${LAB}`); return r.ok ? r.data : null; }
export async function loadRecord(id: string): Promise<McpRecord | null> { const r = await api<McpRecord>(`/api/launches/${encodeURIComponent(id)}`); return r.ok ? r.data : null; }
export async function launchMcp(mode: "BASELINE" | "ATTACK" | "RETEST"): Promise<{ record?: McpRecord; error?: string }> {
  const r = await post<McpRecord>("/api/launch", { lab_id: LAB, specimen_id: mode === "BASELINE" ? BASELINE_SPECIMEN : SPECIMEN, mode, execution: "live" });
  return r.ok && r.data.run_id ? { record: r.data } : { error: problemText(r) };
}
export async function checkEvidence(id: string): Promise<McpEvidence | null> {
  const r = await api<McpEvidence>(`/api/launches/${encodeURIComponent(id)}/evidence?timeout_seconds=0`); return r.ok ? r.data : null;
}
export async function compareHandoff(attack: string, retest: string): Promise<{ search_url: string; starter_spl: string } | null> {
  const r = await post("/api/compare-handoff", { attack_run_id: attack, retest_run_id: retest }); return r.ok ? r.data : null;
}

export type McpKind = "ATTACK_SUCCEEDED" | "BLOCKED" | "DENIED_BUT_EXECUTED" | "NOT_EXERCISED" | "FAILED";
export const KIND: Record<McpKind, { label: string; tone: "bad" | "good" | "warn" }> = {
  ATTACK_SUCCEEDED: { label: "ATTACK SUCCEEDED", tone: "bad" }, BLOCKED: { label: "ATTACK BLOCKED", tone: "good" },
  DENIED_BUT_EXECUTED: { label: "DENIED BUT EXECUTED", tone: "bad" }, NOT_EXERCISED: { label: "NOT EXERCISED", tone: "warn" }, FAILED: { label: "EXECUTION FAILED", tone: "warn" },
};
export const hopOf = (r: McpRecord) => r.runtime?.hops?.[0];

export function outcomeOf(r: McpRecord): { kind: McpKind; head: string } {
  const h = hopOf(r);
  if (r.runtime_status !== "COMPLETED") return { kind: "FAILED", head: "The launch did not complete, so no authorization result can be read." };
  if (!h) return { kind: "NOT_EXERCISED", head: "No authorization decision was recorded for this run." };
  const ran = h["handler.invoked"] || h["operation.executed"];
  if (h["control.decision"] === "ALLOW" && ran) return { kind: "ATTACK_SUCCEEDED", head: r.profile === "vulnerable" ? "CTRL-MCP-001 allowed a tool it never granted (labelled fail-open), and the handler ran." : "The ungranted tool was allowed and its handler ran." };
  if (h["control.decision"] === "DENY" && ran) return { kind: "DENIED_BUT_EXECUTED", head: "The decision was DENY but the handler still began. That contradicts the control." };
  if (h["control.decision"] === "DENY") return { kind: "BLOCKED", head: "CTRL-MCP-001 denied the request before the handler started. A DENY is not automatically SAFE: read the evidence." };
  return { kind: "NOT_EXERCISED", head: `The decision recorded was ${h["control.decision"]}; the handler did not run.` };
}

export function mcpSteps(r: McpRecord, ev?: McpEvidence | null): Step[] {
  const h = hopOf(r), done = r.runtime_status === "COMPLETED";
  const { kind } = outcomeOf(r);
  const splunk: Pick<Step, "state" | "detail"> = !ev ? { state: "pending", detail: `${r.local_event_count} local events recorded. Splunk has not been checked yet.` }
    : ev.splunk_ok === false || ev.probe_error ? { state: "warn", detail: `${r.local_event_count} local events. Splunk could not be checked from this service${ev.probe_error ? ` (${ev.probe_error})` : ""}.` }
    : ev.evidence_state === "EVIDENCE_READY" ? { state: "done", detail: `Splunk returned ${ev.splunk_count ?? "≥1"} event(s) for this run.id (EVIDENCE_READY). That is an existence check, not SPLUNK-VERIFIED.` }
    : { state: "pending", detail: `Splunk has no events for this run.id yet (${ev.splunk_count ?? 0}). That is not a failure or proof of prevention.` };
  return [
    { id: "launch", label: "Launch", icon: "clock", state: done ? "done" : "failed", detail: `Run minted · ${r.mode} · ${r.profile} profile · live.` },
    { id: "request", label: "Tool request", icon: "terminal", state: h ? "done" : "warn", detail: h ? `${h.agent_name} requested ${h["tool.name"]} through tools/call.` : "No tool request was recorded." },
    { id: "auth", label: "Authorization decision", icon: "shield", state: h ? "done" : "warn", detail: h ? `CTRL-MCP-001: ${h["control.decision"]}. ${h["control.reason"].split(":")[0]}.` : "No decision was recorded." },
    { id: "exec", label: "Handler execution", icon: "play", state: h ? "done" : "warn", detail: h ? `Handler ${h["handler.invoked"] ? "ran" : "did not run"} · mcp.started ${h["mcp.started"]} · completed ${h["mcp.completed"]} · failed ${h["mcp.failed"]}.` : "Unknown." },
    { id: "evidence", label: "Evidence", icon: "search", ...splunk },
    { id: "outcome", label: "Outcome", icon: kind === "BLOCKED" ? "shield" : "target", state: kind === "FAILED" || kind === "NOT_EXERCISED" ? "warn" : "done", detail: KIND[kind].label.toLowerCase() },
  ];
}
