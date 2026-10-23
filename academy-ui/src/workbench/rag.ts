import type { Step } from "../mission/RunProgress";
import type { Evidence, LaunchRecord } from "./launch";

// How to read a LAB-RAG-CONTEXT launch record. Hop 0 is the classification of the retrieved document (CTRL-RAG-CONTEXT-001); a later hop is the follow-on
// tool request (CTRL-MCP-001). Every value comes from the record. This lab calls no language model, so nothing here can say a model obeyed anything.
export interface RagHop { "hop.index": number; "control.decision": string; "control.reason": string; "tool.name": string; "handler.invoked": boolean; "mcp.started": boolean; "mcp.completed": boolean; "operation.attempted": boolean; "operation.executed": boolean; "operation.outcome": string | null }
export interface RagRuntime { document_id: string; content_hash: string; context_control_decision: string; context_control_reason: string; follow_on_decision: string | null; follow_on_reason: string | null; handler_invoke_count: number; lookup_customer_tier_handler_count: number; blocked: boolean; block_reason: string | null; terminal: string; testbed_mode: string; hops: RagHop[] }
export type RagRecord = Omit<LaunchRecord, "runtime"> & { runtime: RagRuntime };
export const asRag = (r: LaunchRecord | null | undefined) => (r ? (r as unknown as RagRecord) : null);

export type RagKind = "NORMAL" | "ALLOWED_AND_RAN" | "DENIED_NOT_RUN" | "DENIED_BUT_RAN" | "ALLOWED_NOT_RUN" | "NOT_EXERCISED" | "FAILED";
export const RAG_KIND: Record<RagKind, { label: string; tone: "bad" | "good" | "warn" | "plain" }> = {
  NORMAL: { label: "NORMAL DOCUMENT OBSERVED, NO FOLLOW-ON", tone: "plain" }, ALLOWED_AND_RAN: { label: "FOLLOW-ON TOOL ALLOWED AND RAN", tone: "bad" }, DENIED_NOT_RUN: { label: "FOLLOW-ON TOOL DENIED, HANDLER DID NOT RUN", tone: "good" },
  DENIED_BUT_RAN: { label: "DENIED BUT THE HANDLER RAN", tone: "bad" }, ALLOWED_NOT_RUN: { label: "ALLOWED BUT THE HANDLER DID NOT RUN", tone: "warn" }, NOT_EXERCISED: { label: "NOT EXERCISED", tone: "warn" }, FAILED: { label: "RUN FAILED", tone: "warn" },
};
export const followOn = (r: RagRecord) => r.runtime?.hops?.find((h) => h["tool.name"]);
export const ran = (r: RagRecord) => (r.runtime?.handler_invoke_count ?? 0) > 0;
const short = (h?: string) => (h ? h.replace("sha256:", "").slice(0, 12) + "…" : "—");
export const hashShort = short;

export function interpret(r: RagRecord): { kind: RagKind; head: string } {
  const rt = r.runtime, f = followOn(r), dec = rt?.follow_on_decision;
  if (r.runtime_status !== "COMPLETED" || !rt) return { kind: "FAILED", head: "The runtime did not complete, so no control result can be read." };
  if (!rt.context_control_decision) return { kind: "NOT_EXERCISED", head: "No classification of the retrieved document was recorded." };
  if (!dec && !f) return { kind: "NORMAL", head: ran(r) ? "No follow-on request was recorded, yet a handler count was reported. Read the table below before concluding anything." : "The document was retrieved and classified (OBSERVE). No follow-on tool was requested and no handler ran. That is an observation, not proof the document is safe." };
  if (dec === "ALLOW") return ran(r) ? { kind: "ALLOWED_AND_RAN", head: r.profile === "vulnerable" ? "On the deliberately vulnerable setting CTRL-MCP-001 allowed the follow-on request (a labelled fail-open) and the handler ran. The document did not grant that permission, and no model was involved in this lab." : "CTRL-MCP-001 allowed the follow-on request on a defended run and the handler ran. That is unexpected for this lab." } : { kind: "ALLOWED_NOT_RUN", head: "The follow-on request was allowed but the handler count is 0. An ALLOW is a decision, not an execution." };
  return ran(r) ? { kind: "DENIED_BUT_RAN", head: "The decision was DENY but the handler count is above 0. That contradicts the control." } : { kind: "DENIED_NOT_RUN", head: `CTRL-MCP-001 denied the follow-on request (${rt.follow_on_reason}) and the handler count is 0. The classification step (OBSERVE) did not stop anything; the authorization control did. A DENY is not automatically SAFE.` };
}

export function ragSteps(r: RagRecord, ev?: Evidence | null): Step[] {
  const rt = r.runtime, ok = r.runtime_status === "COMPLETED", f = followOn(r), k = interpret(r).kind;
  const splunk: Pick<Step, "state" | "detail"> = !ev ? { state: "pending", detail: "Splunk has not been checked yet." }
    : ev.splunk_ok === false || ev.probe_error ? { state: "warn", detail: `Splunk could not be checked from this service${ev.probe_error ? ` (${ev.probe_error})` : ""}.` }
    : ev.evidence_state === "EVIDENCE_READY" ? { state: "done", detail: `Splunk returned ${ev.splunk_count ?? "≥1"} event(s) for this run.id. That is an existence check, not verification.` }
    : { state: "pending", detail: `Splunk has no events for this run.id yet (${ev.splunk_count ?? 0}). Not a failure, and not proof of prevention.` };
  return [
    { id: "launch", label: "Launch", icon: "clock", state: ok ? "done" : "failed", detail: `Run minted · ${r.mode} · ${r.profile} profile · live.` },
    { id: "retrieved", label: "Content retrieved", icon: "search", state: rt?.document_id ? "done" : "warn", detail: rt?.document_id ? `${rt.document_id}, content hash ${short(rt.content_hash)}.` : "No document was recorded." },
    { id: "classified", label: "Content classified", icon: "shield", state: rt?.context_control_decision ? "done" : "warn", detail: rt?.context_control_decision ? `CTRL-RAG-CONTEXT-001: ${rt.context_control_decision} (${rt.context_control_reason}). This classifies; it does not grant or block a tool.` : "No classification was recorded." },
    { id: "authorized", label: "Follow-on authorization", icon: "shield", state: f ? "done" : ok ? "pending" : "warn", detail: f ? `CTRL-MCP-001 on ${f["tool.name"]}: ${f["control.decision"]} (${f["control.reason"]}).` : "No follow-on tool was requested in this run." },
    { id: "executed", label: "Tool execution", icon: "play", state: ok ? "done" : "warn", detail: `Handler ran ${rt?.handler_invoke_count ?? "?"} time(s). The handler count is the authoritative record of execution.` },
    { id: "telemetry", label: "Telemetry", icon: "terminal", state: r.local_event_count ? "done" : "warn", detail: `${r.local_event_count ?? "?"} local events recorded. Collector export reported otlp.ok ${String(r["otlp.ok"])}, hec.ok ${String(r["hec.ok"])}. Not the same as indexed in Splunk.` },
    { id: "evidence", label: "Splunk evidence", icon: "search", ...splunk },
    { id: "outcome", label: "Outcome", icon: k === "DENIED_NOT_RUN" ? "shield" : "target", state: k === "FAILED" || k === "NOT_EXERCISED" || k === "ALLOWED_NOT_RUN" ? "warn" : "done", detail: RAG_KIND[k].label.toLowerCase() },
  ];
}
