import type { RecEvent, RecRun } from "../curriculum";

// Pure readers over recorded events. They only read fields that are present; a missing field stays missing and is never filled in.
export const f = (e: RecEvent | undefined, k: string): string | undefined => {
  const v = e?.[k];
  return v === undefined || v === null ? undefined : Array.isArray(v) ? v.join(", ") : String(v);
};
export const name = (e: RecEvent) => (f(e, "event.name") ?? "").replace(/^agentsec\./, "");
export const seq = (e: RecEvent) => Number(e["agentsec.sequence"]);

export const decisiveEvent = (r: RecRun) => r.events.find((e) => seq(e) === r.decisive)!;
export const decision = (r: RecRun) => f(decisiveEvent(r), "agentsec.control.decision");

/** A handler is evidenced only by an mcp.started event that records executed=true. An ALLOW decision is not evidence of execution. */
export const handlerStarts = (r: RecRun) => r.events.filter((e) => f(e, "event.name") === "agentsec.mcp.started" && e["agentsec.operation.executed"] === true);
export const handlerText = (r: RecRun) => {
  const h = handlerStarts(r);
  return h.length ? `Handler began: yes. mcp.started is recorded at sequence ${h.map(seq).join(", ")} (${h.map((e) => f(e, "gen_ai.tool.name") ?? "tool not recorded").join(", ")}).`
    : "Handler began: no mcp.started event is in this pack. Absence in a recording is corroboration, not proof that the handler never ran.";
};

/** The recorded preview is a bounded string; it may be cut off. Show it verbatim and parse only what is valid JSON. */
export const preview = (e: RecEvent) => f(e, "agentsec.content.preview");
export const previewJson = (e: RecEvent): Record<string, unknown> | null => {
  try { const v = JSON.parse(preview(e) ?? ""); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
};
export const authoritySource = (e: RecEvent) => /"authority_source":\s*"([^"]*)"/.exec(preview(e) ?? "")?.[1];

export const question = (e: RecEvent) => f(e, "agentsec.control.id") === "CTRL-MCP-RESULT-001"
  ? "What does CTRL-MCP-RESULT-001 record about this tool result?" : `What does ${f(e, "agentsec.control.id") ?? "the control"} decide about this request?`;

/** What the learner may see before predicting: the request and the grant, plus what the first tool call returned. Never the decision, reason, outcome or later events. */
export function setup(r: RecRun): [string, string][] {
  const d = decisiveEvent(r);
  const rows: [string, string | undefined][] = [
    ["Profile", r.meta.profile], ["Tool", f(d, "gen_ai.tool.name")], ["Requested scope", f(d, "agentsec.mcp.requested_scope")], ["Granted scope", f(d, "agentsec.mcp.allowed_scope")],
    ["Resource named", f(d, "agentsec.mcp.resource.id")], ["Granted resources", f(d, "agentsec.mcp.allowed_resource.ids")],
    ["Request came from", f(d, "agentsec.content.origin.type") ? `${f(d, "agentsec.content.origin.type")} ${f(d, "agentsec.content.origin.id") ?? ""}`.trim() : undefined],
  ];
  return rows.filter((x): x is [string, string] => x[1] !== undefined);
}
export const priorResult = (r: RecRun) => [...r.events].reverse().find((e) => seq(e) < r.decisive && f(e, "event.name") === "agentsec.mcp.completed");

export const outcome = (r: RecRun) => { const l = r.events[r.events.length - 1]; return f(l, "agentsec.outcome") ?? name(l); };

export function summary(e: RecEvent): string {
  const n = f(e, "event.name");
  if (n === "agentsec.control.decision") return `${f(e, "agentsec.control.id") ?? "control"}: ${f(e, "agentsec.control.decision")}, reason ${f(e, "agentsec.control.reason") ?? "not recorded"}`;
  if (n === "agentsec.mcp.started") return `Handler began for ${f(e, "gen_ai.tool.name") ?? "the tool"} (this event records executed=${String(e["agentsec.operation.executed"])})`;
  if (n === "agentsec.mcp.completed") return `Handler finished; the result is marked ${f(e, "agentsec.mcp.result.trust") ?? "trust not recorded"}`;
  if (n === "agentsec.mcp.failed") return "Handler reported a failure";
  if (n === "agentsec.pipeline.stopped") return `Pipeline stopped: ${f(e, "agentsec.stop.reason") ?? "reason not recorded"}`;
  return f(e, "agentsec.outcome") ?? "";
}

export type Row = { label: string; values: string[]; differs: boolean };
const NA = "not recorded";
/** Rows for the runs given, from recorded fields only. */
export function compare(runs: RecRun[]): Row[] {
  const dec = (r: RecRun, k: string) => f(decisiveEvent(r), k) ?? NA;
  const spec: [string, (r: RecRun) => string][] = [
    ["Profile", (r) => r.meta.profile], ["Testbed mode", (r) => r.meta.mode], ["Tool", (r) => dec(r, "gen_ai.tool.name")],
    ["Requested scope", (r) => dec(r, "agentsec.mcp.requested_scope")], ["Granted scope", (r) => dec(r, "agentsec.mcp.allowed_scope")],
    ["Resource named", (r) => dec(r, "agentsec.mcp.resource.id")], ["Authority source in the request preview", (r) => authoritySource(decisiveEvent(r)) ?? NA],
    ["Control", (r) => dec(r, "agentsec.control.id")], ["Decision", (r) => dec(r, "agentsec.control.decision")], ["Reason", (r) => dec(r, "agentsec.control.reason")],
    ["Handler began (mcp.started events)", (r) => String(handlerStarts(r).length)], ["How the run ended", outcome], ["Events in the pack", (r) => String(r.events.length)],
  ];
  return spec.map(([label, get]) => { const values = runs.map(get); return { label, values, differs: new Set(values).size > 1 }; });
}
export const sameRequest = (a: RecRun, b: RecRun) => ["gen_ai.tool.name", "agentsec.mcp.requested_scope", "agentsec.mcp.resource.id"].every((k) => f(decisiveEvent(a), k) === f(decisiveEvent(b), k));
