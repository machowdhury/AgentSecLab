import type { Eval, Investigation, InvRun, RecEvent, Ref, Scenario } from "../curriculum";
import { f, name, seq } from "./recorded";

// Pure readers over the committed packs. The answer to a question is computed here from the recorded events, never typed in beside the question.
export const NONE = "NONE RECORDED";
export const runOf = (inv: Investigation, scenario: string, stage: string): InvRun | undefined => inv.scenarios.find((s) => s.id === scenario)?.runs.find((r) => r.stage === stage);

const pick = (run: InvRun, where: { control?: string; event?: string; nth?: "first" | "last" } = {}): RecEvent | undefined => {
  const hits = run.events.filter((e) => (where.control ? f(e, "agentsec.control.id") === where.control && f(e, "event.name") === "agentsec.control.decision" : where.event ? f(e, "event.name") === where.event : true));
  return where.nth === "first" ? hits[0] : hits[hits.length - 1];
};
export type Found = { value: string | undefined; pointer: string };
const dig = (o: unknown, path: string[]): unknown => path.reduce<unknown>((x, k) => (x && typeof x === "object" ? (x as Record<string, unknown>)[k] : undefined), o);

export function resolve(inv: Investigation, ref: Ref): Found {
  if (ref.src === "run") { const r = runOf(inv, ref.scenario, ref.stage); return { value: r?.run_id, pointer: r ? `${ref.scenario} ${ref.stage} run ${r.run_id}` : "no such run" }; }
  if (ref.src === "external") {
    const rec = inv.external.find((x) => x.scan_id === ref.scan)?.records.find((r) => dig(r, ref.path) !== undefined);
    const v = rec ? dig(rec, ref.path) : undefined;
    return { value: v === undefined ? undefined : String(v), pointer: `scanner pack ${ref.scan.slice(0, 8)}, ${ref.path.join(".")}` };
  }
  const run = runOf(inv, ref.scenario, ref.stage), e = run && pick(run, ref.where);
  let value = e ? f(e, ref.field) : undefined;
  if (value !== undefined && ref.json) {          // a string key inside a recorded preview. Previews are cut at 200 characters, so this reads the text, not a parsed document.
    value = new RegExp(`"${ref.json}":\\s*"([^"]*)"`).exec(value)?.[1];
  }
  return { value, pointer: run && e ? `${ref.scenario} ${ref.stage} run ${run.run_id.slice(0, 8)}, event ${seq(e)} ${name(e)}, ${ref.field}${ref.json ? " → " + ref.json : ""}` : `${ref.scenario} ${ref.stage}: no such event` };
}

export const handlerStartsFor = (run: InvRun | undefined, tool: string) =>
  (run?.events ?? []).filter((e) => f(e, "event.name") === "agentsec.mcp.started" && e["agentsec.operation.executed"] === true && f(e, "gen_ai.tool.name") === tool);

export function evaluate(inv: Investigation, ev: Eval): { answer: string; pointers: string[] } {
  if (ev.kind === "value") { const r = resolve(inv, ev.ref); return { answer: r.value ?? NONE, pointers: [r.pointer] }; }
  if (ev.kind === "equal") {
    const a = resolve(inv, ev.a), b = resolve(inv, ev.b);
    return { answer: a.value === undefined || b.value === undefined ? "not comparable" : a.value === b.value ? "same" : "different", pointers: [a.pointer, b.pointer] };
  }
  const run = runOf(inv, ev.scenario, ev.stage), h = handlerStartsFor(run, ev.tool);
  return { answer: h.length ? "yes" : "no", pointers: [run ? `${ev.scenario} ${ev.stage} run ${run.run_id.slice(0, 8)}: ${h.length ? `mcp.started for ${ev.tool} at sequence ${h.map(seq).join(", ")}` : `no mcp.started for ${ev.tool} in the pack`}` : "no such run"] };
}

export type Filter = "all" | "decisions" | "handlers" | "context";
const isContext = (e: RecEvent) => /memory|retriev|rag/i.test(f(e, "event.name") ?? "") || /MEMORY|RAG/.test(f(e, "agentsec.control.id") ?? "");
export const keep = (e: RecEvent, filter: Filter) => filter === "all" ? true
  : filter === "decisions" ? f(e, "event.name") === "agentsec.control.decision"
  : filter === "handlers" ? (f(e, "event.name") ?? "").startsWith("agentsec.mcp.")
  : isContext(e);

/** Per-scenario facts for the comparison table, all read from the events. */
export function summarize(s: Scenario): { label: string; value: string }[] {
  const decisions = s.runs.flatMap((r) => r.events.filter((e) => f(e, "event.name") === "agentsec.control.decision").map((e) => `${s.runs.length > 1 ? r.stage + ": " : ""}${f(e, "agentsec.control.id")} ${f(e, "agentsec.control.decision")} (${f(e, "agentsec.control.reason") ?? "no reason recorded"})`));
  const starts = s.runs.flatMap((r) => r.events.filter((e) => f(e, "event.name") === "agentsec.mcp.started" && e["agentsec.operation.executed"] === true).map((e) => `${s.runs.length > 1 ? r.stage + ": " : ""}${f(e, "gen_ai.tool.name") ?? "tool not recorded"}`));
  return [
    { label: "Profile", value: [...new Set(s.runs.map((r) => r.meta.profile))].join(", ") },
    { label: "Testbed mode", value: [...new Set(s.runs.map((r) => r.meta.mode))].join(", ") },
    { label: "Runs and events", value: s.runs.map((r) => `${r.stage} ${r.run_id.slice(0, 8)} (${r.events.length})`).join("; ") },
    { label: "Control decisions", value: decisions.join("; ") || NONE },
    { label: "Handler starts (mcp.started)", value: starts.join("; ") || "none in these packs" },
    { label: "How each run ended", value: s.runs.map((r) => { const l = r.events[r.events.length - 1]; return `${r.stage}: ${f(l, "agentsec.outcome") ?? name(l)}`; }).join("; ") },
  ];
}
