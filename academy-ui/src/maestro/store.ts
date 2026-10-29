import { useSyncExternalStore } from "react";
import { emptyModel } from "./assess";
import type { Judgment, Model, Path, Threat } from "./types";

// The model is a LOCAL DRAFT: it lives in this browser only and is never sent anywhere. Saving does not approve anything.
const KEY = "agentsec.maestro.v1";
export interface Draft { model: Model; saved: "saved" | "memory"; notice: string }
let draft: Draft | null = null;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
// A saved draft is data from storage, so it is rebuilt field by field into the shape the page expects (types, ranges and sizes), never trusted as it is.
const str = (v: unknown, n: number) => (typeof v === "string" ? v.slice(0, n) : "");
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").map((x) => x.slice(0, 80)).slice(0, 60) : []);
const int = (v: unknown, lo: number, hi: number, dflt: number) => (typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi ? v : dflt);
const pick = <T extends string>(v: unknown, ok: readonly T[]): T | null => (ok.includes(v as T) ? (v as T) : null);
const judgment = (j: any): Judgment => ({ impact: pick(j?.impact, ["LOW", "MODERATE", "HIGH"] as const), likelihood: pick(j?.likelihood, ["UNLIKELY", "POSSIBLE", "LIKELY"] as const), rationale: str(j?.rationale, 400) }); // eslint-disable-line @typescript-eslint/no-explicit-any
const rec = (v: unknown): Record<string, any> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, any>) : {}); // eslint-disable-line @typescript-eslint/no-explicit-any
export function normalize(m: unknown): Model | null {
  const o = rec(m);
  if (typeof o.scope !== "string" || !Array.isArray(o.threats) || !Array.isArray(o.paths) || typeof o.placements !== "object" || typeof o.boundaries !== "object") return null;
  const placements: Model["placements"] = {}, boundaries: Model["boundaries"] = {};
  for (const [k, v] of Object.entries(rec(o.placements)).slice(0, 100)) if (/^[A-Za-z0-9-]{1,40}$/.test(k) && k !== "__proto__") placements[k] = int(v, 0, 7, 0);
  for (const [k, v] of Object.entries(rec(o.boundaries)).slice(0, 100)) if (/^[A-Za-z0-9-]{1,40}$/.test(k) && k !== "__proto__") { const b = rec(v), l = Array.isArray(b.layers) ? b.layers : []; boundaries[k] = { found: b.found === true, layers: [int(l[0], 0, 7, 0), int(l[1], 0, 7, 0)] }; }
  const threats: Threat[] = o.threats.slice(0, 200).map((x: unknown, i: number) => { const t = rec(x); return { id: str(t.id, 20) || `T${i + 1}`, layer: int(t.layer, 1, 7, 1), label: str(t.label, 120), custom: t.custom === true, kind: t.kind === "traditional" ? "traditional" : "agentic",
    description: str(t.description, 600), elements: strs(t.elements), evidence: pick(t.evidence, ["DEMONSTRATED", "DOCUMENTED", "ASSUMED"] as const) ?? "", scenarios: strs(t.scenarios), controls: strs(t.controls), inherent: judgment(t.inherent), mitigation: str(t.mitigation, 600), residual: judgment(t.residual) }; });
  const paths: Path[] = o.paths.slice(0, 50).map((x: unknown, i: number) => { const p = rec(x); return { id: str(p.id, 20) || `P${i + 1}`, name: str(p.name, 120), narrative: str(p.narrative, 600),
    steps: (Array.isArray(p.steps) ? p.steps : []).slice(0, 30).map((y: unknown) => { const s = rec(y); return { layer: int(s.layer, 1, 7, 1), threat: str(s.threat, 20), note: str(s.note, 200) }; }) }; });
  return { scope: str(o.scope, 1500), placements, boundaries, threats, paths };
}

function load(): Draft {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (raw) { const j = JSON.parse(raw), m = j?.v === 1 ? normalize(j.model) : null; if (m) return { model: m, saved: "saved", notice: "" }; return { model: emptyModel(), saved: "saved", notice: "Your saved draft could not be read, so a blank model was started." }; }
    return { model: emptyModel(), saved: "saved", notice: "" };
  } catch { return { model: emptyModel(), saved: "memory", notice: "This browser would not give access to saved drafts, so your work is kept in memory only and is lost on reload." }; }
}
export const getDraft = (): Draft => (draft ??= load());
export function setModel(model: Model, notice = ""): void {
  let saved: Draft["saved"] = "saved";
  try { window.localStorage.setItem(KEY, JSON.stringify({ v: 1, model })); } catch { saved = "memory"; }
  draft = { model, saved, notice: saved === "memory" ? "This browser would not store the draft, so this change is kept in memory only and will be lost on reload." : notice };
  emit();
}
export function clearDraft(): void { try { window.localStorage.removeItem(KEY); } catch { /* nothing saved */ } draft = { model: emptyModel(), saved: "saved", notice: "The draft was cleared." }; emit(); }
export const useDraft = (): Draft => useSyncExternalStore((cb) => { listeners.add(cb); return () => { listeners.delete(cb); }; }, getDraft, getDraft);
