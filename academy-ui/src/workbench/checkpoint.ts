import type { Checkpoint, InvQuestion, Prediction } from "../curriculum";

// Pure readers over a committed simulated or documented packet. They read only fields that are present; a missing field stays missing.
type Rec = Record<string, unknown>;
export const NOT_RECORDED = "not recorded in this record";
export const text = (v: unknown): string | undefined => v === undefined || v === null ? undefined : typeof v === "string" ? v : typeof v === "object" ? JSON.stringify(v) : String(v);
export const dig = (o: unknown, path: string): unknown => path.split(".").reduce<unknown>((x, k) => (x && typeof x === "object" ? (x as Rec)[k] : undefined), o);
export const modes = (cp: Checkpoint) => (cp.packet.modes as Rec[]) ?? [];
export const modeOf = (cp: Checkpoint, name: string) => modes(cp).find((m) => m.mode === name)!;
export const order = (cp: Checkpoint) => cp.spec.order ?? modes(cp).map((m) => String(m.mode));
export const field = (m: Rec, f: string) => text(m[f]);
export const classification = (cp: Checkpoint) => String(cp.packet.evidence_classification);

export type Answer = { answer: string; recorded: string; reason?: string; how?: string };
/** The packet's answer to a prediction. A derived answer is computed here from the packet's own timestamps or values, and says so. */
export function answer(cp: Checkpoint, mode: string, p: Prediction): Answer {
  const m = modeOf(cp, mode), d = p.derived;
  if (d?.kind === "within") {
    const w = d.window;
    const src = w.lookup ? (dig(cp.packet, w.lookup.list) as Rec[]).find((c) => c[w.lookup!.key] === m[w.lookup!.by]) : (dig(cp.packet, w.packet_path!) as Rec);
    const at = String(m[d.at]), from = String(src?.[w.from]), to = String(src?.[w.to]);
    const inside = Date.parse(at) >= Date.parse(from) && Date.parse(at) <= Date.parse(to);
    return { answer: inside ? d.inside : d.outside, recorded: inside ? d.inside : d.outside, how: `${d.at} ${at}; window ${from} to ${to}${w.lookup ? ` (${String(m[w.lookup.by])})` : ""}` };
  }
  if (d?.kind === "equals") {
    const a = text(m[d.a]), b = text(dig(cp.packet, d.b_packet));
    return { answer: a === b ? "yes" : "no", recorded: a === b ? "yes" : "no", how: `${d.a} ${a}; packet ${d.b_packet} ${b}` };
  }
  const v = text(m[p.field]);
  if (v === undefined) return { answer: NOT_RECORDED, recorded: NOT_RECORDED };
  const hit = p.match === "startswith" ? p.options.find((o) => v.startsWith(o)) : v;
  return { answer: hit ?? v, recorded: v, reason: p.reason_field ? text(m[p.reason_field]) : undefined };
}
export const answerable = (cp: Checkpoint, mode: string, p: Prediction) => p.derived !== undefined || modeOf(cp, mode)[p.field] !== undefined;

export const differing = (cp: Checkpoint, a: string, b: string, fields: { field: string }[]) =>
  fields.filter((f) => field(modeOf(cp, a), f.field) !== field(modeOf(cp, b), f.field)).map((f) => f.field);

export const items = (cp: Checkpoint) => (dig(cp.packet, cp.spec.items_path!) as Rec[]) ?? [];
export const selectWhere = (cp: Checkpoint, q: InvQuestion) => items(cp).filter((i) => {
  const v = text(i[q.where.field]) ?? "";
  return q.where.equals !== undefined ? v === q.where.equals : q.where.not_equals !== undefined ? v !== q.where.not_equals : v.toLowerCase().includes(String(q.where.contains).toLowerCase());
}).map((i) => String(i[cp.spec.name_field!]));
