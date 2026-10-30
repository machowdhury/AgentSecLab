// Reading a notebook result for the learner. Everything here is computed from the rows the search returned; nothing is added from outside the rows.
export interface Insight { barsTitle: string; bars: { label: string; value: number }[]; sentences: string[] }

const col = (cols: string[], name: string) => cols.indexOf(name);
const tally = (rows: string[][], i: number) => {
  const t = new Map<string, number>();
  rows.forEach((r) => { const k = r[i] || "(none)"; t.set(k, (t.get(k) ?? 0) + 1); });
  return [...t].map(([label, value]) => ({ label, value }));
};
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

export function insight(cell: string, cols: string[], rows: string[][]): Insight | null {
  if (!rows.length) return null;
  if (cell === "run_events") {
    const e = col(cols, "event"), h = col(cols, "hop");
    const bars = tally(rows, e);
    const hops = [...new Set(rows.map((r) => r[h]).filter((x) => x !== "" && x !== undefined))];
    return { barsTitle: "Events returned, by name", bars, sentences: [
      `The search returned ${plural(rows.length, "event")}${hops.length ? ` across ${plural(hops.length, "hop")} (${hops.join(", ")})` : ""}.`,
      `The first row is ${rows[0][e]} and the last is ${rows[rows.length - 1][e]}.`] };
  }
  if (cell === "control_decisions") {
    const d = col(cols, "decision"), x = col(cols, "executed"), r0 = col(cols, "reason");
    const bars = tally(rows, d);
    const denied = rows.filter((r) => r[d] === "DENY");
    const executed = rows.filter((r) => String(r[x]).toLowerCase() === "true");
    const out = [`The control recorded ${bars.map((b) => `${b.label} ${b.value}`).join(", ")} in the ${plural(rows.length, "row")} returned.`];
    if (denied.length && executed.some((r) => r[d] === "DENY")) out.push(`${plural(executed.filter((r) => r[d] === "DENY").length, "DENY row")} also show executed = true. A denied call that executed is what the assurance rules call a bypass.`);
    else if (denied.length) out.push("No DENY row shows executed = true.");
    else out.push("No DENY decision is in these rows, so they say nothing about whether this control can stop a call.");
    if (rows[0][r0]) out.push(`The first recorded reason is "${rows[0][r0]}".`);
    return { barsTitle: "Decisions recorded", bars, sentences: out };
  }
  if (cell === "execution_check") {
    const h = col(cols, "hop"), dec = col(cols, "decision"), st = col(cols, "handlers_started"), ex = col(cols, "executed");
    const bars = rows.flatMap((r) => [{ label: `hop ${r[h]}: handlers started`, value: Number(r[st]) || 0 }, { label: `hop ${r[h]}: executed`, value: Number(r[ex]) || 0 }]);
    const out: string[] = [];
    rows.forEach((r) => {
      const denied = /DENY/.test(r[dec]), started = Number(r[st]) || 0;
      if (denied && started > 0) out.push(`Hop ${r[h]}: the control decided ${r[dec]} but ${plural(started, "handler")} started. That is the pattern the rules call a bypass; read the finding for the verdict.`);
      else if (denied) out.push(`Hop ${r[h]}: the control decided ${r[dec]} and no handler started.`);
      else out.push(`Hop ${r[h]}: ${r[dec] ? `the control decided ${r[dec]}; ` : "no decision recorded; "}${plural(started, "handler")} started, ${Number(r[ex]) || 0} executed.`);
    });
    return { barsTitle: "Handlers started and executed, per hop", bars, sentences: out };
  }
  return null;
}
