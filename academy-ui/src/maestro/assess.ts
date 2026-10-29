import type { Assessment, Data, Level, Model, Result, Threat } from "./types.ts";

// A self-check of the structure and honesty of a MAESTRO model against the worked example. It cannot judge whether your reasoning is right. Pure: no DOM, no storage.
const ORDER: Level[] = ["LOW", "MEDIUM", "HIGH"];
export const levelOf = (d: Data, impact: unknown, likelihood: unknown): Level | null =>
  d.risk.impact.some((x) => x.id === impact) && d.risk.likelihood.some((x) => x.id === likelihood) ? d.risk.matrix[impact as string][likelihood as string] : null;
const rank = (l: Level | null) => (l ? ORDER.indexOf(l) : -1);
const long = (s: string, n: number) => typeof s === "string" && s.trim().length >= n;
const pairKey = (a: number, b: number) => [a, b].sort().join("-");

export function assess(m: Model, d: Data): Assessment {
  const T = d.rubric.thresholds, els = d.acmebank.elements, out: Result[] = [];
  const res = (id: string, state: Result["state"], detail: string) => out.push({ id, title: d.rubric.criteria.find((c) => c.id === id)?.title ?? id, state, detail });
  const grade = (ok: boolean, part: boolean): Result["state"] => (ok ? "MET" : part ? "PARTIAL" : "NOT MET");

  // R1 decomposition
  const right = els.filter((e) => [e.layer, ...e.also].includes(m.placements[e.id] ?? 0)).length, ratio = els.length ? right / els.length : 0;
  const covered = new Set(els.map((e) => m.placements[e.id] ?? 0).filter((n) => n >= 1 && n <= 7));
  res("R1", grade(ratio >= T.placement_ratio && covered.size === 7, ratio >= T.placement_ratio || covered.size === 7), `${right} of ${els.length} elements on the reference layer; ${covered.size} of 7 layers have an element.`);

  // R2 boundaries
  const bs = d.acmebank.boundaries, found = bs.filter((b) => m.boundaries[b.id]?.found);
  const okLayers = found.filter((b) => pairKey(...m.boundaries[b.id].layers) === pairKey(...b.layers)).length;
  res("R2", grade(found.length >= T.boundary_found && okLayers >= Math.ceil(found.length * T.boundary_layer_ratio), found.length >= 4), `${found.length} of ${bs.length} boundaries identified; ${okLayers} with the right two layers.`);

  // R3 layer threats
  const layers = d.framework.layers, label = (t: Threat) => {
    const l = layers.find((x) => x.n === t.layer); return !!l && !!t.label.trim() && (l.official_threats.includes(t.label) || (t.custom && long(t.description, 20)));
  };
  const withThreat = new Set(m.threats.map((t) => t.layer)), badLabels = m.threats.filter((t) => !label(t));
  res("R3", grade(withThreat.size === 7 && badLabels.length === 0, withThreat.size >= 5), `${withThreat.size} of 7 layers have a threat.${badLabels.length ? ` ${badLabels.length} threat(s) have neither an official label for their layer nor a custom reason (${badLabels.map((t) => t.id).join(", ")}).` : ""}`);

  // R4 cross-layer paths
  const byId = new Map(m.threats.map((t) => [t.id, t]));
  const validPath = (p: Model["paths"][number]) => p.steps.length >= T.path_steps && new Set(p.steps.map((s) => s.layer)).size >= T.path_layers && p.steps.every((s) => byId.get(s.threat)?.layer === s.layer);
  const vp = m.paths.filter(validPath).length;
  res("R4", grade(vp >= T.paths, vp >= 1), `${vp} valid path(s) of ${m.paths.length}; a valid path has at least ${T.path_steps} steps over at least ${T.path_layers} layers, and every step names a register threat on that layer.`);

  // R5 risk, mitigation, residual
  const complete = (t: Threat) => long(t.inherent.rationale, 10) && long(t.residual.rationale, 10) && long(t.mitigation, 10) && t.controls.length >= 1 &&
    levelOf(d, t.inherent.impact, t.inherent.likelihood) !== null && levelOf(d, t.residual.impact, t.residual.likelihood) !== null &&
    rank(levelOf(d, t.residual.impact, t.residual.likelihood)) <= rank(levelOf(d, t.inherent.impact, t.inherent.likelihood));
  const done = m.threats.filter(complete).length;
  res("R5", grade(m.threats.length > 0 && done === m.threats.length, m.threats.length > 0 && done >= Math.ceil(m.threats.length * 0.7)), `${done} of ${m.threats.length} threats have both judgments with reasons, a mitigation, a named control (or NONE) and a residual not above the inherent level.`);

  // R6 evidence honesty
  const honest = (t: Threat) => !!t.evidence && (t.evidence !== "DEMONSTRATED" || t.scenarios.length >= 1) &&
    !(t.evidence === "ASSUMED" && rank(levelOf(d, t.residual.impact, t.residual.likelihood)) < rank(levelOf(d, t.inherent.impact, t.inherent.likelihood)) && t.controls.every((c) => c === "NONE"));
  const hon = m.threats.filter(honest).length;
  res("R6", grade(m.threats.length > 0 && hon === m.threats.length, m.threats.length > 0 && hon >= Math.ceil(m.threats.length * 0.7)), `${hon} of ${m.threats.length} threats state their evidence status consistently.`);

  // R7 scenario families
  const fam = new Set(m.threats.flatMap((t) => t.scenarios.map((s) => d.acmebank.scenarios.find((x) => x.lab_id === s)?.family)).filter(Boolean) as string[]);
  const wanted = d.families.filter((f) => fam.has(f));
  res("R7", grade(wanted.length >= T.scenario_families, wanted.length >= 2), `Linked scenario families: ${wanted.join(", ") || "none"} (${wanted.length} of ${d.families.length}; ${T.scenario_families} needed).`);

  // R8 prioritization
  const lv = m.threats.filter((t) => levelOf(d, t.inherent.impact, t.inherent.likelihood) && levelOf(d, t.residual.impact, t.residual.likelihood)).length;
  const hi = m.threats.some((t) => levelOf(d, t.inherent.impact, t.inherent.likelihood) === "HIGH");
  res("R8", grade(m.threats.length > 0 && lv / m.threats.length >= T.priority_ratio && hi, lv > 0), `${lv} of ${m.threats.length} threats can be ranked; ${hi ? "at least one is HIGH inherent" : "none is HIGH inherent"}.`);

  const state = (id: string) => out.find((r) => r.id === id)?.state;
  return { results: out, applied: ["R1", "R2", "R3", "R4", "R5", "R7"].every((id) => state(id) === "MET") };
}

/** Rank for the prioritization table: inherent level, then residual level, then the threat id. */
export function prioritize(m: Model, d: Data): Threat[] {
  const k = (t: Threat) => [-rank(levelOf(d, t.inherent.impact, t.inherent.likelihood)), -rank(levelOf(d, t.residual.impact, t.residual.likelihood))];
  return [...m.threats].sort((a, b) => { const x = k(a), y = k(b); return x[0] - y[0] || x[1] - y[1] || a.id.localeCompare(b.id); });
}

/** The worked example, as a model the learner can edit. Judgments in it are the lab author's, labelled as such in the report. */
export function exampleModel(d: Data): Model {
  return {
    scope: d.example.scope,
    placements: Object.fromEntries(d.acmebank.elements.map((e) => [e.id, e.layer])),
    boundaries: Object.fromEntries(d.acmebank.boundaries.map((b) => [b.id, { found: true, layers: [...b.layers] as [number, number] }])),
    threats: d.example.register.map((t) => JSON.parse(JSON.stringify(t))),
    paths: d.example.paths.map((p) => ({ id: p.id, name: p.name, narrative: p.narrative, steps: p.steps.map((s) => ({ ...s })) })),
  };
}
export const emptyModel = (): Model => ({ scope: "", placements: {}, boundaries: {}, threats: [], paths: [] });
