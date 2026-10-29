import { assess, levelOf, prioritize } from "./assess.ts";
import type { Data, Model } from "./types.ts";

// The learner's report. Plain text built from the learner's own entries: no HTML is ever produced, and table cells and headings are escaped so an entry cannot
// break the document's structure. Pure: the caller supplies the clock and the hash function.
export const SCHEMA = "agentsec.maestro_threat_model.v1", STATUS = "LOCAL_DRAFT_NOT_APPROVED";
const clean = (s: unknown, n = 2000) => String(s ?? "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").slice(0, n);
export const cell = (s: unknown) => clean(s).replace(/\r?\n+/g, " ").replace(/\|/g, "\\|").replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;")).trim() || "—";
const para = (s: unknown) => clean(s).replace(/^[ \t]*(#+|`{3,}|~{3,}|-{3,}|={3,})/gm, (m) => "\\" + m).replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;")).trim() || "—";

export function exportDoc(m: Model, d: Data, hash: (t: string) => string): Record<string, unknown> {
  const body = JSON.stringify(m);
  return { schema: SCHEMA, status: STATUS, framework: "MAESTRO (Cloud Security Alliance, Ken Huang, 2025-02-06)", scenario: d.acmebank.scenario,
    integrity: { algorithm: "sha256", model_sha256: hash(body), note: "A checksum of the model below serialised compactly (JSON.stringify, no spaces). It detects accidental change. It is not a signature and proves nothing about who wrote it." }, model: m };
}

export function architectureBrief(m: Model, d: Data): string {
  const by = (n: number) => d.acmebank.elements.filter((e) => (m.placements[e.id] ?? 0) === n).map((e) => e.name);
  return d.framework.layers.map((l) => `Layer ${l.n}, ${l.name}: ${by(l.n).join("; ") || "(nothing placed)"}.`).join("\n") +
    `\nAgents and tools interact as follows: ${d.acmebank.interactions.map((i) => `${i.from} to ${i.to} (${i.data})`).join("; ")}.`;
}

export function markdown(m: Model, d: Data, hash: (t: string) => string, now: string): string {
  const A = assess(m, d), L = (t: { inherent: { impact: unknown; likelihood: unknown } }) => levelOf(d, t.inherent.impact, t.inherent.likelihood) ?? "NOT ASSESSED";
  const R = (t: { residual: { impact: unknown; likelihood: unknown } }) => levelOf(d, t.residual.impact, t.residual.likelihood) ?? "NOT ASSESSED";
  const layerName = (n: number) => d.framework.layers.find((l) => l.n === n)?.name ?? String(n);
  const out: string[] = [];
  out.push(`# MAESTRO threat model: ${cell(d.acmebank.scenario)}`, "",
    `**Status: ${STATUS}.** A learner's draft about a lab system with synthetic data. It is not an assessment of any real system, not compliance, not approved, and not a certification. Generated ${cell(now)}.`, "",
    `Framework: ${d.framework.name} (${d.framework.expansion}), ${d.framework.author}, Cloud Security Alliance, ${d.framework.published}. Sources: ${d.framework.sources.map((s) => `${cell(s.title)} <${s.url}>`).join("; ")}.`, "",
    "## 1. Scope", "", para(m.scope), "", "## 2. Decomposition by layer", "",
    "| Layer | Element | Kind | Evidence in the repository |", "| --- | --- | --- | --- |");
  for (const l of d.framework.layers) {
    const els = d.acmebank.elements.filter((e) => (m.placements[e.id] ?? 0) === l.n);
    if (!els.length) out.push(`| ${l.n}. ${cell(l.name)} | (nothing placed) | | |`);
    for (const e of els) out.push(`| ${l.n}. ${cell(l.name)} | ${cell(e.name)} | ${cell(e.kind)} | ${cell(e.evidence.join(", "))} |`);
  }
  out.push("", "## 3. Trust boundaries", "", "| Boundary | Between layers | What changes |", "| --- | --- | --- |");
  for (const b of d.acmebank.boundaries.filter((x) => m.boundaries[x.id]?.found)) out.push(`| ${cell(b.id)} ${cell(b.name)} | ${m.boundaries[b.id].layers.map(layerName).map(cell).join(" and ")} | ${cell(b.note)} |`);
  out.push("", "## 4. Threat register, in priority order", "", "| Rank | ID | Layer | Threat | Kind | Evidence | Inherent | Controls | Mitigation | Residual | Scenarios |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  prioritize(m, d).forEach((t, i) => out.push(`| ${i + 1} | ${cell(t.id)} | ${cell(t.layer)}. ${cell(layerName(t.layer))} | ${cell(t.label)}${t.custom ? " (custom)" : ""}: ${cell(t.description)} | ${cell(t.kind)} | ${cell(t.evidence || "NOT STATED")} | ${L(t)} | ${cell(t.controls.join(", "))} | ${cell(t.mitigation)} | ${R(t)} | ${cell(t.scenarios.join(", "))} |`));
  out.push("", "### Reasons for each judgment", "");
  for (const t of m.threats) out.push(`- **${cell(t.id)}** inherent (${cell(t.inherent.impact)} impact, ${cell(t.inherent.likelihood)} likelihood): ${cell(t.inherent.rationale)} Residual (${cell(t.residual.impact)} impact, ${cell(t.residual.likelihood)} likelihood): ${cell(t.residual.rationale)}`);
  out.push("", "## 5. Cross-layer attack paths", "");
  if (!m.paths.length) out.push("(none recorded)");
  for (const p of m.paths) {
    out.push(`### ${cell(p.id)} ${cell(p.name)}`, "", para(p.narrative), "");
    p.steps.forEach((s, i) => out.push(`${i + 1}. Layer ${cell(s.layer)} (${cell(layerName(s.layer))}), ${cell(s.threat)}: ${cell(s.note)}`));
    out.push("");
  }
  out.push("## 6. Residual risk summary", "");
  const rest = prioritize(m, d).filter((t) => R(t) !== "LOW" && R(t) !== "NOT ASSESSED");
  out.push(rest.length ? rest.map((t) => `- ${cell(t.id)} ${cell(t.label)}: residual ${R(t)}. ${cell(t.residual.rationale)}`).join("\n") : "No threat is left above LOW residual in this draft, or none has been assessed.");
  out.push("", "## 7. Self-check against the MAESTRO method", "", "| Criterion | Result | Detail |", "| --- | --- | --- |", ...A.results.map((r) => `| ${cell(r.id)} ${cell(r.title)} | ${r.state} | ${cell(r.detail)} |`), "",
    `Overall: ${A.applied ? "the structure MAESTRO asks for is present" : "the structure MAESTRO asks for is not complete yet"}. This is a self-check against a worked example. It cannot judge whether your reasoning is right.`, "",
    "## 8. Compare with the official MAESTRO Threat Analyzer", "", `${cell(d.analyzer.status_here)}`, "", "Paste this architecture description into the Analyzer yourself, then compare layer by layer:", "", "```text", architectureBrief(m, d).replace(/`/g, "'"), "```", "",
    ...d.analyzer.compare.map((c, i) => `${i + 1}. ${cell(c)}`), "",
    "## 9. Limits", "", "- Risk levels come from the AgentSecLab Risk Center's qualitative matrix, from judgments you entered. The CSA article asks for a risk matrix but defines none.",
    "- DEMONSTRATED means a lab in this repository shows it for its own fixtures. It does not mean the threat is handled in general. DOCUMENTED and ASSUMED are weaker.",
    "- Authentication, human approval and cryptographic delegation are NOT MODELED in AcmeBank. Nothing here was run against a real system.", "",
    `Integrity: sha256 ${hash(JSON.stringify(m))} (a checksum of the model, not a signature).`, "");
  return out.join("\n");
}
