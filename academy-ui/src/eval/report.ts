import type { EvalIndex, Experiment, Finding } from "./types";

// The report is built here from the loaded evidence files and nothing else: no timestamp, no counts of its own, no scores. Observations and interpretations are kept in separate sections.
const cell = (v: unknown) => v === null || v === undefined ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
export const NOT_ASSESSED = "NOT ASSESSED";

export function reportJson(index: EvalIndex, exps: Experiment[]) {
  const ids = new Set(exps.map((e) => e.id));
  const findings = index.findings.filter((f) => ids.has(f.experiment));
  const files = new Map<string, string>();
  exps.forEach((e) => [e.documentation, ...e.cases.flatMap((c) => c.sources)].forEach((s) => files.set(s.file, s.sha256)));
  return {
    schema: "agentsec.eval_report.v1",
    generated_from: "committed evidence only; nothing was run to produce this report",
    scope: exps.map((e) => ({ experiment: e.id, title: e.title, evidence_class: e.evidence_class, status: e.status, test_cases: e.cases.length })),
    observations: exps.flatMap((e) => e.cases.map((c) => ({ experiment: e.id, case: c.id, role: c.role, evidence_class: c.evidence_class, statement: c.statement, conditions: c.conditions, facts: c.facts, sources: c.sources, splunk_copy: c.splunk_copy, verification: c.verification, limitations: c.limitations }))),
    interpretations: {
      label: "INTERPRETATION: statements about what the observations mean, each with the rule or documented line it rests on",
      comparisons: exps.filter((e) => e.comparison).map((e) => ({ experiment: e.id, kind: e.comparison!.kind, reading: e.comparison!.reading ?? e.comparison!.method, controlled_pair: e.comparison!.controlled_pair ?? null, limits: e.comparison!.limits })),
      no_comparison: exps.filter((e) => !e.comparison).map((e) => ({ experiment: e.id, reason: e.comparison_unavailable })),
      findings: findings.map((f) => ({ id: f.id, rule: f.rule, experiment: f.experiment, observed: f.observed, expected: f.expected, matches_documented: f.matches_documented, match_basis: f.match_basis, evidence: f.evidence, verification: f.verification, limitations: f.limitations, threat: f.threat })),
    },
    not_assessed: { severity: NOT_ASSESSED, likelihood: NOT_ASSESSED, impact: NOT_ASSESSED, owner: "NOT ASSIGNED", remediation_status: "NOT ASSIGNED", findings: findings.length },
    provenance: [...files].map(([file, sha256]) => ({ file, sha256 })),
    limitations: [...new Set(["No test case has a host-verifier receipt, so every observation is NOT_VERIFIED.", ...exps.flatMap((e) => [...e.limitations, ...e.cases.flatMap((c) => c.limitations)])])],
  };
}

export function reportMarkdown(index: EvalIndex, exps: Experiment[]): string {
  const j = reportJson(index, exps), L: string[] = [];
  L.push("# AI Security Evaluation Report", "", `${j.generated_from}.`, "", "## 1. Scope", "");
  j.scope.forEach((s) => L.push(`- ${s.title} (\`${s.experiment}\`): ${s.evidence_class}, ${s.status}, ${s.test_cases} test case(s), NOT_VERIFIED`));
  L.push("", "## 2. Observations (what the sources recorded)", "");
  exps.forEach((e) => {
    L.push(`### ${e.title}`, "");
    e.cases.forEach((c) => {
      L.push(`**${c.title}** (${c.evidence_class}, ${c.verification.status})`, "", c.statement, "");
      Object.entries(c.conditions).forEach(([k, v]) => L.push(`- ${k.replace(/_/g, " ")}: ${cell(v)}`));
      c.sources.forEach((s) => L.push(`- source: \`${s.file}\` (${s.locator}), SHA-256 \`${s.sha256}\``));
      L.push(`- Splunk copy: ${c.splunk_copy.indexed ? (c.splunk_copy.identical ? "indexed and identical to the committed source" : "indexed") : "none"}${c.splunk_copy.note ? `. ${c.splunk_copy.note}` : ""}`, "");
    });
  });
  L.push("## 3. Interpretations (what the observations mean; each states its basis)", "");
  j.interpretations.comparisons.forEach((c) => L.push(`- **${c.experiment}**: ${c.reading} (controlled pair: ${cell(c.controlled_pair)})`));
  j.interpretations.no_comparison.forEach((c) => L.push(`- **${c.experiment}**: no comparison. ${c.reason}`));
  L.push("");
  j.interpretations.findings.forEach((f: Finding | Record<string, any>) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    L.push(`### Finding ${f.id}`, "", `- Rule: ${f.rule}`, `- Observed: ${f.observed}`, `- Expected (documented): ${f.expected.documented ? `"${f.expected.quote.text}" (${f.expected.quote.file})` : "NOT DOCUMENTED"}`,
      `- Matches the documented line: ${f.matches_documented === null ? "not computed" : f.matches_documented ? "yes" : "no"} (${f.match_basis})`, `- Evidence: ${f.evidence.join(", ")}`, `- Related threat: ${f.threat}`, `- Verification: ${f.verification.status}`, "");
  });
  L.push("## 4. Not assessed", "", `- Severity: ${NOT_ASSESSED}`, `- Likelihood: ${NOT_ASSESSED}`, `- Impact: ${NOT_ASSESSED}`, "- Owner: NOT ASSIGNED", "- Remediation status: NOT ASSIGNED", `- Applies to all ${j.not_assessed.findings} finding(s) above.`, "",
    "## 5. Provenance", "");
  j.provenance.forEach((p) => L.push(`- \`${p.file}\` SHA-256 \`${p.sha256}\``));
  L.push("", "## 6. Limitations", "");
  j.limitations.forEach((x) => L.push(`- ${x}`));
  return L.join("\n") + "\n";
}
