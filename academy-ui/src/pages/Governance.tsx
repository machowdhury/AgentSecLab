import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Badge, Button, LinkButton } from "../ui";
import { Callout } from "../mission/parts";
import { EVALS_PATH, GOV_PATH, Link, RISK_PATH, type GovView } from "../router";
import { LimitationsList } from "../assurance/parts";

interface Rel { framework: string; id: string; name: string; verification_status: string; relationship: string; rationale: string; limits: string; version_or_date: string; source_url: string; threats: string[] }
interface Gov {
  distinctions: { name: string; meaning: string; where: string | null }[];
  frameworks: { name: string; status: string; items: { id: string; name: string; status: string; source_url: string; version_or_date: string; limits: string }[]; mapped_relationships: number; reason?: string }[];
  relationships: Rel[];
  threats: { id: string; title: string; question: string; mapped: boolean; relationships: { framework: string; id: string; name: string; relationship: string; rationale: string; via_experiment: string }[]; controls: { id: string; class: string }[];
             findings: { id: string; title: string; experiment: string }[]; experiments: string[]; evidence_classes: string[]; gaps: string[] }[];
  controls: { id: string; class: string; placement: string; code_reference: string; threats: string[]; recorded_decisions: { experiment: string; role: string; decision: string; reason: string }[]; findings: string[]; evidence_state: string;
              owner: string; review: string; attestation: string; independent_verification: string; compliance: string }[];
  gaps: { unmapped_threats: string[]; controls_without_recorded_evidence: string[]; threats_without_evaluation_evidence: string[]; frameworks_not_mapped: string[]; statement: string };
  sources: { file: string; sha256: string; locator: string }[];
}
const FILES = import.meta.glob<{ default: Gov }>("../content/governance/index.json");
const cache: { p?: Promise<Gov> } = {};
const load = () => (cache.p ??= FILES["../content/governance/index.json"]().then((m) => m.default));
const TABS: [GovView, string, string][] = [["overview", "Overview", GOV_PATH], ["frameworks", "Frameworks", `${GOV_PATH}/frameworks`], ["threats", "Threats and controls", `${GOV_PATH}/threats`], ["export", "Export", `${GOV_PATH}/export`]];
const cell = (v: unknown) => (v === null || v === undefined ? "—" : String(v));
function Table({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return <div className="table-wrap" tabIndex={0} role="region" aria-label={`${caption}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{caption}</caption>
    <thead><tr>{head.map((h) => <th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => j === 0 ? <th scope="row" key={j}>{c}</th> : <td data-label={head[j]} key={j}>{c}</td>)}</tr>)}</tbody></table></div>;
}
const Section = ({ id, title, children }: { id: string; title: string; children: ReactNode }) => <section className="wk-sec" aria-labelledby={id}><h2 id={id}>{title}</h2>{children}</section>;

/** The report is built here from the loaded file alone: same input, same bytes, and no counts of its own beyond the lists it prints. */
export function govJson(g: Gov) {
  return { schema: "agentsec.governance_export.v1", statement: "Framework relationships are educational links. This export asserts no compliance, no control effectiveness, no attestation and no approval.",
    relationships: g.relationships, threats: g.threats.map((t) => ({ id: t.id, title: t.title, mapped: t.mapped, controls: t.controls, findings: t.findings, experiments: t.experiments, gaps: t.gaps })),
    controls: g.controls.map((c) => ({ id: c.id, class: c.class, evidence_state: c.evidence_state, recorded_decisions: c.recorded_decisions.length, owner: c.owner, review: c.review, attestation: c.attestation, independent_verification: c.independent_verification, compliance: c.compliance })),
    gaps: g.gaps, frameworks_not_verified: g.frameworks.filter((f) => f.status !== "REFERENCED").map((f) => ({ name: f.name, reason: f.reason })), sources: g.sources };
}
export function govMarkdown(g: Gov): string {
  const j = govJson(g), L: string[] = ["# Governance and Compliance Export", "", j.statement, "", "## Framework relationships", ""];
  g.relationships.forEach((r) => L.push(`- ${r.framework} ${r.id} (${r.name}) — ${r.relationship}, reference ${r.verification_status}; threats: ${r.threats.join(", ")}. ${r.rationale}`));
  L.push("", "## Threats", ""); g.threats.forEach((t) => L.push(`- ${t.id} ${t.title}: ${t.mapped ? "framework relationship recorded" : "NO framework relationship recorded"}; controls ${t.controls.map((c) => c.id).join(", ")}; findings ${t.findings.length}; experiments ${t.experiments.length}`));
  L.push("", "## Controls", ""); g.controls.forEach((c) => L.push(`- ${c.id}: ${c.evidence_state === "NO_RECORDED_EVIDENCE" ? "no recorded decision" : `${c.recorded_decisions.length} recorded decision(s)`}; owner ${c.owner}; review ${c.review}; attestation ${c.attestation}; independent verification ${c.independent_verification}; compliance ${c.compliance}`));
  L.push("", "## Gaps", "", `- Threats with no framework relationship: ${g.gaps.unmapped_threats.join(", ")}`, `- Controls with no recorded decision: ${g.gaps.controls_without_recorded_evidence.join(", ")}`, `- Threats with no evaluation evidence: ${g.gaps.threats_without_evaluation_evidence.join(", ")}`, `- Frameworks with no mapping: ${g.gaps.frameworks_not_mapped.join(", ")}`, `- ${g.gaps.statement}`, "", "## Sources", "");
  g.sources.forEach((s) => L.push(`- \`${s.file}\` (${s.locator}) SHA-256 \`${s.sha256}\``));
  return L.join("\n") + "\n";
}

export default function Governance({ view }: { view: GovView }) {
  const [g, setG] = useState<Gov | null>(null), [err, setErr] = useState(false);
  useEffect(() => { let live = true; load().then((x) => live && setG(x), () => live && setErr(true)); return () => { live = false; }; }, []);
  const titles: Record<GovView, string> = { overview: "Governance and Compliance Center", frameworks: "Framework references", threats: "Threats, controls and evidence", export: "Export" };
  return <div className="page wk ev gv">
    <header className="page-header"><div><div className="eyebrow">GOVERNANCE · FRAMEWORK RELATIONSHIPS · NOT A COMPLIANCE ASSESSMENT</div><h1>{titles[view]}</h1>
      <p>How threats, controls, evaluation findings and risks relate to the frameworks the repository has verified. A relationship is an educational link, never a compliance result.</p></div></header>
    <nav aria-label="Governance Center" className="ev-tabs"><ul>{TABS.map(([v, l, to]) => <li key={v}><Link to={to} aria-current={v === view ? "page" : undefined} className={v === view ? "is-current" : ""}>{l}</Link></li>)}</ul></nav>
    {err && <div className="m-sec" role="alert"><h2>The governance data could not be loaded</h2><p>The file did not load. Nothing was changed.</p><Button onClick={() => window.location.reload()}>Reload the page</Button></div>}
    {!g && !err && <div className="m-sec" role="status"><p className="m-muted">Loading the governance data…</p></div>}
    {g && view === "overview" && <Overview g={g} />}{g && view === "frameworks" && <Frameworks g={g} />}{g && view === "threats" && <Threats g={g} />}{g && view === "export" && <Export g={g} />}
  </div>;
}

function Overview({ g }: { g: Gov }) {
  const nT = g.threats.length, nC = g.controls.length, mapped = g.threats.filter((t) => t.mapped).length;
  return <>
    <Callout kind="warn"><strong>This is not a compliance assessment.</strong> No percentage, rating, certification or approval is shown, because none exists. Where information is missing it says so.</Callout>
    <Section id="g-dist" title="Eight things that are not the same"><dl className="wk-legend">{g.distinctions.map((d) => <div key={d.name}><dt>{d.name}</dt><dd>{d.meaning}{d.where === null && <small> Not held here.</small>}</dd></div>)}</dl></Section>
    <Section id="g-counts" title="What the data holds, with denominators">
      <div className="wk-grid">{[[`${mapped} of ${nT}`, "Threats with a recorded framework relationship", "From the framework reference file, through the experiments that test each threat."], [`${g.controls.filter((c) => c.evidence_state === "RECORDED_DECISIONS_EXIST").length} of ${nC}`, "Controls with a recorded decision in a committed run", "A decision recorded once is not an assessment of the control."],
        [`0 of ${nC}`, "Controls with an owner, a review or an attestation", g.gaps.statement], [`${g.threats.filter((t) => t.experiments.length).length} of ${nT}`, "Threats with linked evaluation evidence", "Linked in the EVAL Center."]].map(([n, l, x]) =>
        <article className="wk-card" key={l}><p className="ev-figure"><strong>{n}</strong></p><h3>{l}</h3><p className="m-muted">{x}</p></article>)}</div></Section>
    <Section id="g-gaps" title="Gaps and missing evidence"><ul className="m-rules">
      <li><strong>{g.gaps.unmapped_threats.length} threats</strong> have no framework relationship recorded: {g.gaps.unmapped_threats.join(", ")}.</li>
      <li><strong>{g.gaps.controls_without_recorded_evidence.length} controls</strong> have no recorded decision: {g.gaps.controls_without_recorded_evidence.join(", ")}.</li>
      <li><strong>{g.gaps.threats_without_evaluation_evidence.length} threats</strong> have no linked evaluation evidence: {g.gaps.threats_without_evaluation_evidence.join(", ")}.</li>
      <li><strong>{g.gaps.frameworks_not_mapped.length} frameworks</strong> have no mapping: {g.gaps.frameworks_not_mapped.join(", ")}.</li></ul></Section>
    <Section id="g-links" title="Related views"><p><Link to={`${EVALS_PATH}/findings`}>Evaluation findings</Link> · <Link to={RISK_PATH}>Risk Center</Link> (your local assessments live there) · <Link to={`${GOV_PATH}/export`}>Export this view</Link></p></Section>
  </>;
}

function Frameworks({ g }: { g: Gov }) {
  const [sel, setSel] = useState(g.frameworks[0].name);
  const f = g.frameworks.find((x) => x.name === sel)!, rels = g.relationships.filter((r) => r.framework === sel);
  return <div className="ev-split"><aside aria-label="Frameworks"><ul className="ev-list">{g.frameworks.map((x) => <li key={x.name}><a href="#fw" aria-current={x.name === sel ? "true" : undefined} className={x.name === sel ? "is-current" : ""} onClick={(e) => { e.preventDefault(); setSel(x.name); }}>{x.name}<small>{x.status === "REFERENCED" ? `${x.items.length} reference(s), ${x.mapped_relationships} relationship(s)` : "not verified here"}</small></a></li>)}</ul></aside>
    <div className="ev-detail" id="fw"><h2>{f.name}</h2>
      {f.status !== "REFERENCED" ? <Callout kind="warn"><strong>No identifier is verified in this repository.</strong> {f.reason}</Callout> : <>
        <p className="m-muted">{f.items.length} reference(s) verified in the repository; {f.mapped_relationships} have a recorded relationship to a threat.</p>
        <Table caption={`${f.name} references`} head={["Identifier", "Title", "Reference status", "Relationship to a threat", "Source and limits"]}
          rows={f.items.map((i) => { const r = rels.find((x) => x.id === i.id); return [<code key="c">{i.id}</code>, i.name, i.status.replace(/_/g, " "), r ? `${r.relationship}: ${r.threats.join(", ")}` : "None recorded", <details key="d" className="m-details"><summary>Source</summary><p>{i.version_or_date}. <a href={i.source_url} rel="noopener">source</a></p><p>{i.limits || "No limit recorded beyond: a reference is not a certified mapping."}</p></details>]; })} /></>}
      <LimitationsList items={["A relationship is an educational link from the framework reference file.", "A reference being listed does not mean any control meets it."]} title="What this does not show" level={3} /></div></div>;
}

function Threats({ g }: { g: Gov }) {
  const [f, setF] = useState<"all" | "mapped" | "unmapped">("all");
  const rows = useMemo(() => g.threats.filter((t) => f === "all" || (f === "mapped") === t.mapped), [g, f]);
  return <>
    <fieldset className="ev-filter"><legend>Show threats</legend>{([["all", "All"], ["mapped", "With a framework relationship"], ["unmapped", "With none recorded"]] as const).map(([v, l]) => <label key={v}><input type="radio" name="tf" checked={f === v} onChange={() => setF(v)} /> {l}</label>)}</fieldset>
    <p role="status" className="m-muted">Showing {rows.length} of {g.threats.length} threats.</p>
    {rows.map((t) => <article className="wk-card" key={t.id} aria-labelledby={`t-${t.id}`}>
      <header><h2 id={`t-${t.id}`}>{t.id}: {t.title}</h2><Badge tone={t.mapped ? "observed" : "muted"}>{t.mapped ? "FRAMEWORK RELATIONSHIP RECORDED" : "NO FRAMEWORK RELATIONSHIP RECORDED"}</Badge></header>
      <p>{t.question}</p>
      <dl className="wk-kv"><div><dt>Framework relationships</dt><dd>{t.relationships.length ? <ul>{t.relationships.map((r) => <li key={r.id}>{r.framework} <code>{r.id}</code> {r.name}: <strong>{r.relationship}</strong> <small>{r.rationale}</small></li>)}</ul> : "None recorded"}</dd></div>
        <div><dt>Controls named by the catalog</dt><dd><ul>{t.controls.map((c) => { const k = g.controls.find((x) => x.id === c.id)!; return <li key={c.id}><code>{c.id}</code> ({c.class}): {k.evidence_state === "NO_RECORDED_EVIDENCE" ? "no recorded decision" : `${k.recorded_decisions.length} recorded decision(s)`}; owner {k.owner}; attestation {k.attestation}</li>; })}</ul></dd></div>
        <div><dt>Evaluation findings</dt><dd>{t.findings.length ? <ul>{t.findings.map((x) => <li key={x.id}><Link to={`${EVALS_PATH}/findings`}>{x.title}</Link></li>)}</ul> : "None linked"}</dd></div>
        <div><dt>Risk</dt><dd><Link to={`${RISK_PATH}/${t.id}`}>Open {t.id} in the Risk Center</Link><small>Your impact, likelihood and treatment are entered there, in your local draft.</small></dd></div></dl>
      <details className="m-details"><summary>Gaps for this threat</summary><ul className="m-rules">{t.gaps.map((x) => <li key={x}>{x}</li>)}</ul></details></article>)}
    <h2>All controls</h2>
    <Table caption="Control register: evidence and what has not been recorded" head={["Control", "Class", "Threats", "Recorded decisions", "Owner", "Review", "Attestation", "Independent verification", "Compliance"]}
      rows={g.controls.map((c) => [<code key="c">{c.id}</code>, c.class, c.threats.join(", "), String(c.recorded_decisions.length), c.owner, c.review, c.attestation, c.independent_verification, c.compliance])} /></>;
}

function Export({ g }: { g: Gov }) {
  const [fmt, setFmt] = useState<"md" | "json">("md"), [done, setDone] = useState("");
  const text = fmt === "md" ? govMarkdown(g) : JSON.stringify(govJson(g), null, 2) + "\n";
  const download = () => { const name = `governance-export.${fmt}`, a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: fmt === "md" ? "text/markdown" : "application/json" })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setDone(`Downloaded ${name} (${text.length} characters).`); };
  return <><h2>Build and download</h2><p className="m-muted">Built in your browser from the governance data file. The same data always produces the same file. It states no compliance, effectiveness, attestation or approval.</p>
    <fieldset className="ev-filter"><legend>Format</legend><label><input type="radio" name="gf" checked={fmt === "md"} onChange={() => { setFmt("md"); setDone(""); }} /> Markdown (readable)</label><label><input type="radio" name="gf" checked={fmt === "json"} onChange={() => { setFmt("json"); setDone(""); }} /> JSON (structured)</label></fieldset>
    <div className="m-actions"><Button onClick={download} icon="arrow">Download the export</Button></div><p role="status" className="m-muted">{done}</p>
    <details className="m-details" open><summary>Preview ({text.length} characters)</summary><pre className="ev-preview" tabIndex={0} aria-label="Export preview">{text}</pre></details></>;
}
