import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Badge, Button, LinkButton } from "../ui";
import { Callout } from "../mission/parts";
import { EVALS_PATH, Link, labPath, type EvalView } from "../router";
import { EvidenceBadge, LimitationsList, MappingTable, ProvenanceDisclosure, VerificationBadge } from "../assurance/parts";
import { EventRow } from "../workbench/RecordedWorkbench";
import { loadExperiment, useExperiment, useIndex } from "../eval/data";
import { reportJson, reportMarkdown } from "../eval/report";
import { RULES, STATUS_LABEL, type CapStatus, type Case, type Category, type EvalIndex, type Experiment, type Finding } from "../eval/types";
import type { RecEvent } from "../curriculum";

const TABS: { view: EvalView; label: string; to: string }[] = [
  { view: "overview", label: "Overview", to: EVALS_PATH }, { view: "catalog", label: "Catalog", to: `${EVALS_PATH}/catalog` }, { view: "results", label: "Results", to: `${EVALS_PATH}/results` },
  { view: "compare", label: "Compare", to: `${EVALS_PATH}/compare` }, { view: "findings", label: "Findings", to: `${EVALS_PATH}/findings` }, { view: "export", label: "Export", to: `${EVALS_PATH}/export` },
];
const capTone = (s: CapStatus) => s === "AVAILABLE_WITH_EVIDENCE" ? "allow" : s === "DOCUMENTED_ONLY" ? "observed" : "muted";
const CapBadge = ({ s }: { s: CapStatus }) => <Badge tone={capTone(s)}>{STATUS_LABEL[s]}</Badge>;
const cell = (v: unknown) => v === null || v === undefined ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
const src = (f: string) => f.split("/").pop();

function Loading({ what }: { what: string }) { return <div className="m-sec" role="status"><p className="m-muted">Loading {what}…</p></div>; }
function Failed({ what }: { what: string }) {
  return <div className="m-sec" role="alert"><h2>{what} could not be loaded</h2><p>The evidence file did not load. Nothing was changed. A browser keeps a failed file load until the page is reloaded.</p><div className="m-actions"><Button onClick={() => window.location.reload()}>Reload the page</Button></div></div>;
}
const Section = ({ id, title, children }: { id: string; title: string; children: ReactNode }) => <section className="wk-sec" aria-labelledby={id}><h2 id={id}>{title}</h2>{children}</section>;
function Table({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return <div className="table-wrap" tabIndex={0} role="region" aria-label={`${caption}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{caption}</caption>
    <thead><tr>{head.map((h) => <th scope="col" key={h}>{h}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => j === 0 ? <th scope="row" key={j}>{c}</th> : <td data-label={head[j]} key={j}>{c}</td>)}</tr>)}</tbody></table></div>;
}

/* ------------------------------------------------------------ overview */
function Overview({ ix }: { ix: EvalIndex }) {
  const roles = Object.keys(ix.decisions_by_role), decs = [...new Set(roles.flatMap((r) => Object.keys(ix.decisions_by_role[r])))].sort();
  const g = ix.gaps, matched = ix.findings.filter((f) => f.matches_documented === true).length;
  return <>
    <Callout kind="info"><strong>Scope.</strong> {ix.scope} Every figure below is a count from the included evidence, with its denominator and scope. There are no rates, rankings or scores.</Callout>
    <Section id="ov-metrics" title="What the included evidence shows">
      <div className="wk-grid">{ix.metrics.map((m) => <article className="wk-card" key={m.id}><p className="ev-figure"><strong>{m.numerator}</strong> of {m.denominator}</p><h3>{m.label}</h3><p className="m-muted">Scope: {m.scope}.</p>
        <details className="m-details"><summary>How this is derived</summary><p>{m.derivation}</p></details></article>)}</div></Section>
    <Section id="ov-suites" title="Evaluation suites and their status">
      <Table caption="Every experiment, its evidence class, status and what it produced" head={["Experiment", "Category", "Class", "Status", "Test cases", "Verification", "Findings"]}
        rows={ix.experiments.map((e) => [<Link key="l" to={`${EVALS_PATH}/results/${e.id}`}>{e.title}</Link>, ix.categories.find((c) => c.id === e.category)?.title, <EvidenceBadge key="c" cls={e.evidence_class} />, e.status, String(e.cases),
          `${e.verified} of ${e.cases} verified`, String(e.findings.length)])} /></Section>
    <Section id="ov-systems" title="Evaluated systems and components">
      <Table caption="Components that appear in the included experiments" head={["Kind", "Name", "Appears in"]}
        rows={[...ix.systems.agents.map((a) => ["Agent", a.name, a.experiments.join(", ")]), ...ix.systems.controls.map((c) => ["Control", c.id, c.experiments.join(", ")]),
               ...ix.systems.models.map((m) => ["Model", m.name, m.experiments.join(", ")]), ...ix.systems.scanners.map((s) => ["Scanner", `${s.name} ${s.version}`, s.experiments.join(", ")])]} /></Section>
    <Section id="ov-methods" title="Evaluation methods"><ul className="m-rules">{ix.methods.map((m) => <li key={m.id}><strong>{m.title}</strong>: {m.experiments.length} experiment(s)</li>)}</ul></Section>
    <Section id="ov-decisions" title="Recorded control decisions, by role">
      <p className="m-muted">A count of decision events in the recorded runs. It is not a rate and does not measure control effectiveness.</p>
      <Table caption="Decision events by test-case role" head={["Role", ...decs]} rows={roles.map((r) => [r, ...decs.map((d) => String(ix.decisions_by_role[r][d] ?? 0))])} /></Section>
    <Section id="ov-findings" title="Findings requiring investigation">
      <p>{ix.findings.length} findings were derived by two stated rules. {matched} have a documented expectation that names the observed outcome; {ix.findings.length - matched} do not, and need a person to look. Severity, owner and remediation are NOT ASSESSED or NOT ASSIGNED for all {ix.findings.length}.</p>
      <ul className="m-rules">{ix.findings.filter((f) => f.matches_documented !== true).map((f) => <li key={f.id}><Link to={`${EVALS_PATH}/findings`}>{f.title}</Link> <small>{f.match_basis}</small></li>)}</ul>
      <LinkButton href={`${EVALS_PATH}/findings`} variant="secondary" internal>Open all findings</LinkButton></Section>
    <Section id="ov-gaps" title="Missing evidence and coverage gaps">
      <ul className="m-rules"><li><strong>{g.no_verifier_receipt.cases} test cases</strong> have no host-verifier receipt. {g.no_verifier_receipt.statement}</li>
        <li><strong>{g.not_implemented.length} capabilities</strong> are not implemented: {g.not_implemented.map((x) => x.capability).join("; ")}.</li>
        <li><strong>{g.documented_only.length} capability</strong> is documented only: {g.documented_only.map((x) => x.capability).join("; ")}.</li>
        <li><strong>{g.no_comparison.length} experiments</strong> have no comparison: {g.no_comparison.map((x) => x.experiment).join(", ")}.</li>
        <li><strong>{g.no_framework_relationships.length} experiments</strong> have no framework relationship recorded: {g.no_framework_relationships.join(", ")}.</li>
        <li>Evidence exists for {g.evidence_exists_but_not_included.length} labs that this increment does not include: {g.evidence_exists_but_not_included.join(", ")}.</li></ul></Section>
    <Section id="ov-demo" title="Guided demonstration">
      <p className="m-muted">One evidence-backed evaluation, from test to export, in five steps.</p>
      <ol className="ev-demo">{ix.demo.steps.map((s, i) => <li key={s.title}><span className="wk-n" aria-hidden="true">{i + 1}</span><div><strong>{s.title}</strong><p>{s.text}</p><Link to={`${EVALS_PATH}/${s.to}`}>Go to this step</Link></div></li>)}</ol></Section>
  </>;
}

/* ------------------------------------------------------------ catalog */
function Catalog({ ix }: { ix: EvalIndex }) {
  const [f, setF] = useState<"ALL" | CapStatus>("ALL");
  const shown = ix.categories.map((c) => ({ ...c, capabilities: c.capabilities.filter((x) => f === "ALL" || x.status === f) })).filter((c) => c.capabilities.length > 0);
  const total = ix.categories.reduce((n, c) => n + c.capabilities.length, 0), n = shown.reduce((k, c) => k + c.capabilities.length, 0);
  return <>
    <p className="m-muted">A category appearing in the Academy does not mean a complete evaluation suite exists. Each capability below carries its own status, and a category's status only says whether any experiment with committed evidence exists.</p>
    <fieldset className="ev-filter"><legend>Show capabilities</legend>{(["ALL", "AVAILABLE_WITH_EVIDENCE", "DOCUMENTED_ONLY", "NOT_IMPLEMENTED"] as const).map((s) =>
      <label key={s}><input type="radio" name="cap" checked={f === s} onChange={() => setF(s)} /> {s === "ALL" ? "All" : STATUS_LABEL[s]}</label>)}</fieldset>
    <p role="status" className="m-muted">Showing {n} of {total} capabilities in {shown.length} categories.</p>
    {shown.length === 0 && <p>No capability has this status.</p>}
    {shown.length > 0 && <h2>Categories and capabilities</h2>}
    {shown.map((c: Category) => <article className="wk-card" key={c.id}><header><h3>{c.title}</h3><CapBadge s={c.status} /></header><p>{c.summary}</p><p className="m-muted">{c.status_basis}</p>
      <ul className="ev-caps">{c.capabilities.map((x) => <li key={x.id}><div><CapBadge s={x.status} /> <strong>{x.title}</strong></div>
        {x.experiments && <p>{x.experiments.map((e) => <Link key={e} to={`${EVALS_PATH}/results/${e}`}>{ix.experiments.find((y) => y.id === e)?.title}</Link>).reduce<ReactNode[]>((a, b, i) => (i ? [...a, " · ", b] : [b]), [])}</p>}
        {x.quote && <p className="m-muted"><q>{x.quote.text}</q> <small className="m-src">Source: <code>{src(x.quote.file)}</code></small></p>}{x.note && <p className="m-muted">{x.note}</p>}</li>)}</ul></article>)}
  </>;
}

/* ------------------------------------------------------------ results */
function CaseView({ c }: { c: Case }) {
  const dec = (c.facts.decisions ?? []) as { sequence: number; control: string; decision: string; reason: string; tool: string | null; requested_scope: string | null; requested_resource: string | null }[];
  return <article className="wk-card" aria-label={c.title}>
    <header><h3>{c.title}</h3><div className="wk-badges"><EvidenceBadge cls={c.evidence_class} /><VerificationBadge status={c.verification.status} /></div></header>
    <p>{c.statement}</p>
    <dl className="wk-kv"><div><dt>Test conditions</dt><dd><ul>{Object.entries(c.conditions).map(([k, v]) => <li key={k}>{k.replace(/_/g, " ")}: <code>{cell(v)}</code></li>)}</ul></dd></div>
      <div><dt>Documented expectation</dt><dd>{c.expected.documented ? <><q>{c.expected.quote!.text}</q> <small className="m-src">Source: <code>{src(c.expected.quote!.file)}</code></small></> : "NOT DOCUMENTED for this case"}</dd></div>
      <div><dt>Splunk copy</dt><dd>{c.splunk_copy.indexed ? `${c.splunk_copy.identical ? "Indexed and identical to the committed source" : "Indexed"}${c.splunk_copy.exact_raw_bytes !== undefined ? ` (${c.splunk_copy.exact_raw_bytes} of ${c.splunk_copy.pack_events} events byte for byte)` : ""}.` : "No indexed copy."} {c.splunk_copy.note}</dd></div></dl>
    {dec.length > 0 && <Table caption="Control and policy decisions recorded in this case" head={["Seq", "Control", "Decision", "Reason", "Tool", "Scope", "Resource"]}
      rows={dec.map((d) => [String(d.sequence), d.control, <Badge key="b" tone={d.decision === "ALLOW" ? "allow" : d.decision === "DENY" ? "deny" : "observed"}>{d.decision}</Badge>, d.reason, cell(d.tool), cell(d.requested_scope), cell(d.requested_resource)])} />}
    {c.facts.handler_starts && <p>Handler starts recorded: {(c.facts.handler_starts as { tool: string; executed: unknown }[]).length === 0 ? "none" : (c.facts.handler_starts as { tool: string; executed: unknown }[]).map((s) => `${s.tool} (executed=${String(s.executed)})`).join(", ")}.</p>}
    {c.kind === "evaluation_result" && !c.facts.decisions && <details className="m-details"><summary>Recorded facts</summary><dl className="rec-fields">{Object.entries(c.facts).map(([k, v]) => <div key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{cell(v)}</dd></div>)}</dl></details>}
    {c.timeline.length > 0 && <details className="m-details"><summary>The recorded events ({c.timeline.length}), exactly as committed</summary><ol className="rec-events" aria-label={`Events of ${c.title}`}>{c.timeline.map((e) => <EventRow key={String(e["agentsec.sequence"])} e={e as RecEvent} headingLevel="h4" />)}</ol></details>}
    <ProvenanceDisclosure sources={c.sources} /><LimitationsList items={c.limitations} /></article>;
}

function ExperimentDetail({ id, ix }: { id: string; ix: EvalIndex }) {
  const { data: e, err } = useExperiment(id);
  const [sel, setSel] = useState(0);
  useEffect(() => setSel(0), [id]);
  if (err) return <Failed what="This experiment" />;
  if (!e) return <Loading what="the experiment" />;
  const c = e.cases[Math.min(sel, e.cases.length - 1)], cat = ix.categories.find((x) => x.id === e.category);
  return <div aria-label={e.title} role="region">
    <header className="ev-head"><h2>{e.title}</h2><div className="wk-badges"><EvidenceBadge cls={e.evidence_class} /><Badge tone="muted">{e.status}</Badge><VerificationBadge status="NOT_VERIFIED" /></div></header>
    <p className="m-muted">{cat?.title}. Lab: <Link to={labPath(e.lab_id)}>{e.lab_id}</Link>. <LinkButton href={`${EVALS_PATH}/compare/${e.id}`} variant="ghost" internal>Compare</LinkButton></p>
    <dl className="wk-kv"><div><dt>What was tested</dt><dd>{e.target.description}</dd></div><div><dt>Method</dt><dd>{e.method}</dd></div>
      {e.target.agents.length > 0 && <div><dt>Agents</dt><dd>{e.target.agents.join(", ")}</dd></div>}{e.target.controls.length > 0 && <div><dt>Controls seen</dt><dd>{e.target.controls.join(", ")}</dd></div>}
      <div><dt>Related threat</dt><dd>{e.threat.id} · {e.threat.category}<small>{e.threat.question}</small></dd></div></dl>
    <h3 id="cases-h">Test cases ({e.cases.length})</h3>
    <div role="group" aria-labelledby="cases-h" className="rec-runs">{e.cases.map((x, i) => <button key={x.id} type="button" aria-pressed={i === sel} className={`rec-run ${i === sel ? "is-current" : ""}`} onClick={() => setSel(i)}>{x.role.replace(/_/g, " ")}<small>{x.evidence_class}</small></button>)}</div>
    <CaseView c={c} />
    <h3>Framework relationships</h3>{e.mappings.length > 0 ? <MappingTable items={e.mappings} /> : <p className="m-muted">No framework relationship is recorded for this experiment.</p>}
    <LimitationsList items={e.limitations} title="Limitations of this experiment" />
  </div>;
}

function Results({ ix, id }: { ix: EvalIndex; id: string | null }) {
  const [cat, setCat] = useState("all"), [cls, setCls] = useState("all"), [q, setQ] = useState("");
  const list = ix.experiments.filter((e) => (cat === "all" || e.category === cat) && (cls === "all" || e.evidence_class === cls) && (!q || (e.title + e.lab_id + e.id).toLowerCase().includes(q.toLowerCase())));
  return <div className="ev-split">
    <aside aria-label="Experiments"><div className="ev-filters">
      <label>Category<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="all">All categories</option>{ix.categories.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}</select></label>
      <label>Evidence class<select value={cls} onChange={(e) => setCls(e.target.value)}><option value="all">All classes</option><option value="RECORDED">RECORDED</option><option value="SIMULATED">SIMULATED</option></select></label>
      <label>Search<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title or lab" /></label></div>
      <p role="status" className="m-muted">Showing {list.length} of {ix.experiments.length} experiments.</p>
      {list.length === 0 ? <div className="m-sec"><p>No experiment matches these filters.</p><Button variant="secondary" onClick={() => { setCat("all"); setCls("all"); setQ(""); }}>Clear the filters</Button></div> :
        <ul className="ev-list">{list.map((e) => <li key={e.id}><Link to={`${EVALS_PATH}/results/${e.id}`} aria-current={e.id === id ? "page" : undefined} className={e.id === id ? "is-current" : ""}>{e.title}<small>{e.evidence_class} · {e.cases} case(s) · {e.findings.length} finding(s)</small></Link></li>)}</ul>}</aside>
    <div className="ev-detail">{id ? (ix.experiments.some((e) => e.id === id) ? <ExperimentDetail id={id} ix={ix} /> : <div className="m-sec" role="alert"><p>There is no experiment called {id}.</p></div>) : <div className="m-sec"><h2>Choose an experiment</h2><p>Select one on the left to see what was tested, each test case, the recorded events, and where they come from.</p></div>}</div></div>;
}

/* ------------------------------------------------------------ compare */
function CompareView({ id, ix }: { id: string; ix: EvalIndex }) {
  const { data: e, err } = useExperiment(id);
  if (err) return <Failed what="This comparison" />;
  if (!e) return <Loading what="the comparison" />;
  const c = e.comparison;
  if (!c) return <div className="m-sec"><h2>{e.title}</h2><Callout kind="info"><strong>No comparison is offered.</strong> {e.comparison_unavailable}</Callout><p className="m-muted">Nothing is inferred from a single result.</p></div>;
  if (c.kind === "scanner_vs_runtime") return <div>
    <h2>{e.title}</h2><Callout kind="info"><strong>Method.</strong> {c.method}</Callout>
    <Table caption="Each scan and the runtime runs that involve the same description hash" head={["Scan", "Findings", "Description SHA-256", "Runtime runs with the same hash", "What the runtime did"]}
      rows={c.rows.map((r: any) => [r.scan, String(r.finding_count), <code key="h">{r.description_sha256}</code>, r.runtime_runs_with_the_same_hash.map((x: any) => `${x.role} ${x.run_id.slice(0, 8)}`).join("; ") || "none", // eslint-disable-line @typescript-eslint/no-explicit-any
        r.runtime_runs_with_the_same_hash.map((x: any) => `${x.role}: ${x.follow_on_decisions.join(", ") || "no follow-on decision"}; ${x.handler_starts} handler start(s)`).join(" | ") || "—"])} /> {/* eslint-disable-line @typescript-eslint/no-explicit-any */}
    <LimitationsList items={c.limits} level={3} /></div>;
  const eq = c.same_request_fields ?? {}, chk = c.same_request_check!;
  return <div>
    <h2>{e.title}</h2>
    <Callout kind={c.controlled_pair ? "good" : "warn"}><strong>Controlled pair: {c.controlled_pair ? "YES" : "NO"}.</strong> {c.reading}</Callout>
    <p className="m-muted">Compared: the ATTACK and RETEST runs, 2 of the {e.cases.length} recorded cases in this experiment. Compared fields come from the {chk.control} decision (number {chk.nth_decision + 1}).</p>
    <Table caption="Is the request the same in both runs?" head={["Field", "ATTACK", "RETEST", "Same?"]}
      rows={Object.keys(eq).map((f) => [<code key="f">{f}</code>, cell(chk.attack[f]), cell(chk.retest[f]), chk.fields_absent_in_both.includes(f) ? "absent in both" : eq[f] ? "yes" : "NO"])} />
    {c.also_reported && Object.keys(c.also_reported).length > 0 && <Table caption="Also reported, not part of the test" head={["Field", "ATTACK", "RETEST", "Same?"]}
      rows={Object.entries(c.also_reported).map(([f, v]) => [<code key="f">{f}</code>, cell(v.attack), cell(v.retest), v.equal ? "yes" : "NO"])} />}
    <Table caption="The recorded runs side by side" head={["Measure", ...(c.roles ?? [])]} rows={c.rows.map((r: any) => [r.label, ...(c.roles ?? []).map((role) => cell(r.values[role]))])} /> {/* eslint-disable-line @typescript-eslint/no-explicit-any */}
    <LimitationsList items={c.limits} level={3} /><p className="m-muted">Other experiments with a comparison: {ix.experiments.filter((x) => x.comparison && x.id !== id).map((x) => x.id).join(", ")}.</p></div>;
}

function Compare({ ix, id }: { ix: EvalIndex; id: string | null }) {
  return <div className="ev-split"><aside aria-label="Experiments to compare"><p className="m-muted">Choose an experiment. A comparison is offered only where the sources support one.</p>
    <ul className="ev-list">{ix.experiments.map((e) => <li key={e.id}><Link to={`${EVALS_PATH}/compare/${e.id}`} aria-current={e.id === id ? "page" : undefined} className={e.id === id ? "is-current" : ""}>{e.title}<small>{e.comparison ? (e.comparison === "attack_retest" ? `attack and retest · controlled pair: ${e.controlled_pair ? "yes" : "no"}` : "scanner and runtime") : "no comparison"}</small></Link></li>)}</ul></aside>
    <div className="ev-detail">{id ? (ix.experiments.some((e) => e.id === id) ? <CompareView id={id} ix={ix} /> : <div className="m-sec" role="alert"><p>There is no experiment called {id}.</p></div>) : <div className="m-sec"><h2>Choose an experiment</h2><p>Runs are compared only when they belong to one documented experiment and carry the same request. Unrelated runs are never compared.</p></div>}</div></div>;
}

/* ------------------------------------------------------------ findings */
function FindingCard({ f, ix }: { f: Finding; ix: EvalIndex }) {
  const e = ix.experiments.find((x) => x.id === f.experiment)!;
  return <article className="wk-card" aria-labelledby={`f-${f.id}`}>
    <header><h3 id={`f-${f.id}`}>{f.title}</h3><div className="wk-badges"><VerificationBadge status={f.verification.status} /><Badge tone="muted">SEVERITY {f.severity}</Badge></div></header>
    <dl className="wk-kv">
      <div><dt>Evaluation source</dt><dd><Link to={`${EVALS_PATH}/results/${f.experiment}`}>{e.title}</Link> <small>{e.status}</small></dd></div>
      <div><dt>Observed behavior</dt><dd>{f.observed}</dd></div>
      <div><dt>Expected behavior</dt><dd>{f.expected.documented ? <><q>{f.expected.quote!.text}</q> <small className="m-src">Source: <code>{src(f.expected.quote!.file)}</code></small></> : "NOT DOCUMENTED"}</dd></div>
      <div><dt>Documented line matches</dt><dd>{f.matches_documented === null ? "Not computed" : f.matches_documented ? "Yes" : "No"}<small>{f.match_basis}</small></dd></div>
      <div><dt>Related threat</dt><dd>{f.threat}</dd></div>
      <div><dt>Likelihood · Impact</dt><dd>{f.likelihood} · {f.impact}</dd></div>
      <div><dt>Owner · Remediation</dt><dd>{f.owner} · {f.remediation_status}</dd></div></dl>
    <details className="m-details"><summary>Target, conditions and evidence references</summary>
      <dl className="rec-fields"><div><dt>Target</dt><dd>{cell(f.target)}</dd></div><div><dt>Test conditions</dt><dd>{cell(f.conditions)}</dd></div><div><dt>Derived by the rule</dt><dd>{RULES[f.rule]}</dd></div>
        <div><dt>Evidence</dt><dd>{f.evidence.join(", ")}</dd></div></dl><ProvenanceDisclosure sources={f.sources} /></details>
    <LimitationsList items={f.limitations} /></article>;
}

function Findings({ ix }: { ix: EvalIndex }) {
  const [exp, setExp] = useState("all"), [m, setM] = useState("all"), [q, setQ] = useState("");
  const list = ix.findings.filter((f) => (exp === "all" || f.experiment === exp) && (m === "all" || (m === "yes" ? f.matches_documented === true : f.matches_documented !== true)) && (!q || (f.title + f.observed).toLowerCase().includes(q.toLowerCase())));
  const withFindings = ix.experiments.filter((e) => e.findings.length > 0);
  return <>
    <Callout kind="info"><strong>How findings are made.</strong> A finding is derived from a recorded test case by one of two stated rules, never typed in. A finding is not a risk: severity, likelihood, impact, owner and remediation are NOT ASSESSED or NOT ASSIGNED until someone with the evidence sets them.</Callout>
    <div className="ev-filters"><label>Evaluation<select value={exp} onChange={(e) => setExp(e.target.value)}><option value="all">All evaluations</option>{withFindings.map((e) => <option key={e.id} value={e.id}>{e.title}</option>)}</select></label>
      <label>Documented line<select value={m} onChange={(e) => setM(e.target.value)}><option value="all">Any</option><option value="yes">Names the observed outcome</option><option value="no">Does not name it (needs a look)</option></select></label>
      <label>Search<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Text in a finding" /></label></div>
    <p role="status" className="m-muted">Showing {list.length} of {ix.findings.length} findings.</p>
    {list.length > 0 && <h2>Findings</h2>}
    {list.length === 0 ? <div className="m-sec"><p>No finding matches these filters.</p><Button variant="secondary" onClick={() => { setExp("all"); setM("all"); setQ(""); }}>Clear the filters</Button></div> : list.map((f) => <FindingCard key={f.id} f={f} ix={ix} />)}</>;
}

/* ------------------------------------------------------------ export */
function Export({ ix }: { ix: EvalIndex }) {
  const [picked, setPicked] = useState<string[]>(["mcp-003"]);
  const [fmt, setFmt] = useState<"md" | "json">("md");
  const [exps, setExps] = useState<Experiment[] | null>(null);
  const [err, setErr] = useState(false);
  const [done, setDone] = useState("");
  useEffect(() => { let live = true; setExps(null); setErr(false); Promise.all(picked.map(loadExperiment)).then((x) => live && setExps(x), () => live && setErr(true)); return () => { live = false; }; }, [picked]);
  const text = useMemo(() => exps && exps.length ? (fmt === "md" ? reportMarkdown(ix, exps) : JSON.stringify(reportJson(ix, exps), null, 2) + "\n") : "", [exps, fmt, ix]);
  const toggle = (id: string, on: boolean) => { setDone(""); setPicked(on ? ix.experiments.map((e) => e.id).filter((x) => picked.includes(x) || x === id) : picked.filter((x) => x !== id)); };
  const download = () => {
    const name = `eval-report-${picked.length === ix.experiments.length ? "all" : picked.join("+")}.${fmt === "md" ? "md" : "json"}`;
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: fmt === "md" ? "text/markdown" : "application/json" })); a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setDone(`Downloaded ${name} (${text.length} characters).`);
  };
  return <>
    <p className="m-muted">The report is built in your browser from the evidence files and downloaded as a file. Nothing is sent anywhere. Observations (what the sources recorded) and interpretations (what they mean, with the basis) are separate sections, and provenance and limitations are included.</p>
    <div className="ev-export"><fieldset><legend>Experiments to include</legend>{ix.experiments.map((e) => <label key={e.id}><input type="checkbox" checked={picked.includes(e.id)} onChange={(x) => toggle(e.id, x.target.checked)} /> {e.title} <small>({e.evidence_class})</small></label>)}
      <div className="m-actions"><Button variant="ghost" onClick={() => setPicked(ix.experiments.map((e) => e.id))}>Select all</Button><Button variant="ghost" onClick={() => setPicked([])}>Clear</Button></div></fieldset>
      <fieldset><legend>Format</legend><label><input type="radio" name="fmt" checked={fmt === "md"} onChange={() => setFmt("md")} /> Markdown (readable)</label><label><input type="radio" name="fmt" checked={fmt === "json"} onChange={() => setFmt("json")} /> JSON (structured)</label></fieldset></div>
    {picked.length === 0 && <div className="m-sec"><p>Select at least one experiment to build a report.</p></div>}
    {err && <Failed what="The report" />}
    {picked.length > 0 && !err && !exps && <Loading what="the selected evidence" />}
    {text && <><div className="m-actions"><Button onClick={download} icon="arrow">Download the report</Button></div><p role="status" className="m-muted">{done}</p>
      <details className="m-details" open><summary>Preview ({text.length} characters)</summary><pre className="ev-preview" tabIndex={0} aria-label="Report preview">{text}</pre></details></>}
  </>;
}

/* ------------------------------------------------------------ page */
export default function EvalCenter({ view, id }: { view: EvalView; id: string | null }) {
  const { data: ix, err } = useIndex();
  const titles: Record<EvalView, string> = { overview: "Overview", catalog: "Evaluation catalog", results: "Results explorer", compare: "Comparison", findings: "Findings and evidence", export: "Export a report" };
  return <div className="page wk ev">
    <header className="page-header"><div><div className="eyebrow">AI SECURITY EVALUATION CENTER · RECORDED EVIDENCE</div><h1>{titles[view]}</h1>
      <p>What was tested, what happened, and how far the evidence goes. Built only from committed evidence; nothing here ran just now.</p></div></header>
    <nav aria-label="Evaluation Center" className="ev-tabs"><ul>{TABS.map((t) => <li key={t.view}><Link to={t.to} aria-current={t.view === view ? "page" : undefined} className={t.view === view ? "is-current" : ""}>{t.label}</Link></li>)}</ul></nav>
    {err && <Failed what="The evaluation index" />}
    {!ix && !err && <Loading what="the evaluation index" />}
    {ix && view === "overview" && <Overview ix={ix} />}
    {ix && view === "catalog" && <Catalog ix={ix} />}
    {ix && view === "results" && <Results ix={ix} id={id} />}
    {ix && view === "compare" && <Compare ix={ix} id={id} />}
    {ix && view === "findings" && <Findings ix={ix} />}
    {ix && view === "export" && <Export ix={ix} />}
  </div>;
}
