import { useState } from "react";
import { Badge, Button } from "../ui";
import { Callout, CopyButton } from "../mission/parts";
import type { External, Investigation, Question } from "../curriculum";
import { EventRow, NOT_VERIFIED, RECORDED_BADGE } from "./RecordedWorkbench";
import { evaluate, keep, summarize, type Filter } from "./investigation";
import { seq } from "./recorded";

const FILTERS: [Filter, string][] = [["all", "All events"], ["decisions", "Control decisions"], ["handlers", "Handler events (mcp.*)"], ["context", "Memory and retrieval events"]];
const tone = (a: string) => a === "ALLOW" || a === "yes" ? "allow" : a === "DENY" || a === "no" ? "deny" : a === "ERROR" ? "warning" : a === "OBSERVE" ? "observed" : "muted";

function Ask({ q, inv }: { q: Question; inv: Investigation }) {
  const [pick, setPick] = useState<string>();
  const [shown, setShown] = useState(false);
  const r = shown ? evaluate(inv, q.eval) : null;
  return <li className="rec-q"><fieldset disabled={shown}><legend>{q.prompt}</legend>
    <div className="rec-options">{q.choices.map((c) => <label key={c}><input type="radio" name={`q-${q.id}`} value={c} checked={pick === c} onChange={() => setPick(c)} /> {c}</label>)}</div></fieldset>
    {!shown && <div className="m-actions"><Button disabled={!pick} onClick={() => setShown(true)}>Check against the recorded evidence</Button><Button variant="ghost" onClick={() => setShown(true)}>Show the answer without predicting</Button></div>}
    {r && <div role="status" className="rec-reveal">
      <p>{pick ? <>You answered <strong>{pick}</strong>. </> : null}Recorded: <Badge tone={tone(r.answer)}>{r.answer}</Badge>{pick ? (pick === r.answer ? " — your answer matched." : " — your answer did not match.") : ""}</p>
      <p className="m-muted">Read from: {r.pointers.map((p, i) => <span key={i}>{i ? "; " : ""}<code>{p}</code></span>)}.</p>
      <p>{q.teach}</p><p className="m-muted">The lab's own wording: <q>{q.quote.text}</q> <small className="m-src">Source: <code>{q.quote.file.split("/").pop()}</code></small></p></div>}
  </li>;
}

function Scanner({ ext }: { ext: External[] }) {
  return <div className="m-sec"><h4>The scanner's own records <Badge tone="replay">{RECORDED_BADGE}</Badge></h4>
    <p className="m-muted">Plane 1: what the external scanner recorded. It is a static scan of a catalog snapshot, and it records no run id.</p>
    <ul className="rec-events">{ext.map((x) => x.records.map((r, i) => {
      const a = (r.artifact ?? {}) as Record<string, unknown>, fi = r.finding as Record<string, unknown> | undefined, sc = r.scan as Record<string, unknown> | undefined;
      return <li className="rec-event" key={`${x.scan_id}-${i}`}><details><summary><code>{String(r["event.name"]).replace("agentsec.", "")}</code> <Badge tone="observed">{String(r.evidence_class)}</Badge> <span className="rec-sum">{String(a.fixture)} · {sc ? `finding_count ${String(sc.finding_count)}` : fi ? `${String(fi.native_severity)} ${String(fi.native_category)}` : ""}</span></summary>
        <dl className="rec-fields">{[["scan_id", x.scan_id], ["description_sha256", a.description_sha256], ["artifact.sha256", a.sha256]].map(([k, v]) => <div key={String(k)}><dt><code>{String(k)}</code></dt><dd>{String(v)}</dd></div>)}</dl>
        <h5>The record, verbatim</h5><pre className="rec-pre">{JSON.stringify(r, null, 1)}</pre></details></li>;
    }))}</ul></div>;
}

/** Practice for an investigation over committed packs: questions with computed answers, a chronological timeline, and a scenario comparison. */
export function InvestigationPractice({ inv }: { inv: Investigation }) {
  const [sel, setSel] = useState(inv.scenarios[0].id);
  const [filter, setFilter] = useState<Filter>("all");
  const [hints, setHints] = useState(0);
  const sc = inv.scenarios.find((s) => s.id === sel)!;
  const hintBlock = inv.blocks.find((b) => b.group === "hints");
  const rows = inv.scenarios.map((s) => ({ s, facts: summarize(s) }));
  return <div className="m-sec rec" data-testid="investigation-workbench">
    <h3>Recorded investigation <Badge tone="replay">{RECORDED_BADGE}</Badge></h3>
    <p className="m-muted">Everything here is read from committed specimen packs the lab recorded earlier. Nothing is launched, no model is called and nothing is sent to Splunk.</p>
    <div className="m-explain"><Badge tone="muted">THE LAB'S BRIEF</Badge>{inv.brief.paragraphs.map((p) => <p key={p}>{p}</p>)}<small className="m-src">Source: <code>{inv.brief.source}</code></small></div>

    <div className="m-sec"><h4>1. Answer, then check <Badge tone="muted">YOUR ANSWER IS NOT EVIDENCE</Badge></h4>
      <p className="m-muted">Each answer is computed from the recorded events when you check it. You can also open the timeline below and investigate first.</p>
      <ol className="rec-qs">{inv.questions.map((q) => <Ask key={q.id} q={q} inv={inv} />)}</ol></div>

    {hintBlock && <div className="m-sec"><h4>Hints, in the order the lab discloses them</h4>
      <ol>{hintBlock.items.slice(0, hints).map((h) => <li key={h}>{h}</li>)}</ol>
      {hints < hintBlock.items.length ? <Button variant="secondary" onClick={() => setHints(hints + 1)}>Show hint {hints + 1} of {hintBlock.items.length}</Button> : <p className="m-muted">All {hintBlock.items.length} hints shown.</p>}
      <small className="m-src">Source: <code>{hintBlock.source}</code></small></div>}

    <div className="m-sec"><h4>2. Read the recorded timeline</h4>
      <div role="group" aria-label="Scenarios" className="rec-runs">{inv.scenarios.map((s) => <button key={s.id} type="button" aria-pressed={s.id === sel} className={`rec-run ${s.id === sel ? "is-current" : ""}`} onClick={() => setSel(s.id)}>{s.label}<small>{s.runs.length} run{s.runs.length > 1 ? "s" : ""}</small></button>)}</div>
      <fieldset className="rec-filter"><legend>Show</legend>{FILTERS.map(([k, label]) => <label key={k}><input type="radio" name="inv-filter" checked={filter === k} onChange={() => setFilter(k)} /> {label}</label>)}</fieldset>
      <p className="m-muted">Ordered by the lab's stage order, then by recorded sequence. Several runs share one timestamp second, so the order across runs is the lab's documented order, not a measured clock order. Documented in <code>{sc.documented_in}</code>.</p>
      {sc.runs.map((r) => <section key={r.run_id} aria-label={`${sc.label}, ${r.stage}`} className="rec-stage">
        <h5>{r.stage === "run" || r.stage === "runtime" ? "Run" : r.stage} · <code>{r.run_id}</code> · {r.meta.mode}, {r.meta.profile}</h5>
        <ol className="rec-events" aria-label={`Events of the ${r.stage} run`}>{r.events.filter((e) => keep(e, filter)).map((e) => <EventRow key={seq(e)} e={e} />)}</ol>
        {r.events.filter((e) => keep(e, filter)).length === 0 && <p className="m-muted">No events of this kind in this pack.</p>}
        <p className="m-muted">Source specimen <code>{r.pack}</code>.</p></section>)}
    </div>
    {inv.external.length > 0 && <Scanner ext={inv.external} />}

    <div className="m-sec"><h4>3. Compare the scenarios</h4>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Scenario comparison; scrolls sideways on a narrow screen"><table><caption className="m-caption">Facts read from each scenario's recorded events</caption>
        <thead><tr><th scope="col">Fact</th>{rows.map(({ s }) => <th scope="col" key={s.id}>{s.label}</th>)}</tr></thead>
        <tbody>{rows[0].facts.map((fa, i) => { const vals = rows.map((r) => r.facts[i].value); return <tr key={fa.label} className={new Set(vals).size > 1 ? "rec-differs" : ""}><th scope="row">{fa.label}{new Set(vals).size > 1 && <small> (differs)</small>}</th>{vals.map((v, j) => <td key={j}>{v}</td>)}</tr>; })}</tbody></table></div></div>
  </div>;
}

/** Prove for an investigation: the lab's own findings and limits, the evidence graph if the lab has one, provenance, verification status and the lab's searches. */
export function InvestigationProve({ inv }: { inv: Investigation }) {
  const [done, setDone] = useState<Record<string, boolean>>({});
  const runs = [...new Map(inv.scenarios.flatMap((s) => s.runs.map((r) => [r.run_id, { r, s }] as const))).values()];
  const block = (g: string) => inv.blocks.filter((b) => b.group === g);
  return <div className="m-sec rec" data-testid="investigation-prove">
    <h3>What the evidence supports, and what it does not <Badge tone="replay">{RECORDED_BADGE}</Badge></h3>
    <Callout kind="warn"><strong>Verification status: not verified here.</strong> {NOT_VERIFIED}</Callout>
    {block("prove").map((b) => <div className="m-sec" key={b.title}><h4>{b.title}</h4><ul className="m-rules">{b.items.map((i) => <li key={i}>{i}</li>)}</ul><small className="m-src">Source: <code>{b.source}</code></small></div>)}
    {inv.graph && <div className="m-sec"><h4>The lab's bounded evidence graph</h4>
      <p>{inv.graph.scope}. Edges may only mean: {inv.graph.allowed_edge_semantics.join(", ")}. Not allowed unless established: {inv.graph.forbidden_unless_established.join(", ")}.</p>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Evidence graph nodes; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Nodes, with the lab's own state for each</caption><thead><tr><th scope="col">Node</th><th scope="col">Kind</th><th scope="col">State</th></tr></thead>
        <tbody>{inv.graph.nodes.map((n) => <tr key={n.id}><td data-label="Node">{n.label}</td><td data-label="Kind">{n.kind}</td><td data-label="State"><Badge tone={n.state === "PROVEN" ? "allow" : n.state === "REFUTED" || n.state === "NOT OBSERVED" ? "muted" : "observed"}>{n.state}</Badge></td></tr>)}</tbody></table></div>
      <ul className="m-rules">{inv.graph.edges.map((e) => { const l = (id: string) => inv.graph!.nodes.find((n) => n.id === id)?.label ?? id; return <li key={e.from + e.to}>{l(e.from)} <strong>{e.semantic}</strong> {l(e.to)} — <span className="m-muted">basis: {e.basis}</span></li>; })}</ul>
      <small className="m-src">Source: <code>{inv.graph.source}</code></small></div>}
    {inv.control_analysis && <div className="m-sec"><h4>The lab's control analysis</h4>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Control analysis; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Control by control, as the lab states it</caption><thead><tr>{Object.keys(inv.control_analysis.controls[0]).map((k) => <th scope="col" key={k}>{k.replace(/_/g, " ")}</th>)}</tr></thead>
        <tbody>{inv.control_analysis.controls.map((c) => <tr key={c.control}>{Object.keys(inv.control_analysis!.controls[0]).map((k) => <td key={k} data-label={k.replace(/_/g, " ")}>{c[k] ?? "—"}</td>)}</tr>)}</tbody></table></div>
      <small className="m-src">Source: <code>{inv.control_analysis.source}</code></small></div>}
    {[...block("limits"), ...block("rules")].map((b) => <div className="m-sec" key={b.title}><h4>{b.title}</h4><ul className="m-rules">{b.items.map((i) => <li key={i}>{i}</li>)}</ul><small className="m-src">Source: <code>{b.source}</code></small></div>)}
    {block("assess").length > 0 && <div className="m-sec"><h4>Check yourself <Badge tone="muted">SELF-ASSESSED · NOT SAVED · NOT A CERTIFICATION</Badge></h4>
      {block("assess").map((b) => <fieldset key={b.title}><legend>{b.title}</legend><ul className="rec-checks">{b.items.map((i) => <li key={i}><label><input type="checkbox" checked={Boolean(done[i])} onChange={(e) => setDone({ ...done, [i]: e.target.checked })} /> {i}</label></li>)}</ul><small className="m-src">Source: <code>{b.source}</code></small></fieldset>)}</div>}
    <details className="m-details"><summary>Provenance of each pack</summary>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Pack provenance; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Committed packs shown on this page</caption>
        <thead><tr><th scope="col">Run or scan</th><th scope="col">Pack file</th><th scope="col">SHA-256 of the file</th><th scope="col">Originally recorded as</th><th scope="col">First event</th></tr></thead>
        <tbody>{runs.map(({ r, s }) => <tr key={r.run_id}><td data-label="Run"><code>{r.run_id}</code><br />{s.label}</td><td data-label="Pack file"><code>{r.pack}</code></td><td data-label="SHA-256"><code>{r.sha256}</code></td><td data-label="Originally recorded as">{r.meta.execution_mode} / {r.meta.fidelity}, schema {r.meta.schema_version}</td><td data-label="First event">{r.meta.started}</td></tr>)}
          {inv.external.map((x) => <tr key={x.scan_id}><td data-label="Run"><code>{x.scan_id}</code><br />scanner scan</td><td data-label="Pack file"><code>{x.pack}</code></td><td data-label="SHA-256"><code>{x.sha256}</code></td><td data-label="Originally recorded as">{String(x.records[0].evidence_class)}</td><td data-label="First event">{String(x.records[0].timestamp)}</td></tr>)}</tbody></table></div>
      <p className="m-muted">Original timestamps and values are preserved. "LIVE / OBSERVED" describes how the lab recorded them at the time, not how this page shows them.</p></details>
    <div className="m-sec"><h3>The lab's searches (SPL)</h3>
      <p className="m-muted">Shown as written in the lab. They are not run from this page. Each uses a placeholder such as <code>__RUN_ID__</code>; the lab's dashboards fill it in.</p>
      {inv.spl.map((q) => <details className="m-details" key={q.source}><summary><code>{q.name}</code></summary><pre>{q.text}</pre><CopyButton text={q.text} label="Copy search" /><small className="m-src">Source: <code>{q.source}</code></small></details>)}</div>
  </div>;
}

