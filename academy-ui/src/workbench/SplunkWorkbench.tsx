import { useState } from "react";
import { Badge, Button } from "../ui";
import { Callout, CopyButton } from "../mission/parts";
import type { Checkpoint, CmpSide, Study, StudyQuestion } from "../curriculum";
import { dig, text } from "./checkpoint";
import { Question } from "./StudyWorkbench";

type Spec = Study & Checkpoint["spec"];
type Row = Record<string, unknown>;
interface Search { id: string; spl_file: string; spl_sha256: string; spl_text: string; sid: string; submitted_at: string; dispatch_state: string; result_count: number; scan_count: number; time_bounds: { earliest_time: string | null; latest_time: string | null }; attribution: { kind: string; run_ids?: string[]; note?: string; run_attribution?: string; scope?: string }; errors_or_warnings: unknown[]; rows: Row[] }
interface MRun { run_id: string; mode: string[]; indexed_rows: number; committed_pack: { path: string; sha256: string } | null; match: { exact_raw_bytes: number; pack_events: number } | null }

const searchesOf = (cp: Checkpoint) => cp.packet.searches.searches as Search[];
const runsOf = (cp: Checkpoint) => (cp.packet.matching.runs as MRun[]);
const one = (x: unknown) => x && typeof x === "object" ? Object.values(x).join(" ") : text(x);
const cell = (v: unknown) => v === undefined ? "—" : Array.isArray(v) ? v.map(one).join(", ") : text(v) ?? "—";
const cols = (rows: Row[]) => [...new Set(rows.flatMap((r) => Object.keys(r)))].filter((k) => !k.startsWith("_") || k === "_time");
const src = (f: string) => f.split("/").pop();

function Table({ title, rows }: { title: string; rows: Row[] }) {
  const c = cols(rows);
  return <div className="table-wrap" tabIndex={0} role="region" aria-label={`${title}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{title}, values as recorded</caption>
    <thead><tr>{c.map((k) => <th scope="col" key={k}>{k}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={i}>{c.map((k) => <td key={k} data-label={k}>{cell(r[k])}</td>)}</tr>)}</tbody></table></div>;
}

function Results({ s, cp }: { s: Search; cp: Checkpoint }) {
  const runs = new Map(runsOf(cp).map((r) => [r.run_id, r]));
  return <div className="rec-reveal" role="status">
    {s.rows.length === 0 ? <p><strong>Zero rows returned.</strong> The search executed successfully (state {s.dispatch_state}, {s.scan_count} events scanned). A zero-row result is a recorded execution, not missing evidence, and it does not by itself prove anything is correct or safe.</p> : <Table title={`Rows returned by ${s.id}`} rows={s.rows} />}
    <dl className="rec-fields">
      <div><dt>Search id</dt><dd><code>{s.sid}</code></dd></div><div><dt>Submitted at</dt><dd>{s.submitted_at}</dd></div><div><dt>State</dt><dd>{s.dispatch_state}</dd></div>
      <div><dt>Result count</dt><dd>{s.result_count}</dd></div><div><dt>Events scanned</dt><dd>{s.scan_count}</dd></div>
      <div><dt>Time bounds recorded</dt><dd>earliest {s.time_bounds.earliest_time ?? "not reported"}; latest {s.time_bounds.latest_time ?? "not reported"}</dd></div>
      <div><dt>Warnings and errors</dt><dd>{s.errors_or_warnings.length === 0 ? "none recorded" : text(s.errors_or_warnings)}</dd></div>
      <div><dt>Attribution</dt><dd>{s.attribution.kind === "per_run" ? `the output names ${s.attribution.run_ids?.length} runs` : s.attribution.kind === "unattributed_sample" ? s.attribution.note : `aggregate: ${s.attribution.run_attribution ?? "not attributable to individual runs"}`}</dd></div></dl>
    {s.attribution.kind === "per_run" && <p className="m-muted">Of the {s.attribution.run_ids!.length} runs it names, {s.attribution.run_ids!.filter((r) => runs.get(r)?.committed_pack).length} have a committed specimen pack and {s.attribution.run_ids!.filter((r) => !runs.get(r)?.committed_pack).length} do not.</p>}
  </div>;
}

function RunTable({ cp, title }: { cp: Checkpoint; title: string }) {
  const runs = runsOf(cp);
  return <div className="table-wrap" tabIndex={0} role="region" aria-label={`${title}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{title}</caption>
    <thead><tr><th scope="col">Run</th><th scope="col">Mode</th><th scope="col">Indexed events</th><th scope="col">Committed pack</th><th scope="col">Byte match with the pack</th></tr></thead>
    <tbody>{runs.map((r) => <tr key={r.run_id}><th scope="row"><code>{r.run_id}</code></th><td data-label="Mode">{r.mode.join(", ")}</td><td data-label="Indexed events">{r.indexed_rows}</td>
      <td data-label="Committed pack">{r.committed_pack ? <><span>yes</span> <small><code>{r.committed_pack.path}</code></small></> : "no committed pack"}</td>
      <td data-label="Byte match with the pack">{r.match ? `${r.match.exact_raw_bytes} of ${r.match.pack_events} pack events` : "not comparable"}</td></tr>)}</tbody></table></div>;
}

function IndexWide({ cp }: { cp: Checkpoint }) {
  const w = cp.packet.matching.index_wide;
  return <p role="note"><strong>{w.otel_runs_in_index} runs are indexed. {w.runs_with_committed_pack} have a committed pack and {w.runs_without_committed_pack} do not.</strong> {w.statement}</p>;
}

function Side({ side, cp }: { side: CmpSide; cp: Checkpoint }) {
  if (side.search) { const s = searchesOf(cp).find((x) => x.id === side.search)!; return <Table title={`${side.label}: ${s.id}`} rows={s.rows} />; }
  const rows = (dig(cp.packet, side.path!) as Row[]).map((r) => Object.fromEntries(side.columns!.map(([k, l]) => [l, r[k]])));
  return <Table title={side.label} rows={rows} />;
}

/** Practice for recorded Splunk results: predict, reveal the recorded rows and metadata, compare, and inspect which runs have committed packs. Nothing here queries Splunk. */
export function SplunkPractice({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec as Spec, stages = spec.stages!, all = searchesOf(cp);
  const [idx, setIdx] = useState(0);
  const [picks, setPicks] = useState<Record<string, string[]>>({});
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const st = stages[idx], s = all.find((x) => x.id === st.search)!;
  const done = (qs: { id: string }[]) => qs.every((q) => shown[q.id]);
  const qui = (q: StudyQuestion) => <Question key={q.id} q={q} picked={picks[q.id] ?? []} onPick={(v) => setPicks({ ...picks, [q.id]: v })} shown={Boolean(shown[q.id])} onCheck={() => setShown({ ...shown, [q.id]: true })} />;
  return <div className="m-sec rec" data-testid="splunk-workbench">
    <h3>Recorded Splunk investigation <Badge tone="replay">{spec.label}</Badge></h3>
    <p className="m-muted">These are search results collected earlier from the lab's Splunk index with read-only searches. Nothing is searched, launched or sent to Splunk from this page, and no model is called. Your predictions are not evidence.</p>
    <div role="group" aria-label="Recorded searches" className="rec-runs">{stages.map((x, i) => <button key={x.search} type="button" aria-pressed={i === idx} className={`rec-run ${i === idx ? "is-current" : ""}`} onClick={() => setIdx(i)}>{x.title}<small>{revealed[x.search] ? "results shown" : "not yet predicted"}</small></button>)}</div>
    <div className="m-sec rec-predict"><h4>{st.title} <Badge tone="muted">YOUR PREDICTION IS NOT EVIDENCE</Badge></h4>
      <p>{st.goal}</p>
      <details className="m-details"><summary>The shipped search, <code>{s.id}</code></summary><pre>{s.spl_text}</pre><small className="m-src">Source: <code>{s.spl_file}</code>. SHA-256 <code>{s.spl_sha256}</code></small></details>
      <ol className="rec-qs">{st.questions.map((q) => qui(q))}</ol>
      {!revealed[s.id] && <div className="m-actions"><Button disabled={!done(st.questions)} onClick={() => setRevealed({ ...revealed, [s.id]: true })}>Show the recorded results</Button><Button variant="ghost" onClick={() => setRevealed({ ...revealed, [s.id]: true })}>Skip the predictions and show the recorded results</Button></div>}
      {revealed[s.id] && <Results s={s} cp={cp} />}
    </div>
    <div className="m-sec"><h4>Compare</h4>
      {(spec.comparisons ?? []).map((c) => { const need = [c.left, c.right].filter((x) => x.search).map((x) => x.search!), ready = need.every((n) => revealed[n]);
        const l = c.left.search ? all.find((x) => x.id === c.left.search) : undefined, r = c.right.search ? all.find((x) => x.id === c.right.search) : undefined;
        return <div key={c.title} className="m-sec"><h5>{c.title}</h5><p className="m-muted">{c.note}</p>
          {!ready ? <p className="m-muted">Show the recorded results of {need.join(" and ")} to compare them.</p> : <><Side side={c.left} cp={cp} /><Side side={c.right} cp={cp} />
            {l && r && l.rows.some((x) => x.run_id) && <p className="m-muted">Computed from the recorded rows: {l.id} returned {l.rows.length} rows and {r.id} returned {r.rows.length}. Run ids in {l.id} that are not in {r.id}: {l.rows.filter((x) => x.run_id && !r.rows.some((y) => y.run_id === x.run_id)).length} of {l.rows.filter((x) => x.run_id).length}.</p>}</>}
        </div>; })}
    </div>
    {spec.provenance && <div className="m-sec"><h4>{spec.provenance.title}</h4><p className="m-muted">{spec.provenance.intro}</p>
      <ol className="rec-qs">{spec.provenance.questions.map((q) => qui(q))}</ol>
      {done(spec.provenance.questions) && <><IndexWide cp={cp} /><RunTable cp={cp} title="Runs this lab's recorded searches depend on" /></>}</div>}
  </div>;
}

/** Prove for recorded Splunk results: exact SPL and hash, results and metadata, run and pack provenance, limits and a conclusion exercise. */
export function SplunkProve({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec as Spec, all = searchesOf(cp), man = cp.packet.manifest;
  const [picks, setPicks] = useState<Record<string, string[]>>({});
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const three = man.three_kinds_of_evidence;
  return <div className="m-sec rec" data-testid="splunk-prove">
    <h3>What was recorded, and where it comes from <Badge tone="replay">{spec.label}</Badge></h3>
    <Callout kind="warn"><strong>Verification status: NOT_VERIFIED.</strong> {spec.verification}</Callout>
    <div className="m-sec"><h4>Exact SPL and its source hash</h4>
      {all.map((s) => <details className="m-details" key={s.id}><summary><code>{s.id}</code></summary><pre>{s.spl_text}</pre><CopyButton text={s.spl_text} label="Copy search" />
        <dl className="rec-fields"><div><dt>Source file</dt><dd><code>{s.spl_file}</code></dd></div><div><dt>SHA-256 of the file</dt><dd><code>{s.spl_sha256}</code></dd></div></dl></details>)}</div>
    <div className="m-sec"><h4>Recorded results and execution metadata</h4>
      {all.map((s) => <details className="m-details" key={s.id}><summary><code>{s.id}</code> — {s.result_count} rows, search id {s.sid}</summary><Results s={s} cp={cp} /></details>)}</div>
    <div className="m-sec"><h4>Run and pack provenance</h4><IndexWide cp={cp} /><RunTable cp={cp} title="Runs behind this lab's recorded searches" />
      {cp.packet.matching.external_events && <div className="table-wrap" tabIndex={0} role="region" aria-label="External events found in the index; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">External and housekeeping events in the index, compared byte for byte with committed files</caption>
        <thead><tr><th scope="col">Sourcetype</th><th scope="col">Indexed rows for this event</th><th scope="col">SHA-256 of the raw event</th><th scope="col">Committed match</th></tr></thead>
        <tbody>{(cp.packet.matching.external_events as Row[]).map((e, i) => <tr key={i}><td data-label="Sourcetype">{String(e.sourcetype)}</td><td data-label="Indexed rows">{String(e.indexed_rows_with_this_raw)}</td><td data-label="SHA-256"><code>{String(e.raw_sha256)}</code></td><td data-label="Committed match">{(e.committed_match as string[] | null)?.length ? (e.committed_match as string[]).join("; ") : "none: not attributable to a committed file"}</td></tr>)}</tbody></table></div>}
      <details className="m-details"><summary>Provenance of the evidence files</summary>
        <dl className="rec-fields">{(cp.files ?? []).map((f) => <div key={f.name}><dt><code>{f.file}</code></dt><dd>SHA-256 <code>{f.sha256}</code></dd></div>)}
          <div><dt>Raw collection</dt><dd><code>{man.collection_file}</code> SHA-256 <code>{man.collection_sha256}</code></dd></div>
          <div><dt>Collected</dt><dd>{man.collected_at} from Splunk {man.splunk.version} (build {man.splunk.build})</dd></div></dl></details></div>
    {three && <div className="m-sec"><h4>Three kinds of evidence, kept apart</h4>
      <h5>Committed specimen evidence (the reproducible baseline)</h5>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Committed specimen packs; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Read directly from the committed packs of {three.committed_specimen_evidence.lab}</caption>
        <thead><tr><th scope="col">Run</th><th scope="col">Mode</th><th scope="col">Control decisions</th><th scope="col">Handler starts</th></tr></thead>
        <tbody>{(three.committed_specimen_evidence.runs as Row[]).map((r) => <tr key={String(r.run_id)}><th scope="row"><code>{String(r.run_id)}</code></th><td data-label="Mode">{String(r.mode)}</td>
          <td data-label="Control decisions">{(r.control_decisions as Row[]).map((c) => `${c.control_id} ${c.decision} ${c.reason}`).join("; ")}</td><td data-label="Handler starts">{(r.handler_starts as Row[]).length ? (r.handler_starts as Row[]).map((h) => String(h.tool)).join(", ") : "none"}</td></tr>)}</tbody></table></div>
      <h5>Current Splunk observations</h5>
      <p>{three.current_splunk_observations.note} The index holds {three.current_splunk_observations.identity_runs_in_index.length} identity runs: {three.current_splunk_observations.identity_runs_with_committed_pack.length} with a committed pack and {three.current_splunk_observations.identity_runs_without_committed_pack.length} without. The committed packs do not reproduce every current identity run.</p>
      <h5>Historical documented expectations (not part of the current observation)</h5>
      <p className="m-muted">From <code>{src(three.historical_documented_expectations.source_file)}</code>. Its run ids are {three.historical_documented_expectations.historical_run_ids_present_in_the_current_index.length === 0 ? "not in the current index" : "in the current index"} and have no committed pack, so they are not merged with anything above.</p>
      <ul className="m-rules">{(three.historical_documented_expectations.statements as { text: string }[]).map((x) => <li key={x.text}><q>{x.text}</q></li>)}</ul></div>}
    {(spec.documented ?? []).length > 0 && <div className="m-sec"><h4>What the lab's documents say (documented statements, not results)</h4><ul className="m-rules">{spec.documented!.map((x) => <li key={x.text}><q>{x.text}</q> <small className="m-src">Source: <code>{src(x.file)}</code></small></li>)}</ul></div>}
    <div className="m-sec"><h4>Limits</h4><ul className="m-rules">{(man.limitations as string[]).map((x) => <li key={x}>{x}</li>)}{spec.limits.map((x) => <li key={x.text}><q>{x.text}</q> <small className="m-src">Source: <code>{src(x.file)}</code></small></li>)}</ul></div>
    {spec.conclusion && <div className="m-sec"><h4>{spec.conclusion.title}</h4><p className="m-muted">{spec.conclusion.intro}</p>
      <ol className="rec-qs">{spec.conclusion.questions.map((q) => <Question key={q.id} q={q} picked={picks[q.id] ?? []} onPick={(v) => setPicks({ ...picks, [q.id]: v })} shown={Boolean(shown[q.id])} onCheck={() => setShown({ ...shown, [q.id]: true })} />)}</ol></div>}
    {cp.spl.length > 0 && <div className="m-sec"><h3>Related dashboard searches</h3>{cp.spl.map((q) => <details className="m-details" key={q.source}><summary><code>{q.name}</code></summary><pre>{q.text}</pre></details>)}</div>}
  </div>;
}
