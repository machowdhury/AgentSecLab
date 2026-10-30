import { useEffect, useRef, useState } from "react";
import { Badge, Button, Icon, LinkButton } from "../ui";
import { api, post } from "../api";
import { Link, MCP_PATH, comparePath, findingPath, labPath, missionPath, navigate, assuranceTabPath, type AssuranceTab } from "../router";
import { adoptRunForWorkshop, updateInvestigationCell, useMission } from "../store";
import { cellState } from "../mission/Notebook";
import { CopyButton } from "../mission/parts";
import { REASONS, TAB_LABEL, cellRunUrl, exploreUrl, investigationUrl, readWindow, searchUrl, useLoad, type CellResult, type InvCell, type Investigation, type WindowKey } from "./live";
import { Banner, ClassBadge, StatusPill } from "./liveParts";
import { insight } from "./insight";

const workshopPath = (lab: string) => (lab === "LAB-LOANDESK-001" ? missionPath() : lab === "LAB-MCP-001" ? MCP_PATH : labPath(lab));
const short = (id: string) => `${id.slice(0, 8)}…`;

function problem(res: { status: number; data: any }): string {
  const e = res.data?.error;
  if (res.status === 503 && e === "search_unavailable") return "Search access to Splunk is not set up on this lab, so nothing was searched. There is no result here, and that is not a pass. Ask the lab owner to run ./agentsec splunk-access.";
  if (res.status === 403) return "Running a live search needs the operator role. Sign in as the operator, or read the recorded examples, which need no search.";
  if (res.status === 429) return "Too many searches in a short time. Wait a few seconds and run it again.";
  if (res.status === 404) return "This finding is no longer in the view (the window moved or the data changed). Go back and open it again.";
  if (res.status === 0) return "The Attack Service could not be reached, so nothing was searched.";
  return res.data?.detail || `Unexpected response (HTTP ${res.status}).`;
}

const FAIL: Record<string, string> = {
  timeout: "The search took too long and was stopped. Try fewer rows, then run it again.",
  search_failed: "Splunk could not run this search. Check that Splunk is up, then retry.",
  access_denied: "Splunk refused the lab's search identity, so nothing was searched. There is no result here, and that is not an empty result or a pass. Ask the lab owner to run ./agentsec splunk-access --check.",
  backend_unavailable: "The Attack Service cannot reach Splunk right now, so there is no result. Nothing was searched.",
  refused: "The search was refused because a parameter was not allowed.",
};

function AssuranceSplCell({ ctx, cell, index, tab, win, onRan }: { ctx: Investigation & { reasonNotReady?: string }; cell: InvCell; index: number; tab: AssuranceTab; win: WindowKey; onRan?: () => void }) {
  const fid = ctx.origin.finding_id;
  const m = useMission();
  const saved = m.investigations?.[fid]?.[cell.id] ?? {};
  const params = { ...Object.fromEntries(cell.params.map((p) => [p.name, p.default])), ...(saved.params ?? {}) } as Record<string, string | number>;
  const [phase, setPhase] = useState<"idle" | "submitting" | "pending" | "done">("idle");
  const [result, setResult] = useState<CellResult | null>(null);
  const [message, setMessage] = useState("");
  const [spl, setSpl] = useState(cell.spl ?? "");
  const live = useRef(0);
  const local = ctx.mode === "local";
  const ready = local || ctx.search_ready;
  useEffect(() => () => { live.current++; }, []);
  useEffect(() => { setSpl(cell.spl ?? ""); }, [cell.spl]);

  const save = (patch: Parameters<typeof updateInvestigationCell>[2]) => updateInvestigationCell(fid, cell.id, patch);
  const setParam = (name: string, value: string | number) => { live.current++; setResult(null); setPhase("idle"); setMessage(""); save({ params: { ...params, [name]: value } }); };
  const reset = () => { live.current++; setResult(null); setPhase("idle"); setMessage(""); save(null); };

  const record = (d: CellResult) => {
    const rs = d.rows ?? [];
    onRan?.();
    save({ ran: { at: new Date().toISOString(), runs: [ctx.origin.run_id], spl: d.spl ?? "", rows: rs.length, preview: rs.slice(0, 6).map((r) => r.join(" | ").slice(0, 160)), changed: [], truncated: Boolean(d.truncated) } });
  };
  const run = async () => {
    if (!ready) return;
    const mine = ++live.current;
    setResult(null); setMessage(""); setPhase("submitting");
    if (local) {
      const r = await api<CellResult>(exploreUrl(tab, fid, cell.id, win, params));
      if (mine !== live.current) return;
      setPhase("done");
      if (!r.ok) { setMessage(problem(r)); return; }
      setResult(r.data); record(r.data);
      return;
    }
    const sub = await post(cellRunUrl(fid, cell.id, win), { params });
    if (mine !== live.current) return;
    if (sub.status !== 202) { setPhase("done"); setMessage(problem(sub)); return; }
    setSpl(sub.data.spl);
    setPhase("pending");
    const until = Date.now() + 70000;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, 900));
      if (mine !== live.current) return;
      const r = await api<CellResult>(searchUrl(fid, sub.data.search_id, win));
      if (mine !== live.current) return;
      if (!r.ok) { setPhase("done"); setMessage(problem(r)); return; }
      if (r.data.status === "PENDING") continue;
      setResult(r.data); setPhase("done");
      if (r.data.status === "READY") record(r.data);
      else if (r.data.status === "UNAVAILABLE") setMessage(FAIL.backend_unavailable);
      else setMessage(FAIL[r.data.error ?? ""] ?? "The search failed.");
      return;
    }
    setPhase("done"); setMessage("No answer within 70 seconds. The search may still finish; run it again in a moment.");
  };

  const rows = result?.status === "READY" ? result.rows ?? [] : null;
  const cols = result?.columns ?? cell.columns;
  const busy = phase === "submitting" || phase === "pending";
  const state = cellState(ready, phase, result, message);
  const shownSpl = result?.spl ?? spl;

  return <section className="notebook-cell notebook-cell--open" aria-labelledby={`${cell.id}-h`}>
    <div className="cell-rail"><span>In [{index}]:</span><i /></div>
    <div className="cell-main">
      <div className="cell-question"><span>{local ? "Explore" : "Live search"} · {index}</span><h2 id={`${cell.id}-h`}>{cell.title}</h2></div>
      <p>{cell.question}</p>
      <div className="m-field m-nb-hypo"><label htmlFor={`${cell.id}-hypo`}>Before you run it: what do you expect to see? (saved in this browser)</label>
        <textarea id={`${cell.id}-hypo`} rows={2} maxLength={300} value={saved.hypothesis ?? ""} onChange={(e) => save({ hypothesis: e.target.value })} /></div>
      <div className="m-nb-params">{cell.params.map((p) => <div className="m-field" key={p.name}>
        <label htmlFor={`${cell.id}-${p.name}`}>{p.label}</label>
        {p.kind === "enum"
          ? <select id={`${cell.id}-${p.name}`} value={String(params[p.name])} onChange={(e) => setParam(p.name, e.target.value)}>{p.choices!.map((c) => <option key={c} value={c}>{p.choice_labels?.[c] ?? c}</option>)}</select>
          : <input id={`${cell.id}-${p.name}`} type="number" min={p.lo} max={p.hi} step={1} value={Number(params[p.name])} onChange={(e) => { const n = Math.trunc(Number(e.target.value)); if (Number.isFinite(n)) setParam(p.name, Math.min(p.hi!, Math.max(p.lo!, n))); }} />}
      </div>)}</div>
      {local
        ? <div className="query-block"><div><span>No search runs for this evidence class</span><Badge tone="muted">NO SPL</Badge></div><pre>{`The table below is read from the ${ctx.tab === "recorded" ? "committed recorded examples" : "synthetic test-fixture events"} held in memory by the Attack Service, filtered by the choices above. There is no Splunk search to copy.`}</pre></div>
        : <div className="query-block"><div><span>SPL that will run (built on the server from a fixed template; you cannot edit it)</span><Badge tone="observed">EXECUTES</Badge></div>
          <pre tabIndex={0} aria-label="Search that will run (read only)">{shownSpl || "Building the search…"}</pre></div>}
      <p className="m-muted">{local ? "Parameter changes apply when you press the button." : "The text above is for the default choices. After you run, it shows the exact search that was sent, with your choices."}</p>
      <div className="m-actions">
        <Button onClick={run} disabled={!ready || busy}>{busy ? "Running…" : local ? "Show the table" : "Run search"} <Icon name="play" size={15} /></Button>
        <Button variant="ghost" onClick={reset} disabled={busy}>Reset cell</Button>
        {!local && shownSpl && <CopyButton text={shownSpl} label="Copy the SPL" />}
        <span className={`m-nb-state m-nb-state--${state.replace(" ", "-")}`} role="status" aria-label={`Cell state: ${state}`}><Badge tone={state === "completed" ? "live" : state === "failed" || state === "unavailable" ? "deny" : "observed"}>{state.toUpperCase()}</Badge></span>
      </div>
      {!ready && <p className="m-error-text" role="status">{ctx.reasonNotReady ?? "Search access to Splunk is not set up on this lab, so nothing can be searched. Ask the lab owner to run ./agentsec splunk-access."}</p>}
      <div role="status" aria-live="polite" className="m-nb-status">
        {phase === "submitting" && (local ? "Reading the events…" : "Sending the search to the Attack Service…")}
        {phase === "pending" && "Waiting for Splunk to answer (usually a few seconds)…"}
        {message && <span className="m-error-text">{message}</span>}
        {result?.status === "READY" && rows!.length === 0 && (local ? "No event of this run matches those choices. That is not a pass: it only means this view found nothing." : "The search ran and returned no rows. Either nothing matched, or Splunk has not indexed this run yet. That is not a pass.")}
      </div>
      {rows && rows.length > 0 && <div className="m-nb-result"><div className="table-wrap"><table>
        <caption className="m-caption">{local ? "Read from events held in memory (no search ran)" : "Results from Splunk"} · {rows.length} row{rows.length === 1 ? "" : "s"}{result?.truncated ? ` (capped at ${result.row_cap})` : ""}{result?.duration_ms !== undefined ? ` · ${result.duration_ms} ms` : ""} · evidence: {result?.evidence_class ?? ctx.origin.evidence_class} · {result?.window ?? ctx.window}</caption>
        <thead><tr>{cols.map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i}>{r.map((v, j) => <td key={j}>{v}</td>)}</tr>)}</tbody></table></div>
        <ResultInsight cell={cell.id} cols={cols} rows={rows} />
        <p className="m-muted">A search result is evidence to explain, not a verdict. The finding's status comes from the assurance rules, not from this table.</p></div>}
      <details className="m-details"><summary>What this shows, and what it does not</summary>
        <div className="learning-note"><Icon name="book" size={18} /><div><p><strong>Shows:</strong> {cell.proves}</p><p><strong>Does not show:</strong> {cell.not_proves}</p><p><strong>Hint:</strong> {cell.hint}</p></div></div></details>
      <div className="m-field m-nb-note"><label htmlFor={`${cell.id}-note`}>What did you notice? (saved in this browser)</label>
        <textarea id={`${cell.id}-note`} rows={2} maxLength={500} value={saved.note ?? ""} onChange={(e) => save({ note: e.target.value })} /></div>
      <div className="m-field m-nb-note"><label htmlFor={`${cell.id}-concl`}>Your conclusion: what does this let you say, and what does it not? (saved in this browser only)</label>
        <textarea id={`${cell.id}-concl`} rows={2} maxLength={500} value={saved.conclusion ?? ""} onChange={(e) => save({ conclusion: e.target.value })} /></div>
    </div>
  </section>;
}

function ResultInsight({ cell, cols, rows }: { cell: string; cols: string[]; rows: string[][] }) {
  const ins = insight(cell, cols, rows);
  if (!ins) return null;
  const max = Math.max(1, ...ins.bars.map((b) => b.value));
  return <div className="as-insight"><h4>{ins.barsTitle}</h4>
    <ul className="m-bars" aria-label={`Bar chart: ${ins.barsTitle}`}>{ins.bars.map((b) => <li key={b.label}><span className="m-bars__label">{b.label}</span><span className="m-bars__track"><span className="m-bars__bar" style={{ width: `${(b.value / max) * 100}%` }} /></span><span className="m-bars__n">{b.value}</span></li>)}</ul>
    <div className="learning-note"><Icon name="book" size={18} /><div><strong>What these rows say</strong>{ins.sentences.map((t) => <p key={t}>{t}</p>)}<p className="m-muted">Read from the rows above only. The finding's status comes from the assurance rules.</p></div></div></div>;
}

export function AssuranceInvestigate({ tab, id, embedded = false, onRan }: { tab: AssuranceTab; id: string; embedded?: boolean; onRan?: () => void }) {
  const win: WindowKey = tab === "recorded" ? "all" : readWindow();
  const res = useLoad<Investigation>(investigationUrl(tab, id, win));
  const d = !res.loading && "data" in res ? res.data : null;
  const m = useMission();
  const back = <Link to={findingPath(tab, id)} className="as-study"><Icon name="chevron" size={14} /> Back to the finding</Link>;
  const head = (h: string) => <header className="page-header"><div><div className="eyebrow">Investigation notebook</div><h1>{h}</h1></div>{back}</header>;
  if (res.loading) return <div className="page as">{head("Loading…")}<p role="status" className="as-empty">Reading the evidence…</p></div>;
  if (!d) {
    const gone = "status" in res && res.status === 404;
    return <div className="page as">{head(gone ? "This finding is not in this view" : "The notebook could not be loaded")}
      <div className="as-state as-state--bad" role="alert"><p>{gone ? "The id may be old (the window moved or the data changed) or it belongs to another evidence class. Go back to the overview and open it again." : "Nothing is shown rather than a guess. Reload, or check that the Attack Service is running."}</p>
        <p><Link to={assuranceTabPath(tab)}>Back to the overview</Link></p></div></div>;
  }
  if (d.state === "unavailable") return <div className="page as">{head("Nothing was read")}<div className="as-state as-state--na"><p>{REASONS[d.reason ?? ""] ?? "Splunk could not be read."}</p>
    <p>The <Link to={assuranceTabPath("recorded")}>recorded examples</Link> do not need Splunk.</p></div></div>;
  const o = d.origin;
  const recorded = tab === "recorded";
  const ctx = { ...d, reasonNotReady: d.mode === "splunk" && !d.search_ready ? "Search access to Splunk is not set up on this lab, so nothing can be searched. There is no result and that is not a pass. Ask the lab owner to run ./agentsec splunk-access." : undefined };
  const earned = d.cells.filter((c) => (m.investigations?.[o.finding_id]?.[c.id]?.ran?.rows ?? 0) > 0).length;
  const goWorkshop = () => { if (o.lab_id) { if (o.adoptable) adoptRunForWorkshop(o.lab_id, o.mode, o.run_id); navigate(workshopPath(o.lab_id)); } };
  return <div className={embedded ? "as as-nb as-embedded" : "page as as-nb"}>
    {!embedded && <><header className="page-header"><div><div className="as-badges"><ClassBadge cls={o.evidence_class} /><StatusPill status={o.status} label={o.status_label} /><Badge>{o.mode} · {o.profile}</Badge></div>
      <div className="eyebrow">{recorded ? "Explore the evidence" : "Investigation notebook"}</div><h1>{o.title}</h1>
      <p className="as-lead">{recorded ? "A recorded example to study. It shows how a control behaved when it was captured." : "Read what the run recorded, cell by cell, then decide what to defend and retest."}</p></div>{back}</header>
    <Banner tab={tab} /></>}
    <section className="as-origin" aria-label="What you are investigating">
      <p>You are investigating <strong>{o.title.toLowerCase()}</strong> from {o.mode === "ATTACK" ? "an attack" : o.mode === "RETEST" ? "a retest" : "a baseline"} run{o.hop !== null ? `, at hop ${o.hop}` : ""}{o.control_id.startsWith("(") ? "" : `, guarded by ${o.control_id}`}.</p>
      <p className="as-muted">Source: {d.source} · {d.window}</p>
      <details><summary>Technical identifiers</summary>
        <dl className="as-ids"><div><dt>Finding</dt><dd><code>{o.finding_id}</code></dd></div><div><dt>Run</dt><dd><code>{o.run_id}</code></dd></div><div><dt>Control</dt><dd><code>{o.control_id}</code></dd></div>
          <div><dt>Hop</dt><dd>{o.hop ?? "not recorded (a finding about the whole run)"}</dd></div><div><dt>Attack id</dt><dd>{o.attack_id ?? "none"}</dd></div><div><dt>Evidence class</dt><dd>{o.evidence_class}</dd></div></dl></details>
    </section>
    <p className="as-progress" role="status">Discoveries: {earned} of {d.cells.length} cells have returned rows for this finding.</p>
    {d.cells.map((c, i) => <AssuranceSplCell key={`${o.finding_id}-${c.id}`} ctx={ctx} cell={c} index={i + 1} tab={tab} win={win} onRan={onRan} />)}
    {!embedded && <><section className="as-next" aria-labelledby="as-next-h"><h2 id="as-next-h">{recorded ? "What to try next" : "Defend and retest"}</h2>
      {recorded
        ? <p>Recorded examples cannot be defended or retested here, because nothing is running. Open the workshop to practise the same technique on your own lab, then return to the live view.</p>
        : tab === "fixtures" ? <p>A test fixture is synthetic data made to test the rules. It has no workshop to defend or retest in.</p>
          : <><p><strong>What to do:</strong> {d.next.defend}</p>{d.next.retest && <p><strong>How to retest:</strong> {d.next.retest}</p>}</>}
      <p className="as-muted">Retest status for this attack: {d.next.retest_outcome === "VALIDATED" ? "validated by a linked, verified-effective retest" : d.next.retest_outcome === "NOT_VALIDATED" ? "a retest exists but is not verified effective" : d.next.retest_outcome === "NO_RETEST" ? "no retest yet" : "not applicable to this run"}.</p>
      <div className="as-actions">
        {o.lab_id && tab !== "fixtures" && <Button onClick={goWorkshop} icon="arrow">{o.adoptable ? "Go to the workshop with this run" : "Open the workshop"}</Button>}
        {o.mode !== "BASELINE" && <LinkButton href={comparePath(tab, o.finding_id)} variant="secondary" internal>Compare with the retest</LinkButton>}
        <LinkButton href={findingPath(tab, o.finding_id, true)} variant="ghost" internal icon="search">Raw evidence</LinkButton>
      </div></section>
    <p className="as-muted">{TAB_LABEL[tab]} · notes are kept in this browser only and never count as evidence.</p></>}
  </div>;
}
