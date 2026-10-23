import { useEffect, useRef, useState } from "react";
import { Badge, Button, Icon } from "../ui";
import { api, post } from "../api";
import { useConfig } from "../config";
import { updateMission, useMission, type NotebookRan } from "../store";
import { splunkSearchUrl } from "./content";
import { CopyButton, QueueBlock } from "./parts";
import { evidenceText } from "./content";
import { useVerify } from "./runStore";
import { useSlot } from "./runStore";
import type { CellConfig } from "./notebooks";

type ParamSpec = { name: string; kind: "int" | "enum"; default: string | number; label: string; lo?: number; hi?: number; choices?: string[] };
type TemplateSpec = { id: string; title: string; params: ParamSpec[]; chart: string | null };
type Result = { status: string; columns?: string[]; rows?: string[][]; truncated?: boolean; row_cap?: number; duration_ms?: number; error?: string; detail?: string; spl?: string; backend?: string; params?: Record<string, string | number> };
type Phase = "idle" | "submitting" | "pending" | "done";

const BASE = "/api/missions/loan-desk";
let catalog: Promise<Record<string, TemplateSpec>> | null = null;
const loadCatalog = () => (catalog ??= api(`${BASE}/search/templates`).then((r) => {
  if (!r.ok) { catalog = null; return {}; }
  return Object.fromEntries((r.data.templates as TemplateSpec[]).map((t) => [t.id, t]));
}));

const FAIL: Record<string, string> = {
  timeout: "The search took too long and was stopped. Try fewer rows, or open it in Splunk.",
  search_failed: "Splunk could not run this search. Check that Splunk is up, then retry.",
  backend_unavailable: "The host cannot reach Splunk right now.",
  refused: "The host verifier refused this search because the template or a parameter was not allowed.",
};

function problem(res: { status: number; data: any }): string {
  const e = res.data?.error;
  if (res.status === 503 && e === "not_installed") return "Live searches need the host verifier, and it is not installed on this lab. The SPL below still works in Splunk.";
  if (res.status === 429) return "Too many searches in a short time. Wait a few seconds and run it again.";
  if (res.status === 404) return "This service no longer knows that run (it may have restarted). Launch the attack again.";
  if (res.status === 0) return "The Attack Service could not be reached.";
  return res.data?.detail || `Unexpected response (HTTP ${res.status}).`;
}

const diffCols = (cols: string[]) => { const b = cols.indexOf("baseline"), d = cols.indexOf("defended"); return b >= 0 && d >= 0 ? [b, d] as const : null; };
/** Rows whose baseline and defended values differ. Computed from the returned rows only. */
export function changedRows(cols: string[], rows: string[][]): string[][] {
  const dc = diffCols(cols);
  return dc ? rows.filter((r) => r[dc[0]] !== r[dc[1]]) : [];
}

export function SplCell({ cell, index }: { cell: CellConfig; index: number }) {
  const { config } = useConfig();
  const m = useMission();
  const view = useSlot("attack").view;
  const retestView = useSlot("retest").view;
  const runId = view?.run_id ?? m.runs.attack;
  const compareRun = cell.compare ? (retestView?.run_id ?? m.runs.retest) : undefined;
  const ready = Boolean(runId && (!cell.compare || compareRun));
  const body = (extra: object = {}) => ({ template: cell.template, params, ...(compareRun ? { compare_run: compareRun } : {}), ...extra });
  const [spec, setSpec] = useState<TemplateSpec | null>(null);
  const [spl, setSpl] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<Result | null>(null);
  const [message, setMessage] = useState("");
  const live = useRef(0);
  const saved = m.notebook?.[cell.id] ?? {};
  const params = { ...Object.fromEntries((spec?.params ?? []).map((p) => [p.name, p.default])), ...(saved.params ?? {}) };
  const keyOf = JSON.stringify(params);

  useEffect(() => { loadCatalog().then((c) => setSpec(c[cell.template] ?? null)); }, [cell.template]);
  useEffect(() => {  // the exact SPL for the current parameters, built by the server (never composed in the browser)
    if (!ready || !spec) { setSpl(""); return; }
    let stale = false;
    post(`${BASE}/runs/${runId}/search/preview`, body()).then((r) => { if (!stale) setSpl(r.ok ? r.data.spl : ""); if (!stale && !r.ok) setMessage(problem(r)); });
    return () => { stale = true; };
  }, [runId, compareRun, spec, cell.template, keyOf]);
  useEffect(() => () => { live.current++; }, []);

  const save = (patch: Partial<{ params: Record<string, string | number>; scratch: string; note: string }>) =>
    updateMission((s) => ({ ...s, notebook: { ...s.notebook, [cell.id]: { ...s.notebook?.[cell.id], ...patch } } }));
  const setParam = (name: string, value: string | number) => { setResult(null); setPhase("idle"); setMessage(""); save({ params: { ...params, [name]: value } }); };
  const reset = () => { live.current++; setResult(null); setPhase("idle"); setMessage(""); updateMission((s) => { const nb = { ...s.notebook }; delete nb[cell.id]; return { ...s, notebook: nb }; }); };

  const record = (d: Result) => {
    const rs = d.rows ?? [], cs = d.columns ?? [];
    const changed = changedRows(cs, rs).map((r) => r.join(" | ").slice(0, 160));
    const ran: NotebookRan = { at: new Date().toISOString(), runs: [runId!, ...(compareRun ? [compareRun] : [])], spl: d.spl ?? spl, rows: rs.length, preview: rs.slice(0, 6).map((r) => r.join(" | ").slice(0, 160)), changed, truncated: Boolean(d.truncated) };
    updateMission((s) => ({ ...s, notebook: { ...s.notebook, [cell.id]: { ...s.notebook?.[cell.id], ran } } }));
  };
  const run = async () => {
    if (!ready) return;
    const mine = ++live.current;
    setResult(null); setMessage(""); setPhase("submitting");
    const sub = await post(`${BASE}/runs/${runId}/search`, body());
    if (mine !== live.current) return;
    if (sub.status !== 202) { setPhase("done"); setMessage(problem(sub)); return; }
    setPhase("pending");
    const searchId = sub.data.search_id as string;
    const until = Date.now() + 70000;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, 900));
      if (mine !== live.current) return;
      const r = await api<Result>(`${BASE}/runs/${runId}/search/${searchId}`);
      if (mine !== live.current) return;
      if (!r.ok) { setPhase("done"); setMessage(problem(r)); return; }
      if (r.data.status === "PENDING") continue;
      setResult(r.data); setPhase("done");
      if (r.data.status === "READY") record(r.data);
      if (r.data.status === "VERIFIER_OFFLINE") setMessage("The host verifier is not running, so nothing can search Splunk for you. Run the SPL in Splunk yourself.");
      else if (r.data.status === "TIMED_OUT") setMessage("The host verifier did not answer in time. Try again.");
      else if (r.data.status === "UNAVAILABLE") setMessage(r.data.detail || "Search results are unavailable.");
      else if (r.data.status === "FAILED") setMessage(FAIL[r.data.error ?? ""] ?? "The search failed.");
      return;
    }
    setPhase("done"); setMessage("No answer within 70 seconds. The search may still finish; run it again in a moment.");
  };

  const rows = result?.status === "READY" ? result.rows ?? [] : null;
  const cols = result?.columns ?? [];
  const dc = diffCols(cols);
  const changed = rows && dc ? changedRows(cols, rows) : [];
  const nums = rows && spec?.chart === "bar" ? rows.map((r) => Number(r[1])).filter((n) => Number.isFinite(n)) : [];
  const max = Math.max(1, ...nums);
  const total = rows && cols[1] === "events" ? rows.reduce((a, r) => a + (Number(r[1]) || 0), 0) : null;
  const local = view?.evidence.event_count;
  const scratch = saved.scratch ?? spl;
  const verA = useVerify("attack"), verR = useVerify("retest");
  const status = cell.compare
    ? `Verification: baseline ${verA.text || (view ? evidenceText(view) : "no run")} | defended ${verR.text || (retestView ? evidenceText(retestView) : "no run")}`
    : `Verification: ${verA.text || (view ? evidenceText(view) : "no run")}`;
  const busy = phase === "submitting" || phase === "pending";

  return <section className="notebook-cell notebook-cell--open" aria-labelledby={`${cell.id}-h`}>
    <div className="cell-rail"><span>In [{index}]:</span><i /></div>
    <div className="cell-main">
      <div className="cell-question"><span>Live search · {index}</span><h2 id={`${cell.id}-h`}>{cell.title}</h2></div>
      <p>{cell.question}</p>
      <div className="m-nb-params">
        {(spec?.params ?? []).map((p) => <div className="m-field" key={p.name}>
          <label htmlFor={`${cell.id}-${p.name}`}>{p.label}</label>
          {p.kind === "enum"
            ? <select id={`${cell.id}-${p.name}`} value={String(params[p.name])} onChange={(e) => setParam(p.name, e.target.value)}>{p.choices!.map((c) => <option key={c}>{c}</option>)}</select>
            : <input id={`${cell.id}-${p.name}`} type="number" min={p.lo} max={p.hi} step={1} value={Number(params[p.name])} onChange={(e) => { const n = Math.trunc(Number(e.target.value)); if (Number.isFinite(n)) setParam(p.name, Math.min(p.hi!, Math.max(p.lo!, n))); }} />}
        </div>)}
      </div>
      <div className="query-block"><div><span>SPL that will run (built on the server from a fixed template)</span><Badge tone="observed">EXECUTES</Badge></div><pre>{spl || (ready ? "Building the search…" : cell.compare ? "Finish the Attack and the Retest first. This search compares your two real runs." : "Launch the attack first. The search is bound to your real run id.")}</pre></div>
      <div className="m-actions">
        <Button onClick={run} disabled={!ready || !spl || busy}>{busy ? "Running…" : "Run search"} <Icon name="play" size={15} /></Button>
        <Button variant="ghost" onClick={reset} disabled={busy}>Reset cell</Button>
        {spl && <a className="button button--secondary" href={splunkSearchUrl(config.urls.splunk_web, spl)} target="_blank" rel="noopener">Open in Splunk <Icon name="arrow" size={15} /></a>}
      </div>
      <p className="m-muted m-nb-runs">{cell.compare ? <>Baseline run <code>{runId ?? "—"}</code> · Defended run <code>{compareRun ?? "—"}</code></> : <>Run <code>{runId ?? "—"}</code></>} · {status}</p>
      <div role="status" aria-live="polite" className="m-nb-status">
        {phase === "submitting" && "Sending the search to the host verifier…"}
        {phase === "pending" && "Waiting for the host verifier to search Splunk (usually a few seconds)…"}
        {message && <span className="m-error-text">{message}</span>}
        {result?.status === "READY" && rows!.length === 0 && "The search ran and returned no rows. Either nothing matched this run, or Splunk has not indexed it yet."}
      </div>
      {rows && rows.length > 0 && <div className="m-nb-result">
        <div className="table-wrap"><table>
          <caption className="m-caption">Results from Splunk for run <code>{runId}</code> · {rows.length} row{rows.length === 1 ? "" : "s"}{result?.truncated ? ` (capped at ${result.row_cap})` : ""} · {result?.duration_ms ?? 0} ms</caption>
          <thead><tr>{cols.map((c) => <th scope="col" key={c}>{c}</th>)}{dc && <th scope="col">Changed?</th>}</tr></thead>
          <tbody>{rows.map((r, i) => { const diff = dc ? r[dc[0]] !== r[dc[1]] : false; return <tr key={i} className={diff ? "is-different" : ""}>{r.map((v, j) => <td key={j}>{v}</td>)}{dc && <td>{diff ? "changed" : "same"}</td>}</tr>; })}</tbody>
        </table></div>
        {spec?.chart === "bar" && nums.length === rows.length && <ul className="m-bars" aria-label="Bar chart of the results above">
          {rows.map((r, i) => <li key={i}><span className="m-bars__label">{r[0]}</span><span className="m-bars__track"><span className="m-bars__bar" style={{ width: `${(nums[i] / max) * 100}%` }} /></span><span className="m-bars__n">{r[1]}</span></li>)}
        </ul>}
        {dc && <div className="m-diff" role="status"><strong>Where the two runs differ</strong>
          {changed.length ? <ul>{changed.map((r, i) => <li key={i}>{cols.slice(0, dc[0]).map((c, k) => `${c}: ${r[k]}`).join(", ")} — baseline {r[dc[0]]}, defended {r[dc[1]]}</li>)}</ul> : <p>No row differs between the two runs in this search.</p>}
          <p className="m-muted">A difference is something to explain, not proof that the defense caused it: the model also varies between runs.</p></div>}
        {cell.showQueue && view && <div className="m-queue-correlate"><strong>The ticket AcmeBank reports in the underwriter queue for this run</strong><QueueBlock view={view} /></div>}
        <p className="m-muted">
          {total !== null && local !== undefined ? <>These rows add up to <strong>{total}</strong> indexed events{result?.truncated ? " (more rows exist beyond the cap)" : ""}; AcmeBank emitted <strong>{local}</strong> locally. </> : null}
          This count is your own observation. Only the host verifier's receipt makes a run SPLUNK-VERIFIED.
        </p>
      </div>}
      <div className="learning-note"><Icon name="book" size={18} /><div><strong>What this proves, and what it does not</strong>
        <p><strong>Proves:</strong> {cell.proves}</p><p><strong>Does not prove:</strong> {cell.notProves}</p><p><strong>Hint:</strong> {cell.hint}</p></div></div>
      <div className="m-field m-nb-note"><label htmlFor={`${cell.id}-note`}>What did you notice? (saved in this browser; shown in your investigation record)</label>
        <textarea id={`${cell.id}-note`} rows={2} maxLength={500} value={saved.note ?? ""} onChange={(e) => save({ note: e.target.value })} /></div>
      <details className="m-scratch">
        <summary>Advanced SPL scratchpad <Badge>NOT EXECUTED HERE</Badge></summary>
        <p className="m-muted">Edit freely. Nothing typed here is ever run by the Academy. Copy it, or open it in Splunk and sign in there.</p>
        <label htmlFor={`${cell.id}-scratch`} className="visually-hidden">Scratchpad SPL (not executed here)</label>
        <textarea id={`${cell.id}-scratch`} rows={5} spellCheck={false} value={scratch} onChange={(e) => save({ scratch: e.target.value })} />
        <div className="m-actions"><CopyButton text={scratch} label="Copy scratchpad" /><a className="button button--secondary" href={splunkSearchUrl(config.urls.splunk_web, scratch)} target="_blank" rel="noopener">Open scratchpad in Splunk <Icon name="arrow" size={15} /></a></div>
      </details>
    </div>
  </section>;
}

/** Evidence-backed milestones: a cell earns its milestone only after a real search returned rows for the learner's current run(s). */
export function Milestones({ cells }: { cells: CellConfig[] }) {
  const m = useMission();
  const attack = m.runs.attack, retest = m.runs.retest;
  const earned = (c: CellConfig) => { const r = m.notebook?.[c.id]?.ran; return Boolean(r && r.rows > 0 && r.runs[0] === attack && (!c.compare || r.runs[1] === retest)); };
  const n = cells.filter(earned).length;
  return <section className="m-milestones" aria-label="Investigation milestones"><strong>Discoveries {n} of {cells.length}</strong>
    <ul>{cells.map((c) => <li key={c.id} className={earned(c) ? "is-earned" : ""}><Icon name={earned(c) ? "check" : "search"} size={15} /><span>{c.milestone}</span><span className="visually-hidden">{earned(c) ? " (found in your results)" : " (not yet found)"}</span></li>)}</ul></section>;
}
