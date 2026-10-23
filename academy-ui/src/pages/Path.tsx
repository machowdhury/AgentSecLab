import { Badge, Icon } from "../ui";
import { StageGuide } from "../StageGuide";
import { FOUNDATIONS_PATH, Link, MASTERY_PATH, MCP_PATH, missionPath } from "../router";
import { firstOpenIncomplete, gateReason, stageComplete, useMission } from "../store";
import { STAGES } from "../stages";
import { useRunViews } from "../runs";
import { ALL_CELLS } from "../mission/notebooks";
import { evidenceText, SEC_LABEL } from "../mission/content";
import { QUIZ } from "../mission/content";
import content from "../content/academy-content.json";

// Progress and evidence history, built only from this browser's mission state and the real run views. No scores or badges are invented.
export function Path() {
  const m = useMission();
  const ids = [m.runs.attack, m.runs.retest].filter(Boolean) as string[];
  const views = useRunViews(ids);
  const done = STAGES.filter((s) => stageComplete(s.id, m)).length;
  const next = firstOpenIncomplete(m);
  const searches = ALL_CELLS.map((c) => ({ c, r: m.notebook?.[c.id]?.ran })).filter((x) => x.r);
  const read = (m.foundationsRead ?? []).length, mcq = m.mastery?.mcq ?? {};
  const answered = QUIZ.filter((q) => mcq[q.id]).length, correct = QUIZ.filter((q) => mcq[q.id] === q.answer).length;
  const runRows = [["Baseline attack", m.runs.attack], ["Defended retest", m.runs.retest]] as const;
  return <div className="page">
    <header className="page-header"><div><div className="eyebrow">Your path</div><h1>Your progress and evidence</h1>
      <p>Everything here comes from your own runs and answers in this browser. Nothing is a score you did not earn.</p></div></header>
    <StageGuide learning="Where you are in the Loan Desk mission and what evidence you have produced."
      todo="Continue the mission, or review a run's evidence."
      happened={`${done} of ${STAGES.length} stages done · ${ids.length} run${ids.length === 1 ? "" : "s"} · ${searches.length} Splunk search${searches.length === 1 ? "" : "es"} recorded.`}
      next={done === STAGES.length ? "Review your record in Explain, or test yourself in Mastery." : `Continue with the ${STAGES.find((s) => s.id === next)!.label} stage.`} />
    <section className="m-section" aria-labelledby="h-path-mission"><div className="lesson-label">Loan Desk mission</div><h2 id="h-path-mission">Seven stages</h2>
      <p className="m-muted">Three different facts: a stage you <strong>visited</strong>, a stage you <strong>completed</strong> (you produced its result), and <strong>evidence verified</strong> by the host verifier. Navigating or completing a stage never means evidence was verified.</p>
      <ol className="m-pathlist">{STAGES.map((s) => { const ok = stageComplete(s.id, m), lock = gateReason(s.id, m), seen = m.seen.includes(s.id);
        const run = s.id === "attack" || s.id === "investigate" ? m.runs.attack : s.id === "retest" ? m.runs.retest : undefined;
        const v = run ? views[run] : undefined;
        const ev = !run ? "no evidence at this stage" : !v ? (v === null ? "run unknown to the service" : "no verification yet") : v.evidence.indexed_status === "SPLUNK_VERIFIED" ? "SPLUNK-VERIFIED" : "not verified";
        return <li key={s.id} className={ok ? "is-done" : ""}><Icon name={ok ? "check" : lock ? "clock" : "arrow"} size={16} />
          {lock && !ok ? <span>{s.label} <small>(locked: {lock})</small></span> : <Link to={missionPath(s.id)}>{s.label}</Link>}
          <span className="m-chips"><Badge tone={seen ? "observed" : "muted"}>{seen ? "VISITED" : "NOT VISITED"}</Badge><Badge tone={ok ? "allow" : "muted"}>{ok ? "COMPLETED" : "NOT COMPLETED"}</Badge><Badge tone={ev === "SPLUNK-VERIFIED" ? "indexed" : "muted"}>{ev === "SPLUNK-VERIFIED" ? ev : `EVIDENCE: ${ev.toUpperCase()}`}</Badge></span></li>; })}</ol>
      <div className="m-actions"><Link className="button button--primary" to={missionPath(next)}>{done ? "Continue the mission" : "Start the mission"} <Icon name="arrow" size={15} /></Link></div>
    </section>
    <section className="m-section" aria-labelledby="h-path-evidence"><div className="lesson-label">Evidence history</div><h2 id="h-path-evidence">Your runs</h2>
      <div className="table-wrap"><table><caption className="m-caption">Runs launched from this browser, read live from the Loan Desk</caption>
        <thead><tr><th scope="col">Run</th><th scope="col">Id</th><th scope="col">Outcome</th><th scope="col">Evidence</th></tr></thead>
        <tbody>{runRows.map(([label, id]) => { const v = id ? views[id] : undefined; return <tr key={label}>
          <th scope="row">{label}</th><td>{id ? <code>{id}</code> : "Not run yet"}</td>
          <td>{!id ? "—" : v === undefined ? "Loading…" : v === null ? "The service no longer knows this run (it restarted)." : <><Badge tone={v.outcomes?.security.outcome === "BLOCKED" ? "deny" : "muted"}>{v.outcomes ? SEC_LABEL[v.outcomes.security.outcome] ?? v.outcomes.security.outcome : "NO OUTCOME YET"}</Badge> {v.status}</>}</td>
          <td>{v ? `${v.evidence.event_count} local events. ${evidenceText(v)}` : "—"}</td></tr>; })}</tbody></table></div>
      {searches.length > 0 ? <ul className="m-pathlist">{searches.map(({ c, r }) => <li key={c.id}><Icon name="search" size={16} /><span>{c.title}</span><small>{r!.rows} row{r!.rows === 1 ? "" : "s"} · {new Date(r!.at).toLocaleString()}</small></li>)}</ul>
        : <p className="m-muted">No Splunk searches run yet. They appear here after you run them in Investigate or Retest.</p>}
      {searches.length > 0 && <div className="m-actions"><Link className="button button--secondary" to={missionPath("explain")}>See the full record in Explain</Link></div>}
    </section>
    <section className="m-section" aria-labelledby="h-path-learn"><div className="lesson-label">Learning</div><h2 id="h-path-learn">Foundations and Mastery</h2>
      <ul className="m-pathlist">
        <li><Icon name="book" size={16} /><Link to={FOUNDATIONS_PATH}>AI &amp; Agent Foundations</Link><small>{read} of {content.foundations.length} lessons marked read</small></li>
        <li><Icon name="chart" size={16} /><Link to={MASTERY_PATH}>Mastery</Link><small>{answered ? `${correct} of ${answered} Loan Desk questions correct` : "Not started"}</small></li>
        <li><Icon name="shield" size={16} /><Link to={MCP_PATH}>MCP Tool Authorization</Link><small>{m.mcp?.retest ? "Attack and retest run" : m.mcp?.attack ? "Attack run; retest not run yet" : m.mcp?.locked ? "Prediction locked" : "Not started"}</small></li>
      </ul>
    </section>
  </div>;
}
