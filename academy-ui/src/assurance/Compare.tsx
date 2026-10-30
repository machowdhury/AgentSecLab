import { Badge, Icon, LinkButton } from "../ui";
import { Link, assuranceTabPath, findingPath, investigatePath, type AssuranceTab } from "../router";
import { REASONS, comparisonUrl, readWindow, useLoad, type CmpRow, type CmpSide, type Comparison, type WindowKey } from "./live";
import { Banner, ClassBadge, StatusPill } from "./liveParts";

const OUTCOME: Record<string, string> = {
  VALIDATED: "Validated: the linked retest was verified effective.",
  NOT_VALIDATED: "Not validated: a retest exists, but it is not verified effective.",
  NO_RETEST: "No retest yet.",
};

function Side({ s, label, tab }: { s: CmpSide; label: string; tab: AssuranceTab }) {
  return <div className="as-cmp__side"><h3>{label}</h3>
    <p><StatusPill status={s.status} byDesign={s.by_design && s.status === "VERIFIED_INEFFECTIVE"} label={s.status_label} /> <Badge>{s.mode} · {s.profile}</Badge></p>
    <p className="as-muted">{s.events ?? "?"} events · {s.complete === false ? "an INCOMPLETE sequence" : "a complete sequence"} · run <code>{s.run_id.slice(0, 8)}…</code></p>
    <Link to={findingPath(tab, s.finding_id)}>Open this finding</Link></div>;
}

const cell = (c: CmpRow["attack"]) => c === null
  ? <span className="as-muted">No decision by this control in this run</span>
  : <><strong>{c.decision}</strong> <span className="as-muted">{c.reason}</span><br />Handler {c.handler_started ? (c.executed ? "started and executed" : "started, did not execute") : "did not start"}</>;

export function AssuranceCompare({ tab, id }: { tab: AssuranceTab; id: string }) {
  const win: WindowKey = tab === "recorded" ? "all" : readWindow();
  const res = useLoad<Comparison>(comparisonUrl(tab, id, win));
  const d = !res.loading && "data" in res ? res.data : null;
  const recorded = tab === "recorded";
  const back = <Link to={findingPath(tab, id)} className="as-study"><Icon name="chevron" size={14} /> Back to the finding</Link>;
  const head = (h: string, lead?: string) => <header className="page-header"><div><div className="eyebrow">Retest comparison</div><h1>{h}</h1>{lead && <p className="as-lead">{lead}</p>}</div>{back}</header>;
  if (res.loading) return <div className="page as">{head("Loading…")}<p role="status" className="as-empty">Reading the evidence…</p></div>;
  if (!d) {
    const gone = "status" in res && res.status === 404;
    return <div className="page as">{head(gone ? "This finding is not in this view" : "The comparison could not be loaded")}
      <div className="as-state as-state--bad" role="alert"><p>{gone ? "The id may be old or it belongs to another evidence class. Go back to the overview and open it again." : "Nothing is shown rather than a guess."}</p><p><Link to={assuranceTabPath(tab)}>Back to the overview</Link></p></div></div>;
  }
  if (d.state === "unavailable") return <div className="page as">{head("Nothing was read")}<div className="as-state as-state--na"><p>{REASONS[d.reason ?? ""] ?? "Splunk could not be read."}</p></div></div>;
  if (d.kind === "none") return <div className="page as">{head("There is nothing to compare for this run")}<Banner tab={tab} /><div className="as-state"><p>{d.message}</p></div></div>;
  if (d.kind === "no_retest") return <div className="page as">{head("No retest to compare yet", recorded ? "In these recorded examples, no retest was captured for this attack." : undefined)}<Banner tab={tab} />
    <div className="as-state" role="status"><p>{d.message}</p><p><Badge>{OUTCOME[d.outcome ?? "NO_RETEST"]}</Badge></p>
      {!recorded && <p>Apply the defense in the workshop, then run the same attack again as a RETEST; it will appear here once Splunk holds it.</p>}</div>
    <div className="as-actions"><LinkButton href={investigatePath(tab, id)} variant="secondary" internal>{recorded ? "Explore the evidence" : "Back to the notebook"}</LinkButton></div></div>;
  const att = d.attack!, ret = d.retest!;
  return <div className="page as as-cmp">
    {head(recorded ? "Attack and retest, side by side" : d.comparable ? OUTCOME[d.outcome ?? ""] ?? "Attack and retest" : "The retest evidence is incomplete",
      recorded ? "A recorded pair to study. It shows what happened when it was captured, not your lab's current state." : "What each run recorded for this control, per hop. The outcome is the assurance rules', not this page's.")}
    <div className="as-badges"><ClassBadge cls={d.evidence_class} /><Badge tone="muted">Outcome by the rules: {d.outcome}</Badge></div>
    <Banner tab={tab} />
    {d.notes!.map((n) => <p key={n} className="as-gapnote" role="note">{n}</p>)}
    <div className="as-cmp__sides"><Side s={att} label="Attack run" tab={tab} /><Side s={ret} label="Retest run (defended)" tab={tab} /></div>
    <div className="table-wrap"><table className="as-table as-cmp__table"><caption className="m-caption">What {d.control_id} recorded in each run, per hop</caption>
      <thead><tr><th scope="col">Hop</th><th scope="col">Attack run</th><th scope="col">Retest run</th></tr></thead>
      <tbody>{d.rows!.length ? d.rows!.map((r) => <tr key={r.hop}><th scope="row">{r.hop}</th><td data-label="Attack run">{cell(r.attack)}</td><td data-label="Retest run">{cell(r.retest)}</td></tr>)
        : <tr><td colSpan={3}>Neither run recorded a decision by this control, so there is nothing to compare per hop.</td></tr>}</tbody></table></div>
    <p className="as-muted">A different decision is something to explain, not proof that the defense caused it: the model also varies between runs. No effectiveness figure is computed here.</p>
    <details className="m-details"><summary>How this comparison is built</summary><ul className="as-list as-list--plain">{d.how!.map((h) => <li key={h}>{h}</li>)}</ul></details>
    <div className="as-actions"><LinkButton href={investigatePath(tab, id)} variant="secondary" internal>{recorded ? "Explore the evidence" : "Back to the notebook"}</LinkButton><LinkButton href={findingPath(tab, id, true)} variant="ghost" internal icon="search">Raw evidence</LinkButton></div>
  </div>;
}
