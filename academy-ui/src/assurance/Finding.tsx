import { useCallback } from "react";
import { Badge, Button, Icon, LinkButton } from "../ui";
import { Link, MCP_PATH, assuranceTabPath, comparePath, findingPath, investigatePath, labPath, missionPath, navigate, type AssuranceTab } from "../router";
import { adoptRunForWorkshop } from "../store";
import { REASONS, TAB_LABEL, findingUrl, readWindow, useLoad, type Detail } from "./live";
import { Banner, ClassBadge, CopyButton, Drawer, ProvenanceBar, StatusPill } from "./liveParts";

const workshopPath = (lab: string) => (lab === "LAB-LOANDESK-001" ? missionPath() : lab === "LAB-MCP-001" ? MCP_PATH : labPath(lab));

function Timeline({ d }: { d: Detail }) {
  const items: { key: string; kind: "event" | "gap" | "open"; label: string; sub?: string; bad?: boolean; focus?: boolean }[] = [];
  let prev = 0;
  for (const t of d.timeline ?? []) {
    if (typeof t.sequence === "number" && t.sequence > prev + 1) items.push({ key: `gap-${prev}`, kind: "gap", label: `${t.sequence - prev - 1} event${t.sequence - prev - 1 === 1 ? "" : "s"} missing` });
    if (typeof t.sequence === "number") prev = t.sequence;
    items.push({ key: `e-${t.sequence}-${t.name}`, kind: "event", label: `${t.sequence ?? "?"} ${t.name}`, sub: t.decision ?? (t.executed ? "executed" : undefined), bad: t.executed === true, focus: t.focus });
  }
  if (d.run && !d.run.terminal) items.push({ key: "open", kind: "open", label: "no completion event" });
  return <ol className="as-timeline" aria-label="Events of this run, in order">{items.map((i) =>
    <li key={i.key} className={`as-tl as-tl--${i.kind} ${i.bad ? "is-bad" : ""} ${i.focus ? "is-focus" : ""}`}><span className="as-tl__dot" aria-hidden="true" /><span className="as-tl__l">{i.label}</span>{i.sub && <span className="as-tl__s">{i.sub}</span>}</li>)}</ol>;
}

function Raw({ d, onClose }: { d: Detail; onClose: () => void }) {
  const f = d.finding!;
  const all = JSON.stringify((d.events ?? []).map((e) => { try { return JSON.parse(e.json); } catch { return e.json; } }), null, 1);
  return <Drawer title="Raw evidence" onClose={onClose}>
    <p className="as-muted">Events of run <code>{f.run_id}</code> as indexed, in order. Read only. Event text is untrusted data: it is shown as text and never run.</p>
    <div className="m-actions"><CopyButton text={all} label="Copy all events (JSON)" /></div>
    {d.missing_sequences!.length > 0 && <p className="as-gapnote" role="note">Sequence numbers missing from the record: {d.missing_sequences!.join(", ")}. These events were not found; nothing is filled in.</p>}
    <ul className="as-events">{d.events!.map((e) => <li key={`${e.sequence}-${e.name}`}><details><summary><span>{e.sequence ?? "?"}</span> <code>{e.name}</code>{e.hop !== null && <small> hop {e.hop}</small>}</summary>
      <pre tabIndex={0} aria-label={`JSON of event ${e.sequence}`}>{e.json}</pre>{e.truncated && <p className="as-muted">Shown up to the size limit; the full event is in Splunk.</p>}<CopyButton text={e.json} label="Copy this event" /></details></li>)}</ul>
    {d.events_truncated && <p className="as-muted">Only the first {d.events!.length} events are shown.</p>}
    <h3>The search that finds these events</h3><pre className="as-spl" tabIndex={0} aria-label="Search used (read only)">{f.spl}</pre>
    <div className="m-actions"><CopyButton text={f.spl} label="Copy the search" /></div>
    <p className="as-muted">The search is printed, not run here. Run it in Splunk with your own login if you want to see the same events there.</p>
  </Drawer>;
}

export function AssuranceFinding({ tab, id, evidence }: { tab: AssuranceTab; id: string; evidence: boolean }) {
  const win = tab === "recorded" ? "all" : readWindow();
  const res = useLoad<Detail>(findingUrl(tab, id, win));
  const d = !res.loading && "data" in res ? res.data : null;
  const close = useCallback(() => navigate(findingPath(tab, id)), [tab, id]);
  const back = <Link to={assuranceTabPath(tab)} className="as-study"><Icon name="chevron" size={14} /> Back to the overview</Link>;
  if (res.loading) return <div className="page as"><header className="page-header"><div><div className="eyebrow">Finding</div><h1>Loading…</h1></div></header><p role="status" className="as-empty">Reading the evidence…</p></div>;
  if (!d) {
    const gone = "status" in res && res.status === 404;
    return <div className="page as"><header className="page-header"><div><div className="eyebrow">Finding</div><h1>{gone ? "This finding is not in this view" : "This finding could not be loaded"}</h1></div>{back}</header>
      <div className="as-state as-state--bad" role="alert"><p>{gone ? "The id may be old (the window moved, or the data changed), or it belongs to another evidence class. Go back and open it from the overview." : "Nothing is shown rather than a guess."}</p></div></div>;
  }
  if (d.state === "unavailable") return <div className="page as"><header className="page-header"><div><div className="eyebrow">Finding</div><h1>Nothing was read</h1></div>{back}</header><div className="as-state as-state--na"><p>{REASONS[d.reason ?? ""] ?? "Splunk could not be read."}</p></div></div>;
  const f = d.finding!, w = d.workshop!;
  const goWorkshop = () => { if (w.lab_id) { if (w.adoptable) adoptRunForWorkshop(w.lab_id, w.mode, w.run_id); navigate(workshopPath(w.lab_id)); } };
  const rows: [string, string, ReturnType<typeof Object>?][] = [
    ["What happened", f.observation], ["What it means", f.interpretation], ["Why it matters", f.impact],
    ["Evidence", `${d.run!.events} event${d.run!.events === 1 ? "" : "s"} in this run, ${d.run!.complete ? "a complete sequence" : "an INCOMPLETE sequence"}${d.run!.duplicates ? `, ${d.run!.duplicates} duplicate event(s) ignored` : ""}. Evidence class ${f.evidence_class}. Judged by rule ${f.rule_id}. Confidence: ${f.confidence}.`],
    ["Control", f.control_id.startsWith("(") ? `This is a finding about the whole run: no single control was involved. ${f.control_interpretation}` : `${f.control_id}${f.control_name && f.control_name !== f.control_id ? ` (${f.control_name})` : ""}, ${f.control_class || "class not recorded"}${f.boundary ? `, trust boundary ${f.boundary}` : ""}. ${f.control_interpretation}`],
    ["What to do", `${f.recommended_action}${f.retest_check ? ` Retest: ${f.retest_check}` : ""}`],
  ];
  const rt = f.retest as { outcome: string; run_id: string | null };
  return <div className="page as">
    <header className="page-header"><div><div className="as-badges"><StatusPill status={f.status} byDesign={f.by_design && f.status === "VERIFIED_INEFFECTIVE"} label={f.status_label} /><ClassBadge cls={f.evidence_class} /><Badge>{f.mode} · {f.profile}</Badge></div>
      <h1>{f.title}</h1><p className="as-lead">{f.attack_id ?? "no attack id"} · <code>{f.control_id}</code>{f.hop !== null ? ` · hop ${f.hop}` : ""} · run <code>{f.run_id}</code></p></div>{back}</header>
    <Banner tab={tab} />
    <Timeline d={d} />
    <div className="as-actions">
      <LinkButton href={investigatePath(tab, id)} internal icon="arrow">{tab === "live" ? "Investigate in the notebook" : "Explore the evidence"}</LinkButton>
      <LinkButton href={findingPath(tab, id, true)} variant="secondary" internal icon="search">Raw evidence</LinkButton>
      {f.mode !== "BASELINE" && <LinkButton href={comparePath(tab, id)} variant="secondary" internal>Compare with the retest</LinkButton>}
      {w.lab_id && <Button variant="secondary" onClick={goWorkshop} icon="arrow">{w.adoptable ? "Go to the workshop with this run" : "Open the workshop"}</Button>}
    </div>
    {tab !== "live" && w.lab_id && <p className="as-muted">{tab === "recorded" ? "This is a recorded run: the workshop opens without it, because a recording is not a run you launched." : "A test fixture is not a run in any workshop."}</p>}
    <dl className="as-seven">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
      <div><dt>Retest</dt><dd>{f.mode !== "ATTACK" ? "Not applicable: this run is not an attack." : rt.outcome === "VALIDATED" ? <>Validated: a linked retest was verified effective{d.linked_retest ? <> (run <code>{d.linked_retest.run_id}</code>, <Link to={findingPath(tab, d.linked_retest.finding_id)}>open that finding</Link>)</> : null}.</> : rt.outcome === "NOT_VALIDATED" ? <>Not validated: a retest exists (run <code>{rt.run_id}</code>) but it is not verified effective{d.linked_retest ? <>, <Link to={findingPath(tab, d.linked_retest.finding_id)}>open it</Link></> : null}.</> : "No retest yet for this attack, control and evidence class. A recorded retest never validates a live attack."}</dd></div></dl>
    {d.provenance && <ProvenanceBar p={d.provenance} tabLabel={TAB_LABEL[tab]} windowLabel={tab === "recorded" ? "committed examples" : "this run's events"} />}
    {evidence && <Raw d={d} onClose={close} />}
  </div>;
}
