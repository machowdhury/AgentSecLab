import { SplunkLink } from "../config";
import { useEffect, useRef, useState } from "react";
import { Badge, Button, Icon } from "../ui";
import { updateMission, useMission } from "../store";
import { StepList } from "../mission/RunProgress";
import { Callout, CopyButton } from "../mission/parts";
import type { Lab } from "../curriculum";
import { compareRuns, launchLab, probeEvidence, type Evidence, type LaunchError } from "./launch";
import { Err, Launch, MODE, Step, useRuns, type Slot } from "./PiWorkbench";
import { asS, type SRecord, type Scenario } from "./scenarios";

/** Practice for the Goal Integrity and Delegation labs: predict, baseline, attack, defended retest, compare, investigate. Same adapter and one-launch-at-a-time rule as the PI and RAG workbenches; only the reading of the record comes from the scenario. */
export function ScenarioPractice({ lab, sc }: { lab: Lab; sc: Scenario }) {
  const m = useMission();
  const wb = lab.explainer!.workbench!.resolved;
  const st = m.workbench?.[sc.lab] ?? {}, pred = st.prediction ?? {};
  const { rec: get, remember } = useRuns(sc.lab);
  const [busy, setBusy] = useState<Slot | "">("");
  const [secs, setSecs] = useState(0);
  const [err, setErr] = useState<{ slot: Slot; e: LaunchError } | null>(null);
  const [evid, setEvid] = useState<Record<string, Evidence | null>>({});
  const [cmp, setCmp] = useState<{ search_url: string; starter_spl: string } | null>(null);
  const inflight = useRef(false);
  const setPred = (p: Partial<NonNullable<typeof st.prediction>>) => updateMission((s) => ({ ...s, workbench: { ...s.workbench, [sc.lab]: { ...s.workbench?.[sc.lab], prediction: { ...s.workbench?.[sc.lab]?.prediction, ...p } } } }));
  const a = asS(get("attack")), r = asS(get("retest")), b = asS(get("baseline"));
  useEffect(() => { setCmp(null); if (a && r) compareRuns(a.run_id, r.run_id).then(setCmp); }, [a?.run_id, r?.run_id]);
  useEffect(() => { if (!busy) return; setSecs(0); const t = window.setInterval(() => setSecs((x) => x + 1), 1000); return () => window.clearInterval(t); }, [busy]);

  const run = async (slot: Slot) => {
    if (inflight.current) return;           // a double click never sends a second launch
    inflight.current = true; setBusy(slot); setErr(null);
    const res = await launchLab(sc.lab, lab.explainer!.workbench!.specimens[MODE[slot]], MODE[slot]);
    inflight.current = false; setBusy("");
    if ("error" in res) setErr({ slot, e: res.error }); else remember(res.record, slot);
  };
  const check = async (x: SRecord) => { setEvid((e) => ({ ...e, [x.run_id]: null })); const v = await probeEvidence(x.run_id); setEvid((e) => ({ ...e, [x.run_id]: v })); };
  const ready = sc.questions.every((q) => pred[q.key]), locked = Boolean(pred.locked);
  const guess = a && locked ? sc.guess(a, pred) : "";
  const gate = (ok: boolean, why: string) => ok ? null : <span className="m-muted">{why}</span>;
  const id = (k: number) => `${sc.lab}-${k}`;

  return <div className="m-wb" aria-label={sc.aria}>
    <p className="m-muted">Each step below is real: pressing a button asks the existing Attack Service to run the lab's own catalog specimen against AcmeBank. Nothing runs when you open this page, and the same button cannot send two launches at once. The setting (vulnerable or defended) and the request are chosen by the server, never by you. {sc.intro}</p>

    <section className="m-wbstep" aria-labelledby={id(1)}><h3 id={id(1)}><span>1</span> Predict</h3>
      <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); if (ready) setPred({ locked: true }); }}>
        {sc.questions.map((q) => <fieldset key={q.key} disabled={locked}><legend>{q.legend}</legend>
          {q.opts.map(([v, l]) => <label className="m-choice" key={v}><input type="radio" name={`${sc.lab}-${q.key}`} checked={pred[q.key] === v} onChange={() => setPred({ [q.key]: v })} /><span>{l}</span></label>)}</fieldset>)}
        {locked ? <div className="recorded"><Icon name="check" size={18} /><span><strong>Prediction locked</strong>Stored only in this browser. It cannot affect any run.</span></div> : <Button onClick={() => ready && setPred({ locked: true })} disabled={!ready}>Lock prediction</Button>}
      </form></section>

    <Step n={2} title="Baseline (optional)" id={id(2)} text={wb.baseline} extra={sc.baselineHint}>
      <Launch label={sc.baselineLabel} disabled={Boolean(busy)} busy={busy === "baseline"} secs={secs} onClick={() => run("baseline")} again={Boolean(b)} />
      {err?.slot === "baseline" && <Err e={err.e} />}{b && <RunCard sc={sc} x={b} ev={evid[b.run_id]} onCheck={() => check(b)} />}</Step>

    <Step n={3} title="Attack" id={id(3)} text={wb.attack} extra={wb.attack_expected.text} src={wb.attack_expected.source}>
      <Launch label="Launch ATTACK (intentionally vulnerable setting)" disabled={!locked || Boolean(busy)} busy={busy === "attack"} secs={secs} onClick={() => run("attack")} again={Boolean(a)} />
      {gate(locked, "Lock your prediction first.")}
      {err?.slot === "attack" && <Err e={err.e} />}{a && <RunCard sc={sc} x={a} ev={evid[a.run_id]} onCheck={() => check(a)} guess={guess} />}</Step>

    <Step n={4} title="Defend and retest" id={id(4)} text={wb.retest} extra={wb.defense.text} src={wb.defense.source}>
      <Launch label="Run RETEST (defended setting)" disabled={!a || Boolean(busy)} busy={busy === "retest"} secs={secs} onClick={() => run("retest")} again={Boolean(r)} />
      {gate(Boolean(a), "Run the attack first.")}
      {err?.slot === "retest" && <Err e={err.e} />}{r && <RunCard sc={sc} x={r} ev={evid[r.run_id]} onCheck={() => check(r)} />}</Step>

    <section className="m-wbstep" aria-labelledby={id(5)}><h3 id={id(5)}><span>5</span> Compare</h3>
      {a && r ? <Compare sc={sc} a={a} r={r} falsify={wb.retest_falsify.text} /> : <p className="m-muted">Appears when you have both an ATTACK run and a RETEST run.</p>}</section>

    <section className="m-wbstep" aria-labelledby={id(6)}><h3 id={id(6)}><span>6</span> Investigate</h3>
      {a || r || b ? <>
        <p>Open the evidence for each live run in Splunk and run the lab's search there. The Academy does not run it for you here. The search is written out under the Prove tab.</p>
        <div className="m-actions">{cmp && <SplunkLink className="button button--secondary" href={cmp.search_url} target="_blank" rel="noopener">Open ATTACK and RETEST in Splunk <Icon name="arrow" size={15} /></SplunkLink>}
          {([b, a, r].filter(Boolean) as SRecord[]).flatMap((x) => (sc.links ? sc.links(x).map(([k, url]) => [`${x.mode} ${k} run`, url, `${x.run_id}-${k}`] as const) : [[`${x.mode}`, x.search_handoff.search_url, x.run_id] as const]))
            .map(([label, url, key]) => <SplunkLink key={key} className="button button--ghost" href={url} target="_blank" rel="noopener">Open {label} in Splunk <Icon name="arrow" size={15} /></SplunkLink>)}</div>
        {cmp && <details className="m-details"><summary>Starter SPL for both runs</summary><pre>{cmp.starter_spl}</pre><CopyButton text={cmp.starter_spl} label="Copy search" /></details>}</>
        : <p className="m-muted">Run something first; the evidence links appear here.</p>}</section>
  </div>;
}

function RunCard({ sc, x, ev, onCheck, guess }: { sc: Scenario; x: SRecord; ev: Evidence | null | undefined; onCheck: () => void; guess?: string }) {
  const v = sc.interpret(x);
  return <div className="m-run m-mcp-run">
    <div className="run-card-head"><div><span>LIVE RUN · {x.mode} · {x.profile.toUpperCase()}</span><code>{x.run_id}</code></div><CopyButton text={x.run_id} label="Copy run id" /></div>
    {sc.ids && <div className="m-sec"><h4>Run ids of this launch</h4><p className="m-muted">One launch minted several runs, each with its own run id. The id above is the recall run.</p>
      <ul className="m-rules">{sc.ids(x).map(([k, v]) => <li key={k}><strong>{k}</strong> <code>{v}</code> {v !== "—" && <CopyButton text={v} label={`Copy ${k} run id`} />}</li>)}</ul></div>}
    {sc.correlation && <div className="m-sec"><h4>Correlation, measured from this record</h4>
      <ul className="m-rules">{sc.correlation(x).map(([t, ok]) => <li key={t}><strong>{ok ? "Held" : "NOT held"}:</strong> {t}.</li>)}</ul></div>}
    <StepList steps={sc.steps(x, ev)} label={`Progress of the ${x.mode} run, from the launch record`} finished />
    <div className={`m-outcome m-outcome--${v.tone}`} role="status"><div className="m-outcome__head"><Icon name={v.tone === "good" ? "shield" : "target"} size={20} /><strong>{v.label}</strong></div><p>{v.head}</p>{guess && <p className="m-muted">{guess}</p>}</div>
    <div className="m-verify"><Button variant="secondary" onClick={onCheck}>Check Splunk for this run <Icon name="search" size={15} /></Button>
      <span className="m-muted">This asks whether events for this run.id exist in Splunk. It never makes the run verified; this lab has no signed verifier.</span></div>
    <details className="m-details"><summary>Technical details: every hop, as recorded</summary>
      <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Hops of run {x.run_id.slice(0, 8)}… as recorded. A decision is not an execution: read the handler column separately.</caption>
        <thead><tr>{["Hop", "Step", "Control decision", "Tool or proposed action", "Handler"].map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
        <tbody>{x.runtime.hops.map((h) => <tr key={h["hop.index"]}>
          <td data-label="Hop">{h["hop.index"]}</td><td data-label="Step">{sc.hopStep(h)}</td><td data-label="Control decision">{h["control.decision"]} ({h["control.reason"]})</td><td data-label="Tool or proposed action">{h["tool.name"] || "—"}</td>
          <td data-label="Handler">{h["hop.index"] === 0 ? "not applicable" : `attempted ${String(h["operation.attempted"])}, started ${String(h["mcp.started"])}, executed ${String(h["operation.executed"])}${h["operation.outcome"] ? `, ${h["operation.outcome"]}` : ""}`}</td></tr>)}</tbody></table></div>
      <p className="m-muted">Lifecycle: {x.lifecycle.join(" → ")} · terminal {x.runtime.terminal} · blocked {String(x.runtime.blocked)}{x.runtime.block_reason ? ` (${x.runtime.block_reason})` : ""}</p></details>
  </div>;
}

function Compare({ sc, a, r, falsify }: { sc: Scenario; a: SRecord; r: SRecord; falsify: string }) {
  const same = sc.sameInput(a, r);
  return <>
    {!same && <Callout kind="warn" role="alert"><strong>These runs did not use the same input.</strong> The comparison below is not a like-for-like retest.</Callout>}
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">{sc.compareCaption(same)} Both columns are live runs.</caption>
      <thead><tr><th scope="col">Fact</th><th scope="col">ATTACK (live)</th><th scope="col">RETEST (live)</th></tr></thead>
      <tbody>{sc.compareRows(a, r).map(([k, p, q]) => <tr key={k} className={p !== q ? "is-different" : ""}><td data-label="Fact">{k}</td><td data-label="ATTACK (live)">{p}</td><td data-label="RETEST (live)">{q}</td></tr>)}</tbody></table></div>
    <div className="learning-note"><Icon name="book" size={18} /><div><strong>What this shows, and what it does not</strong>
      <p>{sc.compareNote(same)} What would have contradicted the defended result: {falsify}</p></div></div></>;
}

/** Prove: six different facts per live run, kept apart. Recorded specimens are shown elsewhere and are never mixed with these. */
export function ScenarioLiveEvidence({ sc }: { sc: Scenario }) {
  const u = useRuns(sc.lab), get = u.rec, ids = u.ids;
  const runs = (["baseline", "attack", "retest"] as Slot[]).map((s) => [s, asS(get(s))] as const).filter(([, x]) => x) as [Slot, SRecord][];
  if (!Object.values(ids).some(Boolean)) return <div className="m-sec"><h3>Your live runs</h3><p className="m-muted">You have not launched anything in this lab yet. Runs you start in Practice appear here, labelled LIVE and kept apart from the recorded specimens below.</p></div>;
  return <div className="m-sec"><h3>Your live runs <Badge tone="live">LIVE, NEW RUNS</Badge></h3>
    <p className="m-muted">These are the runs you launched. They are not the recorded specimens. Six different things are reported separately, because none of them implies the next.</p>
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Per live run, from its launch record</caption>
      <thead><tr><th scope="col">Run</th>{sc.columns.map(([h]) => <th scope="col" key={h}>{h}</th>)}</tr></thead>
      <tbody>{runs.map(([s, x]) => <tr key={x.run_id}><td data-label="Run"><strong>{MODE[s]}</strong> <code>{x.run_id.slice(0, 8)}…</code></td>{sc.columns.map(([h, f]) => <td data-label={h} key={h}>{f(x)}</td>)}</tr>)}</tbody></table></div></div>;
}
