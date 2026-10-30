import { useEffect, useRef, useState } from "react";
import { Badge, Button, Icon } from "../ui";
import { updateMission, useMission } from "../store";
import type { UnifiedStageId } from "../stages";
import { ExplainEvidence, RunFindingLinks, SplCellNotebook } from "../assurance/RunNotebook";
import { StageSection } from "../UnifiedWorkshop";
import { StepList } from "../mission/RunProgress";
import { Callout, CopyButton } from "../mission/parts";
import type { Lab } from "../curriculum";
import { launchLab, loadLaunch, probeEvidence, type Evidence, type LaunchError, type LaunchRecord } from "./launch";
import { PI_KIND, hop0, interpret, modelStarted, piSteps } from "./pi";

export type Slot = "baseline" | "attack" | "retest";
const LAB = "LAB-PI-001";
export const MODE: Record<Slot, string> = { baseline: "BASELINE", attack: "ATTACK", retest: "RETEST" };
const cache = new Map<string, LaunchRecord | null>();

/** Live runs of this lab: stored run ids are re-read from the Attack Service on every visit; a stored copy is never trusted. */
export function useRuns(lab: string = LAB) {
  const m = useMission();
  const ids = m.workbench?.[lab]?.runs ?? {};
  const [, bump] = useState(0);
  useEffect(() => {
    (Object.values(ids) as string[]).filter((id) => id && !cache.has(id)).forEach((id) => loadLaunch(id).then((r) => { cache.set(id, r); bump((n) => n + 1); }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids.baseline, ids.attack, ids.retest]);
  const rec = (s: Slot) => (ids[s] ? cache.get(ids[s]!) : undefined);
  return { ids, rec, remember: (r: LaunchRecord, s: Slot) => { cache.set(r.run_id, r); updateMission((st) => ({ ...st, workbench: { ...st.workbench, [lab]: { ...st.workbench?.[lab], runs: { ...st.workbench?.[lab]?.runs, [s]: r.run_id } } } })); bump((n) => n + 1); } };
}

/** Practice: predict, baseline, attack, defend and retest, compare, investigate. Nothing runs until the learner presses a button, and a second press while one is in flight is ignored. */
export function PiPractice({ lab }: { lab: Lab }) {
  const m = useMission();
  const wb = lab.explainer!.workbench!.resolved;
  const st = m.workbench?.[LAB] ?? {}, pred = st.prediction ?? {};
  const { ids, rec, remember } = useRuns();
  const [busy, setBusy] = useState<Slot | "">("");
  const [secs, setSecs] = useState(0);
  const [err, setErr] = useState<{ slot: Slot; e: LaunchError } | null>(null);
  const [evid, setEvid] = useState<Record<string, Evidence | null>>({});
  const inflight = useRef(false);
  const setPred = (p: Partial<NonNullable<typeof st.prediction>>) => updateMission((s) => ({ ...s, workbench: { ...s.workbench, [LAB]: { ...s.workbench?.[LAB], prediction: { ...s.workbench?.[LAB]?.prediction, ...p } } } }));
  const a = rec("attack"), r = rec("retest"), b = rec("baseline");
  useEffect(() => { if (!busy) return; setSecs(0); const t = window.setInterval(() => setSecs((x) => x + 1), 1000); return () => window.clearInterval(t); }, [busy]);

  const run = async (slot: Slot) => {
    if (inflight.current) return;           // a double click never sends a second launch
    inflight.current = true; setBusy(slot); setErr(null);
    const specimen = lab.explainer!.workbench!.specimens[MODE[slot]];
    const res = await launchLab(LAB, specimen, MODE[slot]);
    inflight.current = false; setBusy("");
    if ("error" in res) setErr({ slot, e: res.error }); else remember(res.record, slot);
  };
  const check = async (rc: LaunchRecord) => { setEvid((e) => ({ ...e, [rc.run_id]: undefined as never })); setEvid((e) => ({ ...e, [rc.run_id]: null })); const v = await probeEvidence(rc.run_id); setEvid((e) => ({ ...e, [rc.run_id]: v })); };
  const locked = Boolean(pred.locked);
  const guess = a && hop0(a) && pred.locked ? `You predicted ${pred.decision} at hop 0 and ${pred.llm === "yes" ? "a model call" : "no model call"}. The control recorded ${hop0(a)!["control.decision"]} and ${modelStarted(a) ? "a model call started" : "no model call started"}.` : "";
  const gate = (needs: boolean, why: string) => needs ? null : <span className="m-muted">{why}</span>;

  return <div className="m-wb" aria-label="Guided sequence for Direct Prompt Injection">
    <p className="m-muted">Each step below is real: pressing a button asks the existing Attack Service to run the lab's own catalog specimen against AcmeBank. Nothing runs when you open this page, and the same button cannot send two launches at once. The setting (vulnerable or defended) is chosen by the server, never by you.</p>

    <StageSection stage="predict" id="wb1" title="Predict">
      <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); if (pred.decision && pred.llm) setPred({ locked: true }); }}>
        <fieldset disabled={locked}><legend>On the intentionally vulnerable ATTACK setting, hop 0 of CTRL-INPUT-001 will…</legend>
          {["ALLOW", "DENY"].map((v) => <label className="m-choice" key={v}><input type="radio" name="wb-dec" checked={pred.decision === v} onChange={() => setPred({ decision: v })} /><span>{v}</span></label>)}</fieldset>
        <fieldset disabled={locked}><legend>…and a model call (llm.started)…</legend>
          {[["yes", "will appear"], ["no", "will not appear"]].map(([v, l]) => <label className="m-choice" key={v}><input type="radio" name="wb-llm" checked={pred.llm === v} onChange={() => setPred({ llm: v })} /><span>{l}</span></label>)}</fieldset>
        {locked ? <div className="recorded"><Icon name="check" size={18} /><span><strong>Prediction locked</strong>Stored only in this browser. It cannot affect any run.</span></div> : <Button onClick={() => pred.decision && pred.llm && setPred({ locked: true })} disabled={!pred.decision || !pred.llm}>Lock prediction</Button>}
      </form></StageSection>

    <Step stage="baseline" title="Baseline (optional)" id="wb2" text={wb.baseline} extra="A normal loan gives you something to compare the attack with.">
      <Launch label="Run BASELINE (benign loan)" disabled={Boolean(busy)} busy={busy === "baseline"} secs={secs} onClick={() => run("baseline")} again={Boolean(b)} />
      {err?.slot === "baseline" && <Err e={err.e} />}{b && <RunCard rec={b} ev={evid[b.run_id]} onCheck={() => check(b)} />}</Step>

    <Step stage="attack" title="Attack" id="wb3" text={wb.attack} extra={wb.attack_expected.text} src={wb.attack_expected.source}>
      <Launch label="Launch ATTACK (intentionally vulnerable setting)" disabled={!locked || Boolean(busy)} busy={busy === "attack"} secs={secs} onClick={() => run("attack")} again={Boolean(a)} />
      {gate(locked, "Lock your prediction first.")}
      {err?.slot === "attack" && <Err e={err.e} />}{a && <RunCard rec={a} ev={evid[a.run_id]} onCheck={() => check(a)} guess={guess} />}</Step>

    <Step stage="investigate" title="Investigate" id="wb5" text={{ text: "Read what your attack run left behind in Splunk. The Academy runs each approved search for you: you choose the options and press Run, then read the table, the chart and what the rows say.", source: "Academy investigation notebook (fixed server-side templates)" }}>
      <SplCellNotebook lab={LAB} runs={[{ slot: "baseline", id: b?.run_id ?? "" }, { slot: "attack", id: a?.run_id ?? "" }, { slot: "retest", id: r?.run_id ?? "" }]} /></Step>

    <Step stage="defend" title="Defend" id="wb6" text={wb.defense} extra="The defended setting is applied by the server when you run the RETEST in the next stage. You do not edit code or settings here.">
      {!a && <span className="m-muted">Run the attack first, so you know what you are defending against.</span>}</Step>

    <Step stage="retest" title="Retest" id="wb7" text={wb.retest}>
      <Launch label="Run RETEST (defended setting)" disabled={!a || Boolean(busy)} busy={busy === "retest"} secs={secs} onClick={() => run("retest")} again={Boolean(r)} />
      {gate(Boolean(a), "Run the attack first.")}
      {err?.slot === "retest" && <Err e={err.e} />}{r && <RunCard rec={r} ev={evid[r.run_id]} onCheck={() => check(r)} />}      {a && r ? <h4>Compare the two runs</h4> : null}
      {a && r ? <Compare a={a} r={r} falsify={wb.retest_falsify.text} /> : <p className="m-muted">Appears when you have both an ATTACK run and a RETEST run.</p>}
      <RunFindingLinks runId={a?.run_id} withCompare={Boolean(r)} /></Step>

    <StageSection stage="explain" id="wb8" title="Explain evidence">
      <ExplainEvidence lab={LAB} runs={[{ slot: "attack", id: a?.run_id ?? "" }, { slot: "retest", id: r?.run_id ?? "" }]} completion={lab.guide?.completion ?? []} /></StageSection>
  </div>;
}

export function Step({ stage, title, id, text, extra, src, children }: { stage: UnifiedStageId; title: string; id: string; text: { text: string; source: string }; extra?: string; src?: string; children: React.ReactNode }) {
  return <StageSection stage={stage} id={id} title={title}><p>{text.text}<small className="m-src">Source: <code>{text.source}</code></small></p>{extra && <p className="m-muted">{extra}{src ? <small className="m-src">Source: <code>{src}</code></small> : null}</p>}{children}</StageSection>;
}
export function Launch({ label, disabled, busy, secs, onClick, again }: { label: string; disabled: boolean; busy: boolean; secs: number; onClick: () => void; again: boolean }) {
  return <div className="m-actions"><Button onClick={onClick} disabled={disabled}>{busy ? "Waiting for the Attack Service…" : again ? label.replace(/^(Run|Launch)/, "$1 again:").replace(": ", " ") : label} <Icon name="play" size={15} /></Button>
    {busy && <span className="m-muted" role="status">{secs} s elapsed. The target calls a local model, which can take a while. Nothing is retried.</span>}</div>;
}
export function Err({ e }: { e: LaunchError }) { return <Callout kind="warn" role="alert"><strong>{e.kind === "timeout" ? "No answer in time." : e.kind === "unreachable" ? "Target unavailable." : "The launch did not produce a run."}</strong> {e.message}</Callout>; }

function RunCard({ rec, ev, onCheck, guess }: { rec: LaunchRecord; ev: Evidence | null | undefined; onCheck: () => void; guess?: string }) {
  const o = interpret(rec), k = PI_KIND[o.kind];
  const evidence = ev === undefined ? undefined : ev;
  return <div className="m-run m-mcp-run">
    <div className="run-card-head"><div><span>LIVE RUN · {rec.mode} · {rec.profile.toUpperCase()}</span><code>{rec.run_id}</code></div><CopyButton text={rec.run_id} label="Copy run id" /></div>
    <StepList steps={piSteps(rec, evidence)} label={`Progress of the ${rec.mode} run, from the launch record`} finished />
    <div className={`m-outcome m-outcome--${k.tone}`} role="status"><div className="m-outcome__head"><Icon name={o.kind === "BLOCKED" ? "shield" : "target"} size={20} /><strong>{k.label}</strong></div><p>{o.head}</p>{guess && <p className="m-muted">{guess}</p>}</div>
    <div className="m-verify"><Button variant="secondary" onClick={onCheck}>Check Splunk for this run <Icon name="search" size={15} /></Button>
      <span className="m-muted">This asks whether events for this run.id exist in Splunk. It never makes the run verified; this lab has no signed verifier.</span></div>
    <details className="m-details"><summary>Technical details: every hop, as recorded</summary><HopTable rec={rec} />
      <p className="m-muted">Lifecycle: {rec.lifecycle.join(" → ")} · terminal {rec.runtime.terminal} · blocked {String(rec.runtime.blocked)}{rec.runtime.block_reason ? ` (${rec.runtime.block_reason})` : ""}</p></details>
  </div>;
}

export function HopTable({ rec }: { rec: LaunchRecord }) {
  return <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Hops of run {rec.run_id.slice(0, 8)}… as recorded. A decision is not an execution: read the model column separately.</caption>
    <thead><tr>{["Hop", "Role", "Control decision", "Operation", "Model call"].map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
    <tbody>{rec.runtime.hops.map((h) => <tr key={h["hop.index"]}>
      <td data-label="Hop">{h["hop.index"]}</td><td data-label="Role">{h.agent_name}</td>
      <td data-label="Control decision">{h["control.decision"]} ({h["control.reason"]})</td>
      <td data-label="Operation">attempted {String(h["operation.attempted"])}, executed {String(h["operation.executed"])}, {h["operation.outcome"]}</td>
      <td data-label="Model call">{h["llm.started"] ? `started${h["llm.completed"] ? ", completed" : ""}${h["llm.failed"] ? ", failed" : ""}` : "not started"}</td></tr>)}</tbody></table></div>;
}

function Compare({ a, r, falsify }: { a: LaunchRecord; r: LaunchRecord; falsify: string }) {
  const x = hop0(a)!, y = hop0(r)!;
  const rows: [string, string, string][] = [["Setting (profile)", a.profile, r.profile], ["Hop-0 decision", x["control.decision"], y["control.decision"]], ["Reason", x["control.reason"], y["control.reason"]],
    ["Model call started", String(modelStarted(a)), String(modelStarted(r))], ["Model calls counted", String(a.runtime.llm_call_count), String(r.runtime.llm_call_count)], ["Terminal", a.runtime.terminal, r.runtime.terminal], ["Outcome", PI_KIND[interpret(a).kind].label, PI_KIND[interpret(r).kind].label]];
  return <>
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Same ATK-002 input, different server-owned setting. Both columns are live runs.</caption>
      <thead><tr><th scope="col">Fact</th><th scope="col">ATTACK (live)</th><th scope="col">RETEST (live)</th></tr></thead>
      <tbody>{rows.map(([k, p, q]) => <tr key={k} className={p !== q ? "is-different" : ""}><td data-label="Fact">{k}</td><td data-label="ATTACK (live)">{p}</td><td data-label="RETEST (live)">{q}</td></tr>)}</tbody></table></div>
    <div className="learning-note"><Icon name="book" size={18} /><div><strong>What this shows, and what it does not</strong>
      <p>The same input produced a different decision because the server-owned setting changed, not because the input changed. A DENY is not automatically SAFE, an ALLOW is not proof the model approved anything, and the control is a pattern-matching lab control. What would have contradicted the defended result: {falsify}</p></div></div></>;
}

/** Prove: five different facts per live run, kept apart, plus the evidence status. Recorded specimens are shown elsewhere and are never mixed with these. */
export function PiLiveEvidence() {
  const { rec, ids } = useRuns();
  const runs = (["baseline", "attack", "retest"] as Slot[]).map((s) => [s, rec(s)] as const).filter(([, x]) => x) as [Slot, LaunchRecord][];
  if (!Object.values(ids).some(Boolean)) return <div className="m-sec"><h3>Your live runs</h3><p className="m-muted">You have not launched anything in this lab yet. Runs you start in Practice appear here, labelled LIVE and kept apart from the recorded specimens below.</p></div>;
  return <div className="m-sec"><h3>Your live runs <Badge tone="live">LIVE, NEW RUNS</Badge></h3>
    <p className="m-muted">These are the runs you launched. They are not the recorded specimens. Five different things are reported separately, because none of them implies the next.</p>
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Per live run, from its launch record</caption>
      <thead><tr>{["Run", "1. Decision", "2. Model call started", "3. Outcome", "4. Telemetry received", "5. Independently verified"].map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
      <tbody>{runs.map(([s, x]) => <tr key={x.run_id}>
        <td data-label="Run"><strong>{MODE[s]}</strong> <code>{x.run_id.slice(0, 8)}…</code></td>
        <td data-label="1. Decision">{hop0(x)?.["control.decision"] ?? "none"} ({hop0(x)?.["control.reason"] ?? "—"}). A decision only.</td>
        <td data-label="2. Model call started">{modelStarted(x) ? "yes (llm.started)" : "no"}</td>
        <td data-label="3. Outcome">{PI_KIND[interpret(x).kind].label}; terminal {x.runtime.terminal}</td>
        <td data-label="4. Telemetry received">{x.local_event_count ?? "?"} local events; otlp.ok {String(x["otlp.ok"])}, hec.ok {String(x["hec.ok"])}. Not the same as indexed in Splunk.</td>
        <td data-label="5. Independently verified">No. This lab has no signed verifier, so nothing here is verified. Existence checks are not verification.</td></tr>)}</tbody></table></div></div>;
}
