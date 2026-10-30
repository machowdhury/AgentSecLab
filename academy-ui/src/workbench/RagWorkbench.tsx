import { useEffect, useRef, useState } from "react";
import { Badge, Button, Icon } from "../ui";
import { updateMission, useMission } from "../store";
import { ExplainEvidence, RunFindingLinks, SplCellNotebook } from "../assurance/RunNotebook";
import { StageSection } from "../UnifiedWorkshop";
import { StepList } from "../mission/RunProgress";
import { Callout, CopyButton } from "../mission/parts";
import type { Lab } from "../curriculum";
import { launchLab, probeEvidence, type Evidence, type LaunchError } from "./launch";
import { Err, Launch, MODE, Step, useRuns, type Slot } from "./PiWorkbench";
import { RAG_KIND, asRag, followOn, hashShort, interpret, ragSteps, ran, type RagRecord } from "./rag";

const LAB = "LAB-RAG-CONTEXT";
const rec = (x: unknown) => asRag(x as never);

/** Practice: predict, baseline, attack, defended retest, compare, investigate. Same adapter and the same one-launch-at-a-time rule as the PI workbench; only the reading of the record is RAG-specific. */
export function RagPractice({ lab }: { lab: Lab }) {
  const m = useMission();
  const wb = lab.explainer!.workbench!.resolved;
  const st = m.workbench?.[LAB] ?? {}, pred = st.prediction ?? {};
  const { rec: get, remember } = useRuns(LAB);
  const [busy, setBusy] = useState<Slot | "">("");
  const [secs, setSecs] = useState(0);
  const [err, setErr] = useState<{ slot: Slot; e: LaunchError } | null>(null);
  const [evid, setEvid] = useState<Record<string, Evidence | null>>({});
  const inflight = useRef(false);
  const setPred = (p: Partial<NonNullable<typeof st.prediction>>) => updateMission((s) => ({ ...s, workbench: { ...s.workbench, [LAB]: { ...s.workbench?.[LAB], prediction: { ...s.workbench?.[LAB]?.prediction, ...p } } } }));
  const a = rec(get("attack")), r = rec(get("retest")), b = rec(get("baseline"));
  useEffect(() => { if (!busy) return; setSecs(0); const t = window.setInterval(() => setSecs((x) => x + 1), 1000); return () => window.clearInterval(t); }, [busy]);

  const run = async (slot: Slot) => {
    if (inflight.current) return;           // a double click never sends a second launch
    inflight.current = true; setBusy(slot); setErr(null);
    const res = await launchLab(LAB, lab.explainer!.workbench!.specimens[MODE[slot]], MODE[slot]);
    inflight.current = false; setBusy("");
    if ("error" in res) setErr({ slot, e: res.error }); else remember(res.record, slot);
  };
  const check = async (x: RagRecord) => { setEvid((e) => ({ ...e, [x.run_id]: null })); const v = await probeEvidence(x.run_id); setEvid((e) => ({ ...e, [x.run_id]: v })); };
  const ready = Boolean(pred.classify && pred.decision && pred.handler), locked = Boolean(pred.locked);
  const guess = a && locked ? `You predicted ${pred.classify} for the classification, ${pred.decision} for the follow-on tool and ${pred.handler === "yes" ? "that the handler would run" : "that the handler would not run"}. Recorded: ${a.runtime.context_control_decision}, ${a.runtime.follow_on_decision ?? "no follow-on"} and a handler count of ${a.runtime.handler_invoke_count}.` : "";
  const gate = (ok: boolean, why: string) => ok ? null : <span className="m-muted">{why}</span>;
  const radio = (name: string, key: "classify" | "decision" | "handler", opts: [string, string][]) => opts.map(([v, l]) => <label className="m-choice" key={v}><input type="radio" name={name} checked={pred[key] === v} onChange={() => setPred({ [key]: v })} /><span>{l}</span></label>);

  return <div className="m-wb" aria-label="Guided sequence for Retrieved Context">
    <p className="m-muted">Each step below is real: pressing a button asks the existing Attack Service to run the lab's own catalog specimen against AcmeBank. Nothing runs when you open this page, and the same button cannot send two launches at once. The setting (vulnerable or defended) and the document are chosen by the server, never by you. This lab calls no language model: it tests whether retrieved content can obtain a tool grant, not whether a model can be talked into something.</p>

    <StageSection stage="predict" id="rg1" title="Predict">
      <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); if (ready) setPred({ locked: true }); }}>
        <fieldset disabled={locked}><legend>On the intentionally vulnerable ATTACK setting, CTRL-RAG-CONTEXT-001 will classify the document as…</legend>{radio("rg-cls", "classify", [["OBSERVE", "OBSERVE (record it as data)"], ["ALLOW", "ALLOW"], ["DENY", "DENY"]])}</fieldset>
        <fieldset disabled={locked}><legend>…the follow-on request for lookup_customer_tier will be decided by CTRL-MCP-001 as…</legend>{radio("rg-dec", "decision", [["ALLOW", "ALLOW"], ["DENY", "DENY"]])}</fieldset>
        <fieldset disabled={locked}><legend>…and the tool handler…</legend>{radio("rg-hnd", "handler", [["yes", "will run"], ["no", "will not run"]])}</fieldset>
        {locked ? <div className="recorded"><Icon name="check" size={18} /><span><strong>Prediction locked</strong>Stored only in this browser. It cannot affect any run.</span></div> : <Button onClick={() => ready && setPred({ locked: true })} disabled={!ready}>Lock prediction</Button>}
      </form></StageSection>

    <Step stage="baseline" title="Baseline (optional)" id="rg2" text={wb.baseline} extra="A normal document gives you something to compare the malicious one with.">
      <Launch label="Run BASELINE (normal document)" disabled={Boolean(busy)} busy={busy === "baseline"} secs={secs} onClick={() => run("baseline")} again={Boolean(b)} />
      {err?.slot === "baseline" && <Err e={err.e} />}{b && <RunCard x={b} ev={evid[b.run_id]} onCheck={() => check(b)} />}</Step>

    <Step stage="attack" title="Attack" id="rg3" text={wb.attack} extra={wb.attack_expected.text} src={wb.attack_expected.source}>
      <Launch label="Launch ATTACK (intentionally vulnerable setting)" disabled={!locked || Boolean(busy)} busy={busy === "attack"} secs={secs} onClick={() => run("attack")} again={Boolean(a)} />
      {gate(locked, "Lock your prediction first.")}
      {err?.slot === "attack" && <Err e={err.e} />}{a && <RunCard x={a} ev={evid[a.run_id]} onCheck={() => check(a)} guess={guess} />}</Step>

    <Step stage="investigate" title="Investigate" id="rg5" text={{ text: "Read what your attack run left behind in Splunk. The Academy runs each approved search for you: you choose the options and press Run, then read the table, the chart and what the rows say.", source: "Academy investigation notebook (fixed server-side templates)" }}>
      <SplCellNotebook lab={LAB} runs={[{ slot: "baseline", id: b?.run_id ?? "" }, { slot: "attack", id: a?.run_id ?? "" }, { slot: "retest", id: r?.run_id ?? "" }]} /></Step>

    <Step stage="defend" title="Defend" id="rg6" text={wb.defense} extra="The defended setting is applied by the server when you run the RETEST in the next stage. You do not edit code or settings here.">
      {!a && <span className="m-muted">Run the attack first, so you know what you are defending against.</span>}</Step>

    <Step stage="retest" title="Retest" id="rg7" text={wb.retest}>
      <Launch label="Run RETEST (defended setting)" disabled={!a || Boolean(busy)} busy={busy === "retest"} secs={secs} onClick={() => run("retest")} again={Boolean(r)} />
      {gate(Boolean(a), "Run the attack first.")}
      {err?.slot === "retest" && <Err e={err.e} />}{r && <RunCard x={r} ev={evid[r.run_id]} onCheck={() => check(r)} />}      {a && r ? <h4>Compare the two runs</h4> : null}
      {a && r ? <Compare a={a} r={r} falsify={wb.retest_falsify.text} /> : <p className="m-muted">Appears when you have both an ATTACK run and a RETEST run.</p>}
      <RunFindingLinks runId={a?.run_id} withCompare={Boolean(r)} /></Step>

    <StageSection stage="explain" id="rg8" title="Explain evidence">
      <ExplainEvidence lab={LAB} runs={[{ slot: "attack", id: a?.run_id ?? "" }, { slot: "retest", id: r?.run_id ?? "" }]} completion={lab.guide?.completion ?? []} /></StageSection>
  </div>;
}

function RunCard({ x, ev, onCheck, guess }: { x: RagRecord; ev: Evidence | null | undefined; onCheck: () => void; guess?: string }) {
  const o = interpret(x), k = RAG_KIND[o.kind];
  return <div className="m-run m-mcp-run">
    <div className="run-card-head"><div><span>LIVE RUN · {x.mode} · {x.profile.toUpperCase()}</span><code>{x.run_id}</code></div><CopyButton text={x.run_id} label="Copy run id" /></div>
    <StepList steps={ragSteps(x, ev)} label={`Progress of the ${x.mode} run, from the launch record`} finished />
    <div className={`m-outcome m-outcome--${k.tone}`} role="status"><div className="m-outcome__head"><Icon name={o.kind === "DENIED_NOT_RUN" ? "shield" : "target"} size={20} /><strong>{k.label}</strong></div><p>{o.head}</p>{guess && <p className="m-muted">{guess}</p>}</div>
    <div className="m-verify"><Button variant="secondary" onClick={onCheck}>Check Splunk for this run <Icon name="search" size={15} /></Button>
      <span className="m-muted">This asks whether events for this run.id exist in Splunk. It never makes the run verified; this lab has no signed verifier.</span></div>
    <details className="m-details"><summary>Technical details: every hop, as recorded</summary><HopTable x={x} />
      <p className="m-muted">Lifecycle: {x.lifecycle.join(" → ")} · terminal {x.runtime.terminal} · blocked {String(x.runtime.blocked)}{x.runtime.block_reason ? ` (${x.runtime.block_reason})` : ""}</p></details>
  </div>;
}

export function HopTable({ x }: { x: RagRecord }) {
  return <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Hops of run {x.run_id.slice(0, 8)}… as recorded. A decision is not an execution: read the handler column separately.</caption>
    <thead><tr>{["Hop", "Step", "Control decision", "Tool", "Handler"].map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
    <tbody>{x.runtime.hops.map((h) => <tr key={h["hop.index"]}>
      <td data-label="Hop">{h["hop.index"]}</td><td data-label="Step">{h["tool.name"] ? "Follow-on tool request (CTRL-MCP-001)" : "Retrieved content classified (CTRL-RAG-CONTEXT-001)"}</td>
      <td data-label="Control decision">{h["control.decision"]} ({h["control.reason"]})</td><td data-label="Tool">{h["tool.name"] || "—"}</td>
      <td data-label="Handler">{h["tool.name"] ? `attempted ${String(h["operation.attempted"])}, started ${String(h["mcp.started"])}, executed ${String(h["operation.executed"])}${h["operation.outcome"] ? `, ${h["operation.outcome"]}` : ""}` : "not applicable"}</td></tr>)}</tbody></table></div>;
}

function Compare({ a, r, falsify }: { a: RagRecord; r: RagRecord; falsify: string }) {
  const same = a.runtime.content_hash === r.runtime.content_hash && a.runtime.document_id === r.runtime.document_id;
  const rows: [string, string, string][] = [["Setting (profile)", a.profile, r.profile], ["Document", a.runtime.document_id, r.runtime.document_id], ["Content hash", hashShort(a.runtime.content_hash), hashShort(r.runtime.content_hash)],
    ["Classification (CTRL-RAG-CONTEXT-001)", a.runtime.context_control_decision, r.runtime.context_control_decision], ["Follow-on decision (CTRL-MCP-001)", a.runtime.follow_on_decision ?? "none", r.runtime.follow_on_decision ?? "none"],
    ["Follow-on reason", a.runtime.follow_on_reason ?? "—", r.runtime.follow_on_reason ?? "—"], ["Handler count", String(a.runtime.handler_invoke_count), String(r.runtime.handler_invoke_count)], ["Outcome", RAG_KIND[interpret(a).kind].label, RAG_KIND[interpret(r).kind].label]];
  return <>
    {!same && <Callout kind="warn" role="alert"><strong>These runs did not retrieve the same document.</strong> The comparison below is not a like-for-like retest.</Callout>}
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">{same ? "Same retrieved document, different server-owned setting." : "Different documents."} Both columns are live runs.</caption>
      <thead><tr><th scope="col">Fact</th><th scope="col">ATTACK (live)</th><th scope="col">RETEST (live)</th></tr></thead>
      <tbody>{rows.map(([k, p, q]) => <tr key={k} className={p !== q ? "is-different" : ""}><td data-label="Fact">{k}</td><td data-label="ATTACK (live)">{p}</td><td data-label="RETEST (live)">{q}</td></tr>)}</tbody></table></div>
    <div className="learning-note"><Icon name="book" size={18} /><div><strong>What this shows, and what it does not</strong>
      <p>{same ? "The same document produced a different follow-on decision because the server-owned setting changed, not because the document changed. " : ""}The classification was the same on both runs, so it is not what changed the outcome; CTRL-MCP-001's decision is. A DENY is not automatically SAFE, an ALLOW is not an execution, and no model was involved. What would have contradicted the defended result: {falsify}</p></div></div></>;
}

/** Prove: six different facts per live run, kept apart, plus the evidence status. Recorded specimens are shown elsewhere and are never mixed with these. */
export function RagLiveEvidence() {
  const u = useRuns(LAB), get = u.rec, ids = u.ids;
  const runs = (["baseline", "attack", "retest"] as Slot[]).map((s) => [s, rec(get(s))] as const).filter(([, x]) => x) as [Slot, RagRecord][];
  if (!Object.values(ids).some(Boolean)) return <div className="m-sec"><h3>Your live runs</h3><p className="m-muted">You have not launched anything in this lab yet. Runs you start in Practice appear here, labelled LIVE and kept apart from the recorded specimens below.</p></div>;
  return <div className="m-sec"><h3>Your live runs <Badge tone="live">LIVE, NEW RUNS</Badge></h3>
    <p className="m-muted">These are the runs you launched. They are not the recorded specimens. Six different things are reported separately, because none of them implies the next.</p>
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Per live run, from its launch record</caption>
      <thead><tr>{["Run", "1. Retrieved content observed", "2. Content classification", "3. Follow-on tool authorization", "4. Actual tool execution", "5. Telemetry received", "6. Independently verified"].map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
      <tbody>{runs.map(([s, x]) => { const f = followOn(x); return <tr key={x.run_id}>
        <td data-label="Run"><strong>{MODE[s]}</strong> <code>{x.run_id.slice(0, 8)}…</code></td>
        <td data-label="1. Retrieved content observed">{x.runtime.document_id}, hash <code>{hashShort(x.runtime.content_hash)}</code>.</td>
        <td data-label="2. Content classification">{x.runtime.context_control_decision} ({x.runtime.context_control_reason}). Classifies only; it neither grants nor blocks a tool.</td>
        <td data-label="3. Follow-on tool authorization">{f ? `${f["control.decision"]} (${f["control.reason"]}) for ${f["tool.name"]}. A decision only.` : "No follow-on tool was requested."}</td>
        <td data-label="4. Actual tool execution">Handler count {x.runtime.handler_invoke_count}{f ? `; started ${String(f["mcp.started"])}, executed ${String(f["operation.executed"])}` : ""}. {ran(x) ? "The tool ran." : "The tool did not run."}</td>
        <td data-label="5. Telemetry received">{x.local_event_count ?? "?"} local events; otlp.ok {String(x["otlp.ok"])}, hec.ok {String(x["hec.ok"])}. Not the same as indexed in Splunk.</td>
        <td data-label="6. Independently verified">No. This lab has no signed verifier, so nothing here is verified. Existence checks are not verification.</td></tr>; })}</tbody></table></div></div>;
}
