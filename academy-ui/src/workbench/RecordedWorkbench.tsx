import { useState } from "react";
import { Badge, Button } from "../ui";
import { Callout, CopyButton } from "../mission/parts";
import type { RecEvent, RecRun, Recorded } from "../curriculum";
import { authoritySource, compare, decision, decisiveEvent, f, handlerText, name, outcome, preview, priorResult, question, sameRequest, seq, setup, summary } from "./recorded";

const tone = (d?: string) => d === "ALLOW" ? "allow" : d === "DENY" ? "deny" : d === "ERROR" ? "warning" : d === "OBSERVE" ? "observed" : "muted";
const short = (s: string) => s.slice(0, 8);
const label = (r: RecRun) => `${r.role} (${r.meta.profile})`;

export const RECORDED_BADGE = "RECORDED — NOT RE-RUN";
export const NOT_VERIFIED = "No receipt from the Splunk verifier is attached to these packs, so this page makes no claim that they are Splunk-verified. The lab's own documents describe a Splunk validation phase; that is the document's statement, not a receipt checked here.";

export function EventRow({ e }: { e: RecEvent }) {
  const d = f(e, "agentsec.control.decision"), pv = preview(e);
  return <li className="rec-event"><details>
    <summary><span className="rec-seq">{seq(e)}</span> <code>{name(e)}</code>{d && <> <Badge tone={tone(d)}>{d}</Badge></>}<span className="rec-sum"> {summary(e)}</span></summary>
    <dl className="rec-fields">{Object.entries(e).filter(([k]) => k !== "agentsec.content.preview").map(([k, v]) => <div key={k}><dt><code>{k}</code></dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>)}</dl>
    {pv && <><h5>Recorded content preview, verbatim</h5><pre className="rec-pre">{pv}</pre></>}
  </details></li>;
}

function Predict({ run, rec, pick, onPick, state, onReveal }: { run: RecRun; rec: Recorded; pick?: string; onPick: (v: string) => void; state?: "predicted" | "skipped"; onReveal: (s: "predicted" | "skipped") => void }) {
  const d = decisiveEvent(run), prior = priorResult(run), shown = Boolean(state);
  return <div className="m-sec rec-predict">
    <h4>1. Predict <Badge tone="muted">YOUR PREDICTION IS NOT EVIDENCE</Badge></h4>
    <dl className="rec-setup">{setup(run).map(([k, v]) => <div key={k}><dt>{k}</dt><dd><code>{v}</code></dd></div>)}</dl>
    {prior && preview(prior) && <><h5>What the first tool call returned (recorded preview)</h5><pre className="rec-pre">{preview(prior)}</pre></>}
    <fieldset disabled={shown}><legend>{question(d)}</legend>
      <div className="rec-options">{rec.options.map((o) => <label key={o}><input type="radio" name={`pred-${run.run_id}`} value={o} checked={pick === o} onChange={() => onPick(o)} /> {o}</label>)}</div>
    </fieldset>
    {!shown && <div className="m-actions"><Button disabled={!pick} onClick={() => onReveal("predicted")}>Reveal the recorded decision</Button><Button variant="ghost" onClick={() => onReveal("skipped")}>Skip the prediction and show the evidence</Button></div>}
    {shown && <div role="status" className="rec-reveal">
      {state === "predicted" && <p>You predicted <strong>{pick}</strong>. The recorded decision is <Badge tone={tone(decision(run))}>{decision(run)}</Badge>{pick === decision(run) ? " — your prediction matched." : " — your prediction did not match."}</p>}
      {state === "skipped" && <p>Recorded decision: <Badge tone={tone(decision(run))}>{decision(run)}</Badge></p>}
      <p>Reason recorded: <code>{f(d, "agentsec.control.reason") ?? "not recorded"}</code> from <code>{f(d, "agentsec.control.id") ?? "control not recorded"}</code>.</p>
      <p className="m-muted">How the lab documents this run: {run.documented_as.text} <small className="m-src">Source: <code>{run.documented_as.source}</code></small></p>
    </div>}
  </div>;
}

/** Practice for a recorded-evidence lab: predict, explore the committed events, compare. Nothing here launches a run, calls a model or contacts Splunk. */
export function RecordedPractice({ rec }: { rec: Recorded }) {
  const [sel, setSel] = useState(rec.runs[0].run_id);
  const [pick, setPick] = useState<Record<string, string>>({});
  const [state, setState] = useState<Record<string, "predicted" | "skipped">>({});
  const run = rec.runs.find((r) => r.run_id === sel)!;
  const revealed = rec.runs.filter((r) => state[r.run_id]);
  const st = state[run.run_id];
  const rows = revealed.length >= 2 ? compare(revealed) : [];
  const attack = revealed.find((r) => r.role === "ATTACK"), retest = revealed.find((r) => r.role === "RETEST");
  return <div className="m-sec rec" data-testid="recorded-workbench">
    <h3>Recorded evidence workbench <Badge tone="replay">{RECORDED_BADGE}</Badge></h3>
    <p className="m-muted">These are events the lab recorded earlier, shown unchanged from the committed specimen packs. Nothing is launched, no model is called and nothing is sent to Splunk from this page.</p>
    <div role="group" aria-label="Recorded runs" className="rec-runs">
      {rec.runs.map((r) => <button key={r.run_id} type="button" aria-pressed={r.run_id === sel} className={`rec-run ${r.run_id === sel ? "is-current" : ""}`} onClick={() => setSel(r.run_id)}>
        {label(r)}<small>run <code>{short(r.run_id)}</code>{state[r.run_id] ? " · revealed" : ""}</small></button>)}
    </div>
    <Predict run={run} rec={rec} pick={pick[run.run_id]} onPick={(v) => setPick((p) => ({ ...p, [run.run_id]: v }))} state={st} onReveal={(s) => setState((x) => ({ ...x, [run.run_id]: s }))} />

    <div className="m-sec"><h4>2. Explore the recorded events</h4>
      {!st ? <p className="m-muted">Make a prediction, or choose to skip it, to see this run's events.</p> : <>
        <p>{handlerText(run)}</p>
        <p className="m-muted">Source specimen <code>{run.pack}</code>. Run <code>{run.run_id}</code>. {run.meta.event_count} events, in recorded order.</p>
        <ol className="rec-events" aria-label={`Events of the ${run.role} run`}>{run.events.map((e) => <EventRow key={seq(e)} e={e} />)}</ol></>}
    </div>

    <div className="m-sec"><h4>3. Compare the runs you have revealed</h4>
      {rows.length === 0 ? <p className="m-muted">Reveal at least two runs to compare them. Only runs you have revealed appear, and only recorded fields are compared.</p> : <>
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Comparison of the revealed runs; scrolls sideways on a narrow screen"><table><caption className="m-caption">Recorded fields of the decisive event, run by run</caption>
          <thead><tr><th scope="col">Field</th>{revealed.map((r) => <th scope="col" key={r.run_id}>{label(r)}</th>)}</tr></thead>
          <tbody>{rows.map((r) => <tr key={r.label} className={r.differs ? "rec-differs" : ""}><th scope="row">{r.label}{r.differs && <small> (differs)</small>}</th>{r.values.map((v, i) => <td key={i}>{v}</td>)}</tr>)}</tbody></table></div>
        {attack && retest && <p className="m-muted">Computed from the recorded fields: the ATTACK and RETEST requests {sameRequest(attack, retest) ? "name the same tool, scope and resource" : "do not name the same tool, scope and resource"}; the profile is {attack.meta.profile} and {retest.meta.profile}.</p>}</>}
    </div>
  </div>;
}

/** Prove for a recorded-evidence lab: the decisive event, provenance, verification status and the lab's searches. */
export function RecordedProve({ rec }: { rec: Recorded }) {
  return <div className="m-sec rec" data-testid="recorded-prove">
    <h3>Decisive events and where they come from <Badge tone="replay">{RECORDED_BADGE}</Badge></h3>
    <Callout kind="warn"><strong>Verification status: not verified here.</strong> {NOT_VERIFIED}</Callout>
    <div className="table-wrap"><table className="m-stack"><caption className="m-caption">The decisive event of each recorded run</caption>
      <thead><tr><th scope="col">Run</th><th scope="col">Decisive event</th><th scope="col">Decision</th><th scope="col">Reason</th><th scope="col">Handler began</th><th scope="col">Ended</th></tr></thead>
      <tbody>{rec.runs.map((r) => { const d = decisiveEvent(r); return <tr key={r.run_id}>
        <td data-label="Run">{label(r)}<br /><code>{r.run_id}</code></td><td data-label="Decisive event">sequence {r.decisive}, <code>{name(d)}</code>, <code>{f(d, "agentsec.control.id")}</code></td>
        <td data-label="Decision"><Badge tone={tone(decision(r))}>{decision(r)}</Badge></td><td data-label="Reason"><code>{f(d, "agentsec.control.reason")}</code></td>
        <td data-label="Handler began">{handlerText(r).startsWith("Handler began: yes") ? "yes (mcp.started)" : "no mcp.started in the pack"}</td><td data-label="Ended">{outcome(r)}</td></tr>; })}</tbody></table></div>
    <details className="m-details"><summary>Provenance of each pack</summary>
      <div className="table-wrap"><table className="m-stack"><caption className="m-caption">Committed specimen packs shown on this page</caption>
        <thead><tr><th scope="col">Run</th><th scope="col">Pack file</th><th scope="col">SHA-256 of the file</th><th scope="col">Originally recorded as</th><th scope="col">First event</th></tr></thead>
        <tbody>{rec.runs.map((r) => <tr key={r.run_id}><td data-label="Run"><code>{r.run_id}</code></td><td data-label="Pack file"><code>{r.pack}</code></td><td data-label="SHA-256"><code>{r.sha256}</code></td>
          <td data-label="Originally recorded as">{r.meta.execution_mode} / {r.meta.fidelity}, schema {r.meta.schema_version}</td><td data-label="First event">{r.meta.started}</td></tr>)}</tbody></table></div>
      <p className="m-muted">Documented in <code>{rec.runs[0].documented_as.source}</code>. The original timestamps and values are preserved. "LIVE / OBSERVED" describes how the lab recorded them at the time, not how this page shows them.</p></details>
    <div className="m-sec"><h3>The lab's searches (SPL)</h3>
      <p className="m-muted">Shown as written in the lab. They are not run from this page. Each uses the placeholder <code>__RUN_ID__</code>; put the run id there, in quotes, as the lab's dashboards do.</p>
      {rec.spl.map((q) => <details className="m-details" key={q.source}><summary><code>{q.name}</code></summary><pre>{q.text}</pre><CopyButton text={q.text} label="Copy search" /><small className="m-src">Source: <code>{q.source}</code></small></details>)}</div>
    <p className="m-muted">Authority labels, where a request carries one, are the lab's own wording read from the recorded preview{rec.runs.some((r) => authoritySource(decisiveEvent(r))) ? ` (for example ${[...new Set(rec.runs.map((r) => authoritySource(decisiveEvent(r))).filter(Boolean))].map((x) => `"${x}"`).join(" and ")})` : ""}.</p>
  </div>;
}
