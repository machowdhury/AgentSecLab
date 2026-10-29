import { useState } from "react";
import { Badge, Button, Icon } from "../../ui";
import { useConfig } from "../../config";
import { useMission } from "../../store";
import { PROOF_EVENTS, evidenceText, searches, splunkSearchUrl } from "../content";
import { Brief, CopyButton } from "../parts";
import { Milestones, SplCell } from "../Notebook";
import { AgentTrace } from "../AgentTrace";
import { LOAN_DESK_INVESTIGATE } from "../notebooks";
import { useSlot, useVerify, verifyRun } from "../runStore";
import { StageNav } from "../StageNav";
import { TaskPanel } from "../TaskPanel";

export function Investigate() {
  const { config } = useConfig();
  const m = useMission();
  const v = useSlot("attack").view;
  const ver = useVerify("attack");
  const [count, setCount] = useState(""); const [countMsg, setCountMsg] = useState(""); const [countErr, setCountErr] = useState("");
  const [proof, setProof] = useState(""); const [proofMsg, setProofMsg] = useState("");
  const state = v ? `LOCAL evidence: AcmeBank emitted ${v.evidence.event_count} events for this run. ${ver.text || evidenceText(v)}` : "No attack run yet.";

  const checkCount = () => {
    setCountErr("");
    if (!v) { setCountErr("Launch the attack first."); return; }
    if (!/^\d{1,5}$/.test(count.trim())) { setCountErr("Enter the whole number Splunk shows under events."); return; }
    const n = Number(count.trim()), local = v.evidence.event_count;
    setCountMsg(n === local ? `Your Splunk count (${n}) matches the ${local} events AcmeBank emitted. This is your own observation, recorded as learner-reported.`
      : n === local * 2 ? `You entered ${n}, exactly double. You probably counted field values (multivalue) instead of events. Use the events column.`
      : n < local ? `You entered ${n} but AcmeBank emitted ${local}. Indexing may still be catching up, or your time range is too short. Search again.`
      : `You entered ${n}, more than the ${local} events AcmeBank emitted. Check that you filtered on this run.id.`);
  };
  const checkProof = () => setProofMsg(!proof ? "Choose an event first." : proof === "agentsec.mcp.started"
    ? "Correct. agentsec.mcp.started is emitted just before the handler body, so its presence proves the handler began. A control.decision of ALLOW only says it was permitted."
    : `Not quite. ${proof} does not prove a handler began. Look for the event that is emitted when the handler starts.`);

  const list = v ? searches(v.run_id) : [];
  return <>
    <TaskPanel task="Run each search in Splunk, then answer from what you see." steps={["Verify", "Search 1", "Search 2", "Search 3", "Prove"]} active={ver.busy ? 0 : count ? 4 : 0} />
    <section className="m-card m-evidence">
      <div className="panel-label">Evidence for your attack run</div>
      <Brief step="investigate" />
      {v && <p>Run id <code>{v.run_id}</code></p>}
      <p className="m-evidence__state" role="status" aria-live="polite">{state}</p>
      <div className="m-actions">
        <Button variant="secondary" disabled={!v || ver.busy} onClick={() => verifyRun("attack")}>Verify with Splunk (host verifier)</Button>
        {config.urls.splunk_web && <a className="button button--ghost" href={`${config.urls.splunk_web}/en-US/app/search/search`} target="_blank" rel="noopener">Open Splunk Search <Icon name="arrow" size={15} /></a>}
      </div>
      {config.gateway && <p className="m-muted">Splunk Web is not published through this gateway. Copy a search and run it in your own Splunk session; the host verifier above checks the indexed evidence.</p>}
      <p className="m-muted">Splunk opens in a new tab and asks for the lab login. Your mission stays here.</p>
    </section>
    {v && <section className="m-card"><AgentTrace view={v} label="attack run" /></section>}
    <div className="notebook">
      {!v && <div className="notebook-empty"><span><Icon name="book" /></span><h2>Launch the attack first</h2><p>The searches use your real run id, so they appear after the Attack stage.</p></div>}
      {v && <Milestones cells={LOAN_DESK_INVESTIGATE} />}
      {v && LOAN_DESK_INVESTIGATE.map((c, i) => <SplCell key={c.id} cell={c} index={i + 1} />)}
      {v && <div className="m-nb-divider">Run these yourself in Splunk (they open in a new tab)</div>}
      {list.map((s, i) => <section className="notebook-cell notebook-cell--open" key={s.title}>
        <div className="cell-rail"><span>In [{i + 1 + LOAN_DESK_INVESTIGATE.length}]:</span><i /></div>
        <div className="cell-main">
          <div className="cell-question"><span>Question {i + 1}</span><h2>{s.title}</h2></div>
          <div className="query-block"><div><span>SPL query</span><Badge>ANALYST VIEW</Badge></div><pre>{s.spl}</pre></div>
          <div className="m-actions"><CopyButton text={s.spl} label="Copy search" />{config.urls.splunk_web && <a className="button button--secondary" href={splunkSearchUrl(config.urls.splunk_web, s.spl)} target="_blank" rel="noopener">Open in Splunk <Icon name="arrow" size={15} /></a>}</div>
          <div className="learning-note"><Icon name="book" size={18} /><div><strong>Learning note</strong><p>{s.note}</p></div></div>
          {i === 0 && <form className="m-inline" onSubmit={(e) => { e.preventDefault(); checkCount(); }}>
            <label htmlFor="splunk-count">How many events does Search 1 show for this run.id?</label>
            <input id="splunk-count" inputMode="numeric" autoComplete="off" value={count} onChange={(e) => setCount(e.target.value)} />
            {countErr && <p className="m-error" role="alert">{countErr}</p>}
            <Button variant="secondary" onClick={checkCount}>Check my count</Button>
            <p role="status">{countMsg}</p>
          </form>}
          {i === 2 && <form className="m-inline" onSubmit={(e) => { e.preventDefault(); checkProof(); }}>
            <label htmlFor="proof-event">Which recorded event proves the review handler actually began?</label>
            <select id="proof-event" value={proof} onChange={(e) => setProof(e.target.value)}><option value="">Choose an event…</option>{PROOF_EVENTS.map((x) => <option key={x}>{x}</option>)}</select>
            <Button variant="secondary" onClick={checkProof}>Check</Button>
            <p role="status">{proofMsg}</p>
          </form>}
        </div>
      </section>)}
    </div>
    <StageNav back="attack" next="defend" nextLabel="Continue to Defend" />
  </>;
}
