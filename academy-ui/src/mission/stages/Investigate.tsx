import { useState } from "react";
import { Button, Icon } from "../../ui";
import { useConfig } from "../../config";
import { useMission } from "../../store";
import { PROOF_EVENTS, evidenceText } from "../content";
import { Brief } from "../parts";
import { Milestones, SplCell } from "../Notebook";
import { AgentTrace } from "../AgentTrace";
import { LOAN_DESK_INVESTIGATE } from "../notebooks";
import { useSlot, useVerify, verifyRun } from "../runStore";
import { StageNav } from "../StageNav";
import { unifiedNumber, unifiedStages } from "../../stages";
import { TaskPanel } from "../TaskPanel";

export function Investigate() {
  const { config } = useConfig();
  const m = useMission();
  const v = useSlot("attack").view;
  const ver = useVerify("attack");
  const [proof, setProof] = useState(""); const [proofMsg, setProofMsg] = useState("");
  const state = v ? `LOCAL evidence: AcmeBank emitted ${v.evidence.event_count} events for this run. ${ver.text || evidenceText(v)}` : "No attack run yet.";

  const checkProof = () => setProofMsg(!proof ? "Choose an event first." : proof === "agentsec.mcp.started"
    ? "Correct. agentsec.mcp.started is emitted just before the handler body, so its presence proves the handler began. A control.decision of ALLOW only says it was permitted."
    : `Not quite. ${proof} does not prove a handler began. Look for the event that is emitted when the handler starts.`);

  return <>
    <TaskPanel task="Press Run on each notebook cell, then answer from the rows you see." steps={["Verify", "Events", "Tools", "Decisions", "Trail", "Handlers"]} active={ver.busy ? 0 : 1} />
    <section className="m-card m-evidence">
      <div className="panel-label">Stage {unifiedNumber("investigate")} of {unifiedStages.length} · Evidence for your attack run</div>
      <Brief step="investigate" />
      {v && <p>Run id <code>{v.run_id}</code></p>}
      <p className="m-evidence__state" role="status" aria-live="polite">{state}</p>
      <div className="m-actions">
        <Button variant="secondary" disabled={!v || ver.busy} onClick={() => verifyRun("attack")}>Verify with Splunk (host verifier)</Button>
        {config.urls.splunk_web && <a className="button button--ghost" href={`${config.urls.splunk_web}/en-US/app/search/search`} target="_blank" rel="noopener">Advanced: open Splunk Search (optional) <Icon name="arrow" size={15} /></a>}
      </div>
      {config.gateway && <p className="m-muted">Splunk Web is not published through this gateway. The notebook below searches Splunk for you, and the host verifier above checks the indexed evidence.</p>}
          </section>
    {v && <section className="m-card"><AgentTrace view={v} label="attack run" /></section>}
    <div className="notebook">
      {!v && <div className="notebook-empty"><span><Icon name="book" /></span><h2>Launch the attack first</h2><p>The searches use your real run id, so they appear after the Attack stage.</p></div>}
      {v && <Milestones cells={LOAN_DESK_INVESTIGATE} />}
      {v && LOAN_DESK_INVESTIGATE.map((c, i) => <SplCell key={c.id} cell={c} index={i + 1} />)}
      {v && <section className="notebook-cell notebook-cell--open"><div className="cell-main">
        <form className="m-inline" onSubmit={(e) => { e.preventDefault(); checkProof(); }}>
          <label htmlFor="proof-event">From the handler-outcomes and decisions cells above: which recorded event proves the review handler actually began?</label>
          <select id="proof-event" value={proof} onChange={(e) => setProof(e.target.value)}><option value="">Choose an event…</option>{PROOF_EVENTS.map((x) => <option key={x}>{x}</option>)}</select>
          <Button variant="secondary" onClick={checkProof}>Check</Button>
          <p role="status">{proofMsg}</p>
        </form></div></section>}
    </div>
    <StageNav back="attack" next="defend" nextLabel="Continue to Defend" />
  </>;
}
