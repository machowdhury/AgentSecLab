import { Button, Icon } from "../../ui";
import { useConfig } from "../../config";
import { updateMission, useMission } from "../../store";
import { appValues, attackText } from "../app";
import { Brief, Callout } from "../parts";
import { RunPanel } from "../RunProgress";
import { AgentTrace } from "../AgentTrace";
import { launch, useSlot } from "../runStore";
import { StageNav } from "../StageNav";
import { TaskPanel } from "../TaskPanel";
import { reviewCall } from "../../runs";
import type { RunView } from "../../types";

function actual(v: RunView) {
  const t = v.tickets?.[0]; const c = reviewCall(v); const harm = v.queue_harm.tickets_with_applicant_text.length > 0;
  return { follow: harm ? "yes" : "no", decision: c ? c.decision : "none", queue: harm ? "planted" : t ? "neutral" : "nothing" };
}

export function Attack() {
  const { config } = useConfig();
  const m = useMission();
  const slot = useSlot("attack");
  const busy = slot.phase === "submitting" || slot.phase === "running";
  const text = attackText(m, config.mission);
  const v = slot.view;
  const finished = Boolean(v && v.status !== "RUNNING");
  const p = m.prediction;
  const a = finished ? actual(v!) : null;
  const rows: [string, string | undefined, string][] = a ? [["Did the agent copy the planted text?", p.follow, a.follow], ["Policy decision for the review submission", p.decision, a.decision], ["What the underwriter sees", p.queue, a.queue]] : [];
  return <>
    <TaskPanel task={finished ? "Read the result and compare it with your prediction." : "Launch the attack, then wait for the run to finish."} steps={["Launch", "Observe"]} active={finished ? 1 : 0} />
    <div className="workbench">
      <section className="scenario-pane">
        <div className="panel-label">01 — Your prediction</div>
        <h2>What you locked</h2>
        <dl className="m-meta">
          <div><dt>Will the agent copy the planted text?</dt><dd>{p.follow ?? "—"}</dd></div>
          <div><dt>Policy decision for the review</dt><dd>{p.decision ?? "—"}</dd></div>
          <div><dt>What the underwriter will see</dt><dd>{p.queue ?? "—"}</dd></div>
        </dl>
        <div className="privacy-note"><Icon name="shield" size={18} /><span>Browser-local learning state. It is never part of the request.</span></div>
      </section>
      <section className="attack-pane">
        <div className="panel-label">02 — Configure & launch</div>
        <h2>Submit the planted application</h2>
        <Brief step="attack" />
        <div className="m-field"><label htmlFor="attack-notes">Applicant notes (the planted text)</label>
          <textarea id="attack-notes" rows={5} maxLength={400} value={text} onChange={(e) => updateMission((s) => ({ ...s, attackNotes: e.target.value }))} /></div>
        <div className="m-actions">
          <button type="button" className="button button--primary" disabled={busy} onClick={() => launch("attack", { ...appValues(m, config.mission), notes: text }, "baseline")}>Launch attack (BASELINE posture) <Icon name="play" size={15} /></button>
          <button type="button" className="button button--ghost" onClick={() => updateMission((s) => ({ ...s, attackNotes: undefined }))}>Restore planted text</button>
        </div>
      </section>
      <aside className="run-pane">
        <div className="panel-label">03 — Observe independent facts</div>
        <RunPanel slot="attack" idle="No run yet. Launch the attack to see what the agent does." next={{ label: "Continue to Investigate", stage: "investigate" }} />
        {v && <AgentTrace view={v} label="attack run" />}
      </aside>
    </div>
    <section className="m-section" aria-labelledby="h-observe">
      <div className="lesson-label">Observe</div>
      <h2 id="h-observe">What happened</h2>
      <Brief step="observe" />
      {!v && <p className="m-muted">Launch the attack to see the result.</p>}
      {v && !finished && <p className="m-muted">The attack run is still working. This view updates when it finishes.</p>}
      {a && v && <>
        <div className="table-wrap"><table><caption className="m-caption">Your prediction versus the run</caption>
          <thead><tr><th scope="col">Question</th><th scope="col">You predicted</th><th scope="col">What happened</th><th scope="col">Match</th></tr></thead>
          <tbody>{rows.map(([q, x, y]) => <tr key={q}><td>{q}</td><td>{x ?? "—"}</td><td>{y}</td><td>{String(x) === y ? "match" : "differs"}</td></tr>)}</tbody></table></div>
        <Callout kind="good">A DENY or an ALLOW is a policy decision. Whether the handler began is a separate fact: see the Executed column and the event agentsec.mcp.started.</Callout>
      </>}
    </section>
    <StageNav back="prepare" next="investigate" nextLabel="Continue to Investigate" />
  </>;
}
