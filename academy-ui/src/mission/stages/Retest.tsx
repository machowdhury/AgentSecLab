import { Badge, Button, Icon } from "../../ui";
import { useConfig } from "../../config";
import { useMission } from "../../store";
import { SEC_LABEL } from "../content";
import { appValues, attackText } from "../app";
import { Brief, Callout, Story } from "../parts";
import { RunPanel } from "../RunProgress";
import { launch, useSlot, useVerify, verifyRun } from "../runStore";
import { StageNav } from "../StageNav";
import { Milestones, SplCell } from "../Notebook";
import { LOAN_DESK_RETEST } from "../notebooks";
import { TaskPanel } from "../TaskPanel";
import { reviewCall } from "../../runs";
import type { RunView } from "../../types";

const revText = (v: RunView) => { const c = reviewCall(v); return c ? `${c.decision} (${c.reason}), handler ${c.executed ? "began" : "did not run"}` : "no review submitted"; };
const harm = (v: RunView) => v.queue_harm.tickets_with_applicant_text.length > 0;

const ROWS: [string, (v: RunView) => string][] = [
  ["Posture", (v) => v.posture.toUpperCase()],
  ["Policy decision for the review note", revText],
  ["Underwriter queue note", (v) => v.tickets?.[0]?.note ?? "(nothing filed)"],
  ["Attacker text reached the queue", (v) => (harm(v) ? "YES" : "no")],
  ["Security outcome", (v) => SEC_LABEL[v.outcomes?.security.outcome ?? ""] ?? "—"],
  ["Business workflow", (v) => v.outcomes?.business.outcome ?? "—"],
  ["Proposed / denied / executed", (v) => v.outcomes ? `${v.outcomes.operations.proposed} / ${v.outcomes.operations.denied} / ${v.outcomes.operations.executed}` : "—"],
  ["Events emitted (local)", (v) => String(v.evidence.event_count)],
  ["Model", (v) => v.model.name + (v.model.identity?.digest ? " " + v.model.identity.digest.slice(0, 12) : "")],
  ["Splunk evidence", (v) => v.evidence.indexed_status.replace(/_/g, " ")],
  ["run.id", (v) => v.run_id],
];

function Compare() {
  const a = useSlot("attack").view, r = useSlot("retest").view;
  const va = useVerify("attack"), vr = useVerify("retest");
  const bothDone = Boolean(a && r && a.status !== "RUNNING" && r.status !== "RUNNING");
  const verifyBoth = async () => { await verifyRun("attack"); await verifyRun("retest"); };
  const text = [va.text && `Attack run: ${va.text}`, vr.text && `Retest run: ${vr.text}`].filter(Boolean).join("  |  ");
  if (!(a && r && bothDone)) return <p className="m-muted">Finish both runs to compare them.</p>;
  const worked = harm(a) && !harm(r);
  return <>
    <div className="table-wrap"><table><caption className="m-caption">Attack run versus retest run</caption>
      <thead><tr><th scope="col">Measure</th><th scope="col">ATTACK</th><th scope="col">RETEST</th></tr></thead>
      <tbody>{ROWS.map(([label, fn]) => { const x = fn(a), y = fn(r); return <tr key={label} className={x !== y ? "is-different" : ""}><th scope="row">{label}</th><td>{x}</td><td>{y}</td></tr>; })}</tbody></table></div>
    <Story view={r} />
    <div className="m-actions"><Button variant="secondary" disabled={va.busy || vr.busy} onClick={verifyBoth}>Verify both runs with Splunk</Button></div>
    {text && <Callout role="status">{text}</Callout>}
    <Callout kind={worked ? "good" : "warn"}>{worked
      ? `The same planted text reached the queue under BASELINE and did not under ${r.posture.toUpperCase()}${r.outcomes?.business.outcome !== "COMPLETE" ? ", even though the retest's loan review did not finish (a usability cost, not a security failure)" : ""}. Model output varies between runs, so read the rows, not just the headline.`
      : "These two runs do not show the defense working: the attacker text reached the queue in the retest, or it never reached it in the attack. Re-run with the right postures, or read the rows to see why."}</Callout>
  </>;
}

export function Retest() {
  const { config } = useConfig();
  const m = useMission();
  const slot = useSlot("retest");
  const busy = slot.phase === "submitting" || slot.phase === "running";
  const done = slot.view && slot.view.status !== "RUNNING";
  return <>
    <TaskPanel task={done ? "Compare the two runs and note what changed." : "Launch the retest with the control you chose."} steps={["Retest", "Compare"]} active={done ? 1 : 0} />
    <div className="workbench">
      <section className="scenario-pane">
        <div className="panel-label">01 — Your control</div>
        <h2>Same attack, new posture</h2>
        <Brief step="retest" />
        <Callout>The retest will run the same planted text with posture <strong>{m.posture.toUpperCase()}</strong>.{m.posture === "baseline" ? " That is the unprotected setting: expect the attack to work again. Go back to Defend to harden it." : ""}</Callout>
      </section>
      <section className="attack-pane">
        <div className="panel-label">02 — Configure & launch</div>
        <h2>Replay the planted text</h2>
        <p>It uses the planted text from the Attack step.</p>
        <button type="button" className="button button--primary" disabled={busy} onClick={() => launch("retest", { ...appValues(m, config.mission), notes: m.attackNotes ?? attackText(m, config.mission) }, m.posture)}>Launch retest ({m.posture.toUpperCase()}) <Icon name="play" size={15} /></button>
      </section>
      <aside className="run-pane">
        <div className="panel-label">03 — Observe independent facts</div>
        <RunPanel slot="retest" idle="No run yet. Launch the retest to see the result." next={{ label: "Continue to Explain", stage: "explain" }} />
      </aside>
    </div>
    <section className="m-section" aria-labelledby="h-nb-retest">
      <div className="lesson-label">Investigate both runs</div><h2 id="h-nb-retest">Prove the difference in Splunk</h2>
      <p>These searches read your two real runs from Splunk, side by side. Rows that differ are marked.</p>
      <Milestones cells={LOAN_DESK_RETEST} />
      <div className="notebook">{LOAN_DESK_RETEST.map((c, i) => <SplCell key={c.id} cell={c} index={i + 1} />)}</div>
    </section>
    <StageNav back="defend" next="explain" nextLabel="Continue to Explain" />
  </>;
}
