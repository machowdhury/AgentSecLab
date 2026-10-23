import { useState } from "react";
import { Button, Icon } from "../../ui";
import { useConfig } from "../../config";
import { updateMission, useMission } from "../../store";
import { appValues, attackText } from "../app";
import { ApplicationForm } from "../ApplicationForm";
import { PREDICTIONS } from "../content";
import { Brief } from "../parts";
import { RunPanel } from "../RunProgress";
import { useSlot } from "../runStore";
import { StageNav } from "../StageNav";
import { TaskPanel } from "../TaskPanel";

export function Prepare() {
  const { config } = useConfig();
  const m = useMission();
  const slot = useSlot("explore");
  const [error, setError] = useState("");
  const locked = Boolean(m.prediction.locked);
  const pick = (id: string, value: string) => !locked && updateMission((s) => ({ ...s, prediction: { ...s.prediction, [id]: value } }));
  const lock = () => {
    const p = m.prediction;
    if (!p.follow || !p.decision || !p.queue) { setError("Answer all three questions before locking."); return; }
    setError(""); updateMission((s) => ({ ...s, prediction: { ...s.prediction, locked: true } }));
  };
  const task = locked ? "Prediction locked. Continue to Attack." : m.runs.explore ? "Now predict what the attack will do, then lock your prediction." : "Run a normal application first, then predict what the attack will do.";
  return <>
    <TaskPanel task={task} steps={["Explore", "Predict"]} active={locked || m.runs.explore ? 1 : 0} />
    <div className="workbench">
      <section className="scenario-pane">
        <div className="panel-label">01 — Explore</div>
        <h2>Run a normal application</h2>
        <Brief step="explore" />
        <ApplicationForm />
      </section>
      <section className="attack-pane">
        <div className="panel-label">02 — Predict</div>
        <h2>What will the attack do?</h2>
        <Brief step="predict" />
        <p>An applicant hides this in their notes. The Loan Desk is in <strong>BASELINE</strong> posture: policy checks the tool, scope and applicant, and the review note may be any text.</p>
        <blockquote className="m-quote">{attackText(m, config.mission)}</blockquote>
        <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); lock(); }}>
          {PREDICTIONS.map((q) => <fieldset key={q.id} disabled={locked}><legend>{q.legend}</legend>
            {q.options.map(([v, label]) => <label className="m-choice" key={v}><input type="radio" name={q.id} checked={m.prediction[q.id] === v} onChange={() => pick(q.id, v)} /><span>{label}</span></label>)}
          </fieldset>)}
          {error && <p className="m-error" role="alert">{error}</p>}
          {locked ? <div className="recorded"><Icon name="check" size={18} /><span><strong>Prediction locked</strong>You can now attack.</span></div> : <Button onClick={lock}>Lock prediction</Button>}
        </form>
        <div className="privacy-note"><Icon name="shield" size={18} /><span>Stored only in this browser. It cannot affect the attack, the control decision, the execution or the evidence.</span></div>
      </section>
      <aside className="run-pane">
        <div className="panel-label">03 — Observe the normal run</div>
        <RunPanel slot="explore" idle="No run yet. Run the normal application to see the timeline." />
      </aside>
    </div>
    <StageNav back="learn" next="attack" nextLabel="Continue to Attack" />
  </>;
}
