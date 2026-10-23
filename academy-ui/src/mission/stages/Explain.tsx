import { useState } from "react";
import { Button, Icon, LinkButton } from "../../ui";
import { markProgress, resetMission, updateMission, useMission } from "../../store";
import { navigate, missionPath } from "../../router";
import { QUIZ } from "../content";
import { Brief, Callout } from "../parts";
import { resetRuns } from "../runStore";
import { InvestigationRecord } from "../InvestigationRecord";
import { StageNav } from "../StageNav";
import { TaskPanel } from "../TaskPanel";

export function Explain() {
  const m = useMission();
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [text, setText] = useState("");
  const [err, setErr] = useState(""); const [result, setResult] = useState("");
  const check = () => {
    setErr(""); setResult("");
    const wrong = QUIZ.filter((q) => answers[q.id] !== q.answer).map((q) => (answers[q.id] ? q.id : `${q.id} (unanswered)`));
    if (wrong.length) { setResult(`Not yet. Revisit: ${wrong.join(", ")}. The Compare step and the policy decision rows have the answers.`); return; }
    if (text.trim().length < 60) { setErr("Write at least 60 characters in your own words."); return; }
    setResult("Mission complete. You attacked a live agent, proved the result, changed a control and retested it.");
    updateMission((s) => ({ ...s, completed: true })); markProgress("workflow_complete");
  };
  const reset = () => { resetRuns(); resetMission(); navigate(missionPath("learn")); };
  return <>
    <TaskPanel task={m.completed ? "Mission complete." : "Answer four questions, then explain it in your own words."} steps={["Answer", "Explain"]} active={m.completed ? 1 : 0} />
    <div className="workshop-grid">
      <div className="lesson">
        <div className="lesson-label">Explain</div>
        <InvestigationRecord />
        <h2>Say it in your own words</h2>
        <Brief step="explain" />
        <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); check(); }}>
          {QUIZ.map((q) => <fieldset key={q.id}><legend>{q.prompt}</legend>
            {q.options.map(([v, label]) => <label className="m-choice" key={v}><input type="radio" name={q.id} checked={answers[q.id] === v} onChange={() => setAnswers((a) => ({ ...a, [q.id]: v }))} /><span>{label}</span></label>)}
          </fieldset>)}
          <div className="m-field"><label htmlFor="explain-text">Explain in your own words what the attacker did and why the retest differed (at least 60 characters)</label>
            <textarea id="explain-text" rows={4} maxLength={1200} value={text} onChange={(e) => setText(e.target.value)} /></div>
          {err && <p className="m-error" role="alert">{err}</p>}
          <div className="m-actions"><Button onClick={check}>Check and finish</Button><Button variant="ghost" onClick={reset}>Reset this mission</Button></div>
          {result && <Callout kind={m.completed ? "good" : "warn"} role="status">{result}</Callout>}
        </form>
        <StageNav back="retest" />
      </div>
      <aside className="prediction-panel">
        <div className="prediction-panel__head"><div><div className="eyebrow">What next</div><h2>{m.completed ? "Well done" : "Almost there"}</h2></div></div>
        <p>{m.completed ? "Your runs and answers stay in this browser. Pick your next lab from the learning path." : "Finish the questions to complete the mission."}</p>
        <div className="m-actions"><LinkButton href="/academy/path" variant="secondary" icon="arrow">Back to your learning path</LinkButton><LinkButton href="/learn" internal variant="ghost">Academy home</LinkButton></div>
        <div className="privacy-note"><Icon name="shield" size={18} /><span>Your answers are checked in this browser only. Nothing here is a score or a certificate.</span></div>
      </aside>
    </div>
  </>;
}
