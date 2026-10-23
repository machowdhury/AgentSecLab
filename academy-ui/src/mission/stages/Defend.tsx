import { useState } from "react";
import { Badge, Button, Icon } from "../../ui";
import { updateMission, useMission } from "../../store";
import type { Posture } from "../../types";
import { REASON_CODES, RULE } from "../content";
import { Brief, Callout } from "../parts";
import { StageNav } from "../StageNav";
import { TaskPanel } from "../TaskPanel";

export function Defend() {
  const m = useMission();
  const [sel, setSel] = useState<Posture>(m.posture);
  const apply = (p: Posture) => updateMission((s) => ({ ...s, posture: p, defenseApplied: true }));
  return <>
    <TaskPanel task={m.defenseApplied ? "Defense applied. Continue to Retest." : "Choose how the review note is controlled, then apply it."} steps={["Choose", "Apply"]} active={m.defenseApplied ? 1 : 0} />
    <div className="workshop-grid">
      <main className="lesson">
        <div className="lesson-label">Defend</div>
        <h2>Change one control</h2>
        <Brief step="defend" />
        <Callout kind="warn">This is a <strong>new</strong> control. The policy denial of cross-customer reads (<code>resource_not_bound_to_run</code>) already existed and is unchanged by this setting. Do not count it as a fix for this attack.</Callout>
        <form onSubmit={(e) => { e.preventDefault(); apply(sel); }}>
          <fieldset className="m-fieldset"><legend>Review note policy</legend>
            <div className="mode-choice" role="radiogroup" aria-label="Review note policy">
              {(["baseline", "hardened"] as Posture[]).map((p) => <button type="button" key={p} role="radio" aria-checked={sel === p} className={sel === p ? "mode-choice--active" : ""} onClick={() => setSel(p)}>
                <Badge tone={p === "hardened" ? "allow" : "neutral"}>{p === "baseline" ? "Free text (BASELINE)" : "Reason codes only (HARDENED)"}</Badge>
                <span>{p === "baseline" ? "The agent may write any note. Flexible, and an injected instruction can ride along." : <>The note must be exactly one of {REASON_CODES.map((c) => <code key={c}>{c} </code>)}. Anything else is denied before the handler runs.</>}</span>
              </button>)}
            </div>
          </fieldset>
          <div className="m-actions"><Button onClick={() => apply(sel)}>Apply setting</Button><Button variant="ghost" onClick={() => { setSel("baseline"); apply("baseline"); }}>Revert to BASELINE</Button></div>
        </form>
        <StageNav back="investigate" next="retest" nextLabel="Continue to Retest" />
      </main>
      <aside className="prediction-panel">
        <div className="prediction-panel__head"><div><div className="eyebrow">Active control</div><h2>{m.posture.toUpperCase()}</h2></div></div>
        <dl className="m-meta">
          <div><dt>Active posture</dt><dd>{m.posture.toUpperCase()} {m.defenseApplied ? "(applied)" : "(not applied yet)"}</dd></div>
          <div><dt>Rule evaluated by CTRL-LOANDESK-001</dt><dd>{RULE[m.posture]}</dd></div>
          <div><dt>Bounds</dt><dd>Closed set of two values. Applies per run, is recorded on every event as <code>agentsec.defense.posture</code>, and changes no stored data.</dd></div>
          <div><dt>Trade-off</dt><dd>HARDENED also rejects the agent's own helpful prose. It must retry with a code.</dd></div>
        </dl>
        <div className="privacy-note"><Icon name="shield" size={18} /><span>You can switch back at any time. The choice is yours; the run records it.</span></div>
      </aside>
    </div>
  </>;
}
