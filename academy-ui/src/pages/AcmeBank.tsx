import { Icon } from "../ui";
import { Link, missionPath } from "../router";
import { useSlot } from "../mission/runStore";
import { ApplicationForm } from "../mission/ApplicationForm";
import { RunDetails, RunPanel } from "../mission/parts";

// World 1, inside the Academy: the real AcmeBank Loan Desk application. Same form, same BASELINE run and same evidence as the mission's Prepare stage.
export function AcmeBank() {
  const slot = useSlot("explore");
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">World 1 · Business</div>
      <h1>AcmeBank loan application</h1>
      <p>An applicant asks AcmeBank for a home loan. An AI agent reviews it, a separate policy engine decides each action, and a human underwriter reads the note it files. This is the real application, running live. You never leave the Academy.</p>
    </div></header>
    <div className="workbench">
      <section className="scenario-pane">
        <div className="panel-label">01 — Apply</div>
        <h2>Submit an application</h2>
        <ApplicationForm />
      </section>
      <aside className="run-pane">
        <div className="panel-label">02 — Review progress</div>
        <RunPanel slot="explore" idle="No application yet. Submit one to watch the agent review it." />
      </aside>
    </div>
    {slot.view && slot.view.status !== "RUNNING" && <section className="m-section" aria-labelledby="h-bank-result"><div className="lesson-label">Result</div><h2 id="h-bank-result">What the review did</h2><RunDetails view={slot.view} /></section>}
    <div className="m-actions"><Link className="button button--primary" to={missionPath("learn")}>Continue to the Loan Desk mission <Icon name="arrow" size={15} /></Link></div>
  </div>;
}
