import { Icon } from "../../ui";
import { useConfig } from "../../config";
import { FLOW } from "../content";
import { Brief, Glossary } from "../parts";
import { ModelCheck } from "../ModelCheck";
import { StageNav } from "../StageNav";

export function Learn() {
  const { config } = useConfig();
  const m = config.mission;
  return <div className="workshop-grid">
    <div className="lesson">
      <div className="lesson-label">01 — Learn</div>
      <h2>Meet the Loan Desk</h2>
      <p className="lead">A real AI agent reviews synthetic loan applications and files a note in the human underwriter queue. You will make it file something an attacker wrote, prove it from recorded evidence, change one control, and prove the change worked.</p>
      <Brief step="understand" />
      <section className="flow-card">
        <div className="section-heading"><div><div className="eyebrow">How it is built</div><h3>Follow the request across boundaries</h3></div></div>
        <ol className="m-flow">{FLOW.map(([name, text], i) => <li key={name}><span>{i + 1}</span><div><strong>{name}</strong><small>{text}</small></div>{i < FLOW.length - 1 && <Icon name="arrow" size={16} />}</li>)}</ol>
      </section>
      <section className="why-card"><Icon name="shield" /><div><h3>Lab boundaries</h3><ul className="m-list">{(m?.boundaries ?? []).map((b) => <li key={b}>{b}</li>)}</ul></div></section>
      <section className="m-card"><h3>The model behind this mission</h3><ModelCheck /></section>
      <Glossary />
      <StageNav next="prepare" nextLabel="Continue to Prepare" />
    </div>
    <aside className="prediction-panel">
      <div className="prediction-panel__head"><div><div className="eyebrow">Before you start</div><h2>What to expect</h2></div></div>
      <dl className="m-meta">
        <div><dt>Time</dt><dd>About {m?.duration_minutes ?? "25 to 40"} minutes at a steady pace (an author estimate, not yet measured with learners)</dd></div>
        <div><dt>Level</dt><dd>Level 1, guided. You need no agent or Splunk experience.</dd></div>
      </dl>
      <h3 className="m-h3">By the end you will be able to</h3>
      <ul className="m-list">{(m?.objectives ?? []).map((o) => <li key={o}>{o}</li>)}</ul>
      <h3 className="m-h3">What you need</h3>
      <ul className="m-list">{(m?.prerequisites ?? []).map((p) => <li key={p}>{p}</li>)}</ul>
      <div className="privacy-note"><Icon name="status" size={18} /><span>Your predictions and answers stay in this browser. Splunk evidence is LOCAL until a host-side check or your own search confirms it.</span></div>
    </aside>
  </div>;
}
