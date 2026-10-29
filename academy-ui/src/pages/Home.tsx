import { Badge, Icon, LinkButton, ProgressBar } from "../ui";
import { FOUNDATIONS_PATH, Link, PATH_PATH, missionPath } from "../router";
import { useConfig } from "../config";
import { useMission, stageComplete, firstOpenIncomplete } from "../store";
import { STAGES, type StageId } from "../stages";
import { useRunViews, reviewCall } from "../runs";
import type { Slot } from "../types";

export function Home() {
  const { config } = useConfig();
  const m = useMission();
  const done = STAGES.filter((s) => stageComplete(s.id, m)).length;
  const started = m.seen.length > 0 || Object.keys(m.runs).length > 0;
  const next: StageId = firstOpenIncomplete(m);
  const nextStage = STAGES.find((s) => s.id === next)!;
  const slots = (["explore", "attack", "retest"] as Slot[]).filter((s) => m.runs[s]);
  const ids = slots.map((s) => m.runs[s]!);
  const views = useRunViews(ids);

  return <div className="page home">
    <section className="hero">
      <div className="eyebrow">HANDS-ON AGENTIC AI SECURITY ACADEMY</div>
      <h1>Learn to investigate how<br />AI agents <em>actually</em> behave.</h1>
      <p>Build practical security judgment through guided labs. Predict control behavior, launch experiments, and prove what happened using runtime evidence.</p>
      <div className="hero__actions">
        <LinkButton href={started ? missionPath(next) : missionPath("learn")} icon="arrow" internal>{started ? "Continue the Loan Desk mission" : "Start the Loan Desk mission"}</LinkButton>
        <LinkButton href={FOUNDATIONS_PATH} variant="secondary" internal>New here? Start with AI basics</LinkButton>
      </div>
      <div className="hero__principle"><Icon name="shield" /><span><strong>Core principle</strong> Control decision ≠ Execution ≠ Observed evidence</span></div>
    </section>

    <section className="novice-start">
      <div className="novice-start__intro"><span className="novice-start__number">START</span><div><div className="eyebrow">First time here?</div><h2>You do not need an AI or security background.</h2><p>Begin with a short guided route. We explain the system before asking you to investigate it.</p></div></div>
      <div className="starter-route">
        {[["01", "Understand", "How LLMs generate responses"], ["02", "Connect", "How agents use tools and data"], ["03", "Recognize", "Where security risks appear"], ["04", "Practice", "Investigate your first run"]].map(([n, t, d], i) =>
          <div className="starter-step" key={t}><span>{n}</span><div><strong>{t}</strong><small>{d}</small></div>{i < 3 && <Icon name="arrow" size={16} />}</div>)}
      </div>
      <LinkButton href={FOUNDATIONS_PATH} icon="arrow" internal>Start the beginner route</LinkButton>
    </section>

    <section className="three-worlds">
      <div className="section-heading"><div><div className="eyebrow">One story, three connected worlds</div><h2>Start with the person—not the telemetry.</h2></div><span className="section-note">Business → AI behavior → Evidence</span></div>
      <div className="world-grid">
        <Link className="world-card world-card--business" to={missionPath("prepare")}><span className="world-number">WORLD 1</span><div className="world-icon"><Icon name="home" /></div><small>BUSINESS</small><h3>AcmeBank</h3><p>What is the customer trying to do?</p><strong>Open the loan application <Icon name="arrow" size={15} /></strong></Link>
        <div className="world-connector"><Icon name="arrow" /></div>
        <Link className="world-card world-card--security" to={missionPath()}><span className="world-number">WORLD 2</span><div className="world-icon"><Icon name="shield" /></div><small>AI / SECURITY</small><h3>AgentSec</h3><p>What did the AI agent actually do?</p><strong>Follow the behavior <Icon name="arrow" size={15} /></strong></Link>
        <div className="world-connector"><Icon name="arrow" /></div>
        <Link className="world-card world-card--evidence" to={missionPath("investigate")}><span className="world-number">WORLD 3</span><div className="world-icon"><Icon name="search" /></div><small>OBSERVABILITY</small><h3>Splunk</h3><p>What evidence proves what happened?</p><strong>Investigate evidence <Icon name="arrow" size={15} /></strong></Link>
      </div>
    </section>

    <section className="section">
      <div className="section-heading"><div><div className="eyebrow">Learning progress</div><h2>{started ? "Continue where you left off" : "Your first mission"}</h2></div>{config.gateway ? <Link className="text-link" to={PATH_PATH}>View your learning path <Icon name="arrow" size={16} /></Link> : <a className="text-link" href="/academy/path">View your learning path <Icon name="arrow" size={16} /></a>}</div>
      <div className="progress-card">
        <div className="progress-card__stat"><strong>{done}<span> / {STAGES.length}</span></strong><p>Loan Desk stages done</p></div>
        <div className="progress-card__main"><div className="progress-card__row"><span>Loan Desk mission</span><strong>{Math.round(done / STAGES.length * 100)}%</strong></div><ProgressBar value={done / STAGES.length * 100} /><div className="level-row"><Badge>LEVEL 1</Badge><span>About {config.mission?.duration_minutes ?? "25 to 40"} minutes · live agent</span></div></div>
        <div className="next-card"><div><small>{started ? "NEXT STAGE" : "START HERE"}</small><h3>{started ? nextStage.label : "Loan Desk: when the agent writes for the underwriter"}</h3><p>{nextStage.blurb}.</p></div><Link to={missionPath(next)} aria-label={`Continue to ${nextStage.label}`} className="next-card__go"><Icon name="arrow" /></Link></div>
      </div>
    </section>

    <section className="section workflow-section">
      <div className="eyebrow">How AgentSec works</div><h2>Security reasoning, practiced end to end</h2>
      <div className="workflow">{STAGES.map((s, i) => <div className="workflow__step" key={s.id}><span>{String(i + 1).padStart(2, "0")}</span><strong>{s.label}</strong>{i < STAGES.length - 1 && <Icon name="arrow" size={16} />}</div>)}</div>
    </section>

    <section className="section">
      <div className="section-heading"><div><div className="eyebrow">Recent investigations</div><h2>Your latest evidence work</h2></div></div>
      {slots.length === 0
        ? <div className="empty-state"><Icon name="book" /><div><strong>No investigations yet</strong><p>Runs you launch in the Loan Desk mission appear here, with their real run ids. Nothing on this page is sample data.</p></div></div>
        : <div className="table-wrap"><table><thead><tr><th>Run</th><th>Mode</th><th>Launched</th><th>Control decision</th><th>Execution</th><th>Investigation</th></tr></thead><tbody>
          {slots.map((slot) => {
            const id = m.runs[slot]!; const v = views[id]; const c = v ? reviewCall(v) : undefined;
            return <tr key={slot}>
              <td><strong>Loan Desk · {slot}</strong><br /><code>{id}</code></td>
              <td><Badge tone="live">LIVE</Badge></td>
              <td>{m.launched[slot] ? new Date(m.launched[slot]!).toLocaleString() : "—"}</td>
              <td>{v === undefined ? "…" : v === null ? <Badge tone="muted">RUN NO LONGER AVAILABLE</Badge> : c ? <Badge tone={c.decision === "ALLOW" ? "allow" : "deny"}>{c.decision}</Badge> : <Badge tone="muted">NO REVIEW SUBMITTED</Badge>}</td>
              <td>{v === undefined ? "…" : v === null ? "—" : c ? <Badge tone={c.executed ? "observed" : "muted"}>{c.executed ? "HANDLER BEGAN" : "NOT EXECUTED"}</Badge> : <Badge tone="muted">NOT OBSERVED</Badge>}</td>
              <td><Link className="text-link" to={missionPath("investigate")}>Open investigation <Icon name="arrow" size={14} /></Link></td>
            </tr>;
          })}
        </tbody></table></div>}
    </section>
  </div>;
}
