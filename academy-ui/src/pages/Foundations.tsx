import { Button, Icon } from "../ui";
import { StageGuide } from "../StageGuide";
import { Link, MASTERY_PATH, missionPath } from "../router";
import { updateMission, useMission } from "../store";
import { Glossary } from "../mission/parts";
import content from "../content/academy-content.json";

// The four existing Foundations lessons (exported from the classic Academy by scripts/export_academy_content.py), shown in the React Academy.
export function Foundations() {
  const m = useMission();
  const read = m.foundationsRead ?? [];
  const lessons = content.foundations;
  const toggle = (id: string) => updateMission((s) => { const r = s.foundationsRead ?? []; return { ...s, foundationsRead: r.includes(id) ? r.filter((x) => x !== id) : [...r, id] }; });
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">Beginner route · No prerequisites</div>
      <h1>Understand AI before you secure it</h1>
      <p>Four short lessons build the mental model for the labs. Each ends with the security idea you will test against real evidence.</p>
    </div></header>
    <StageGuide learning="How a model, an agent, a tool call and a recorded event differ." todo="Read the four lessons in order and mark each one read."
      happened={`${read.length} of ${lessons.length} lessons marked read in this browser.`}
      next={read.length === lessons.length ? "Start the Loan Desk mission, or test yourself in Mastery." : "Finish the lessons, then start the Loan Desk mission."} />
    <nav className="toc" aria-label="Lessons"><ol>{lessons.map((l) => <li key={l.id}><a href={`#lesson-${l.id}`}>{l.title}{read.includes(l.id) ? " ✓" : ""}</a></li>)}</ol></nav>
    {lessons.map((l, i) => <section className="m-lesson" id={`lesson-${l.id}`} key={l.id} aria-labelledby={`h-${l.id}`}>
      <div className="lesson-label">Lesson {i + 1} of {lessons.length}</div>
      <h2 id={`h-${l.id}`}>{l.title}</h2>
      <p className="m-lesson__q"><strong>Start with a question:</strong> {l.question}</p>
      <p>{l.concept}</p>
      <ol className="m-flow" aria-label={`${l.title}: how it flows`}>{l.flow.map((f) => <li key={f}>{f}</li>)}</ol>
      <div className="learning-note"><Icon name="shield" size={18} /><div><strong>Security connection</strong><p>{l.risk}</p></div></div>
      <div className="m-actions"><Button variant={read.includes(l.id) ? "secondary" : "primary"} onClick={() => toggle(l.id)}>{read.includes(l.id) ? "Marked as read (undo)" : "Mark as read"}</Button></div>
    </section>)}
    <section className="m-section"><div className="lesson-label">Words you will meet</div><Glossary /></section>
    <div className="m-actions">
      <Link className="button button--primary" to={missionPath("learn")}>Start the Loan Desk mission <Icon name="arrow" size={15} /></Link>
      <Link className="button button--secondary" to={MASTERY_PATH}>Test yourself in Mastery</Link>
    </div>
  </div>;
}
