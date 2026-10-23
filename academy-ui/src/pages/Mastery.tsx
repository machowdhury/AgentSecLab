import { useState } from "react";
import { Badge, Button } from "../ui";
import { StageGuide } from "../StageGuide";
import { updateMission, useMission } from "../store";
import { QUIZ } from "../mission/content";
import content from "../content/academy-content.json";

const MIN_WRITTEN = 20;
// The 13 MCP knowledge checks, grouped by the idea they test (ids are the existing check ids; nothing is reworded).
const SECTIONS = [
  { title: "Decision vs execution", ids: ["MCP-001-Q01", "MCP-001-Q02", "MCP-001-Q03", "MCP-001-Q04"] },
  { title: "Evidence and its limits", ids: ["MCP-001-Q05", "MCP-001-Q06", "MCP-001-Q09", "MCP-001-Q10"] },
  { title: "Trust and boundaries", ids: ["MCP-001-Q07", "MCP-001-Q08"] },
  { title: "Detection logic", ids: ["MCP-001-Q11", "MCP-001-Q12", "MCP-001-Q13"] },
] as const;
type Verdict = "covered" | "partly" | "not_yet";

// Existing assessment content: the Loan Desk knowledge check as multiple choice (auto-marked) and the MCP knowledge checks as written answers
// compared with the reference answers. Only multiple-choice answers produce a score; written answers are self-assessed and not scored.
export function Mastery() {
  const m = useMission();
  const mcq = m.mastery?.mcq ?? {}, written = m.mastery?.written ?? {};
  const ref = content.checks.loandesk;
  const setMcq = (id: string, v: string | null) => updateMission((s) => { const q = { ...s.mastery?.mcq }; if (v === null) delete q[id]; else q[id] = v; return { ...s, mastery: { ...s.mastery, mcq: q } }; });
  const setW = (id: string, patch: Partial<NonNullable<typeof written[string]>>) => updateMission((s) => ({ ...s, mastery: { ...s.mastery, written: { ...s.mastery?.written, [id]: { text: "", ...s.mastery?.written?.[id], ...patch } } } }));
  const answered = QUIZ.filter((q) => mcq[q.id]).length, correct = QUIZ.filter((q) => mcq[q.id] === q.answer).length;
  const wChecks = content.checks.mcp;
  const [sec, setSec] = useState(0);
  const cur = SECTIONS[sec];
  const number = (id: string) => wChecks.findIndex((c) => c.id === id) + 1;
  const compared = wChecks.filter((c) => written[c.id]?.revealed).length, covered = wChecks.filter((c) => written[c.id]?.verdict === "covered").length;
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">Assess</div><h1>Mastery</h1>
      <p>Test what you understood, not just what you clicked. Answer first, then read the explanation.</p>
    </div></header>
    <StageGuide learning="Whether you can explain who decides, what ALLOW means and what proves execution."
      todo="Answer the Loan Desk questions, then write your own answers to the MCP questions and compare them."
      happened={answered ? `Loan Desk: ${correct} of ${answered} answered correctly (${QUIZ.length - answered} left). MCP: ${compared} of ${wChecks.length} compared.` : "You have not answered anything yet."}
      next={answered === QUIZ.length ? "Review any miss, then continue with the MCP written questions." : "Answer the Loan Desk questions below."} />
    <section className="m-section" aria-labelledby="h-mcq"><div className="lesson-label">Loan Desk · multiple choice</div><h2 id="h-mcq">Loan Desk check</h2>
      <p className="m-score" role="status">{answered ? <><strong>{correct} of {answered}</strong> correct so far. This score is computed only from the answers you gave.</> : "No score yet: it appears as you answer."}</p>
      {QUIZ.map((q, i) => { const pick = mcq[q.id]; const ok = pick === q.answer; return <fieldset className="m-q" key={q.id}>
        <legend>{q.prompt}</legend>
        {q.options.map(([v, label]) => <label className="m-choice" key={v}><input type="radio" name={q.id} checked={pick === v} onChange={() => setMcq(q.id, v)} /><span>{label}</span></label>)}
        {pick && <div className={`m-feedback ${ok ? "is-right" : "is-wrong"}`} role="status"><Badge tone={ok ? "allow" : "deny"}>{ok ? "CORRECT" : "NOT QUITE"}</Badge>
          <p>{ok ? "" : "Correct answer: "}{ref[i]?.answer}</p>
          {!ok && <Button variant="ghost" onClick={() => setMcq(q.id, null)}>Try again</Button>}</div>}
      </fieldset>; })}
    </section>
    <section className="m-section" aria-labelledby="h-written"><div className="lesson-label">MCP Tool Authorization · written</div><h2 id="h-written">Explain it in your own words</h2>
      <p className="m-score" role="status">{compared} of {wChecks.length} compared · {covered} marked as covered by you. These are self-assessed and not scored.</p>
      <div className="m-steps" role="group" aria-label="Written question sections">
        {SECTIONS.map((x, i) => { const n = x.ids.filter((id) => written[id]?.revealed).length; return <button type="button" key={x.title} className={`m-steps__tab ${i === sec ? "is-current" : ""}`} aria-current={i === sec ? "step" : undefined} onClick={() => setSec(i)}>
          <span>Section {i + 1} of {SECTIONS.length}</span><strong>{x.title}</strong><small>{n} of {x.ids.length} compared</small></button>; })}
      </div>
      {cur.ids.map((id) => { const c = wChecks.find((x) => x.id === id)!; return <WrittenQ key={id} n={number(id)} id={id} q={c.question} a={c.answer} st={written[id]} set={(p) => setW(id, p)} />; })}
      <div className="m-actions">
        <Button variant="secondary" disabled={sec === 0} onClick={() => setSec(sec - 1)}>Previous section</Button>
        <Button disabled={sec === SECTIONS.length - 1} onClick={() => setSec(sec + 1)}>Next section</Button>
      </div>
    </section>
  </div>;
}

function WrittenQ({ n, id, q, a, st, set }: { n: number; id: string; q: string; a: string; st?: { text: string; revealed?: boolean; verdict?: Verdict }; set: (p: Partial<{ text: string; revealed: boolean; verdict: Verdict }>) => void }) {
  const text = st?.text ?? "";
  return <div className="m-q m-written">
    <label htmlFor={`w-${id}`}><strong>{n}.</strong> {q.replace(/`/g, "")}</label>
    <textarea id={`w-${id}`} rows={2} maxLength={800} value={text} onChange={(e) => set({ text: e.target.value })} />
    {!st?.revealed ? <Button variant="secondary" disabled={text.trim().length < MIN_WRITTEN} onClick={() => { set({ revealed: true }); }}>Compare with the reference answer</Button>
      : <div className="m-feedback" role="status"><strong>Reference answer</strong><p>{a.replace(/`/g, "")}</p>
        <fieldset className="m-verdict"><legend>Did your answer cover it?</legend>
          {([["covered", "Yes"], ["partly", "Partly"], ["not_yet", "Not yet"]] as [Verdict, string][]).map(([v, l]) => <label className="m-choice" key={v}><input type="radio" name={`v-${id}`} checked={st.verdict === v} onChange={() => set({ verdict: v })} /><span>{l}</span></label>)}
        </fieldset></div>}
    {!st?.revealed && text.trim().length < MIN_WRITTEN && <p className="m-muted">Write at least {MIN_WRITTEN} characters to unlock the reference answer.</p>}
  </div>;
}
