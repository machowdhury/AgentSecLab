import { useState } from "react";
import { Badge, Button } from "../ui";
import { Callout, CopyButton } from "../mission/parts";
import type { Checkpoint, Study, StudyQuestion } from "../curriculum";
import { dig, text } from "./checkpoint";

type Spec = Study & Checkpoint["spec"];
const src = (f: string) => f.split("/").pop();
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

export function Question({ q, picked, onPick, shown, onCheck }: { q: StudyQuestion; picked: string[]; onPick: (v: string[]) => void; shown: boolean; onCheck: () => void }) {
  const toggle = (o: string, on: boolean) => onPick(q.mode === "single" ? [o] : on ? [...picked, o] : picked.filter((x) => x !== o));
  return <li className="rec-q"><fieldset disabled={shown}><legend>{q.prompt}</legend>
    <div className="rec-options">{q.candidates.map((o) => <label key={o}><input type={q.mode === "single" ? "radio" : "checkbox"} name={q.id} value={o} checked={picked.includes(o)} onChange={(e) => toggle(o, e.target.checked)} /> {o}</label>)}</div></fieldset>
    {!shown && <div className="m-actions"><Button disabled={picked.length === 0} onClick={onCheck}>Check against the sources</Button></div>}
    {shown && <div role="status" className="rec-reveal"><p>The committed sources give: <strong>{q.answer.join(", ")}</strong>. You chose {picked.join(", ")}{sameSet(picked, q.answer) ? " — that matches." : " — that does not match."}</p>
      {q.how && <p className="m-muted">Computed from: {q.how}.</p>}
      {q.quote && <p className="m-muted">The lab's own wording: <q>{q.quote.text}</q> <small className="m-src">Source: <code>{src(q.quote.file)}</code></small></p>}</div>}
  </li>;
}

function Compare({ cp, spec }: { cp: Checkpoint; spec: Spec }) {
  const c = spec.compare!, l = dig(cp.packet, c.left.path) as Record<string, string>, r = dig(cp.packet, c.right.path) as Record<string, string>;
  const need = new Map((dig(cp.packet, c.need.path) as Record<string, unknown>[]).map((x) => [String(x[c.need.key]), x[c.need.flag]]));
  const keys = [...new Set([...Object.keys(l), ...Object.keys(r)])];
  return <div className="m-sec"><h4>Compare the two records</h4>
    <div className="table-wrap" tabIndex={0} role="region" aria-label={`${c.title}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{c.title}, values as the data map records them</caption>
      <thead><tr><th scope="col">Field</th><th scope="col">{c.left.label}</th><th scope="col">{c.right.label}</th><th scope="col">{c.need.label}</th></tr></thead>
      <tbody>{keys.map((k) => <tr key={k} className={l[k] === r[k] ? "" : "rec-differs"}><th scope="row">{k}{l[k] !== r[k] && <small> (only in the {r[k] === undefined ? c.left.label.toLowerCase() : c.right.label.toLowerCase()})</small>}</th>
        <td data-label={c.left.label}>{l[k] ?? "—"}</td><td data-label={c.right.label}>{r[k] ?? "—"}</td><td data-label={c.need.label}>{need.has(k) ? (need.get(k) ? "yes" : "no") : "not classified"}</td></tr>)}</tbody></table></div>
    <h4>What authorization decided, as the lab documents it</h4>
    <p className="m-muted">Quoted from the lab's own notes and its existing test. These are documented statements; nothing was re-run to produce them.</p>
    <dl className="rec-fields">{(spec.documented ?? []).map((d) => <div key={d.label}><dt>{d.label}</dt><dd><q>{d.text}</q> <small className="m-src">Source: <code>{src(d.file)}</code></small></dd></div>)}</dl>
  </div>;
}

/** Practice for a documented or recorded study: answer questions whose options and answers were computed from the committed sources. Nothing here launches a run. */
export function StudyPractice({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec as Spec;
  const [picks, setPicks] = useState<Record<string, string[]>>({});
  const [shown, setShown] = useState<Record<string, boolean>>({});
  return <div className="m-sec rec" data-testid="checkpoint-workbench">
    <h3>Study workbench <Badge tone="replay">{spec.label}</Badge></h3>
    <p className="m-muted">Every option and every answer below is computed from committed source files. Nothing is launched, no model is called and nothing is sent to Splunk. Your answers are not evidence.</p>
    {spec.steps.map((st) => <div className="m-sec" key={st.title}><h4>{st.title} <Badge tone="muted">YOUR ANSWER IS NOT EVIDENCE</Badge></h4><p className="m-muted">{st.intro}</p>
      <ol className="rec-qs">{st.questions.map((q) => <Question key={q.id} q={q} picked={picks[q.id] ?? []} onPick={(v) => setPicks({ ...picks, [q.id]: v })} shown={Boolean(shown[q.id])} onCheck={() => setShown({ ...shown, [q.id]: true })} />)}</ol></div>)}
    {spec.compare && <Compare cp={cp} spec={spec} />}
  </div>;
}

/** Prove for a study: the sources' own assertions, tables, limits and the hash of every source file. */
export function StudyProve({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec as Spec;
  return <div className="m-sec rec" data-testid="checkpoint-prove">
    <h3>What the sources say, and where they come from <Badge tone="replay">{spec.label}</Badge></h3>
    <Callout kind="warn"><strong>Verification status: not verified here.</strong> {spec.verification}</Callout>
    <div className="m-sec"><h4>What the sources themselves state</h4>
      <dl className="rec-fields">{(spec.facts ?? []).map((f) => <div key={f.path}><dt>{f.label}</dt><dd>{text(dig(cp.packet, f.path))}</dd></div>)}</dl></div>
    {(spec.tables ?? []).map((t) => <div className="m-sec" key={t.path}><h4>{t.title}</h4><div className="table-wrap" tabIndex={0} role="region" aria-label={`${t.title}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{t.title}, unedited</caption>
      <thead><tr>{t.columns.map(([, l]) => <th scope="col" key={l}>{l}</th>)}</tr></thead>
      <tbody>{(dig(cp.packet, t.path) as Record<string, unknown>[]).map((r, i) => <tr key={i}>{t.columns.map(([k, l]) => <td key={k} data-label={l}>{text(r[k])}</td>)}</tr>)}</tbody></table></div></div>)}
    {(spec.lists ?? []).map((l) => <div className="m-sec" key={l.path}><h4>{l.title}</h4><ul className="m-rules">{(dig(cp.packet, l.path) as string[]).map((x) => <li key={x}>{x}</li>)}</ul></div>)}
    <div className="m-sec"><h4>Limits, in the sources' own words</h4><ul className="m-rules">{spec.limits.map((x) => <li key={x.text}><q>{x.text}</q> <small className="m-src">Source: <code>{src(x.file)}</code></small></li>)}</ul></div>
    <details className="m-details"><summary>Provenance of each source file</summary>
      <dl className="rec-fields">{(cp.files ?? []).map((f) => <div key={f.name}><dt><code>{f.file}</code></dt><dd>SHA-256 <code>{f.sha256}</code></dd></div>)}</dl>
      <p className="m-muted">Each file is shown as committed. Nothing on this page upgrades a documented or recorded source to a live or measured result.</p></details>
    {cp.spl.length > 0 && <div className="m-sec"><h3>The lab's searches (SPL)</h3>
      <p className="m-muted">Shown as written in the lab. They are not run from this page.</p>
      {cp.spl.map((q) => <details className="m-details" key={q.source}><summary><code>{q.name}</code></summary><pre>{q.text}</pre><CopyButton text={q.text} label="Copy search" /><small className="m-src">Source: <code>{q.source}</code></small></details>)}</div>}
  </div>;
}
