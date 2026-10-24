import { useState, type ReactNode } from "react";
import { Badge, Button, Icon } from "../ui";
import { StageGuide } from "../StageGuide";
import { CURRICULUM_PATH, Link } from "../router";
import { AVAIL, REGISTRY_NOTE, domainName, labById, type Entry, type Lab } from "../curriculum";
import { AttackPath } from "../AttackPath";
import { Glossary } from "../mission/parts";
import { CopyButton } from "../mission/parts";
import { availTone } from "./Curriculum";
import { PiLiveEvidence, PiPractice } from "../workbench/PiWorkbench";
import { RagLiveEvidence, RagPractice } from "../workbench/RagWorkbench";
import { ScenarioLiveEvidence, ScenarioPractice } from "../workbench/ScenarioWorkbench";
import { SCENARIOS } from "../workbench/scenarios";
import { RecordedPractice, RecordedProve } from "../workbench/RecordedWorkbench";

type Tab = "learn" | "practice" | "prove" | "all";
type EntryKey = Exclude<keyof Lab["sections"], "learn">;
const SECTION_TITLES: [EntryKey, string][] = [["idea", "The idea of this lab"], ["problem", "The attack or security problem"], ["why", "Why it matters"], ["controls", "What the attacker controls"], ["boundary", "Where the trust boundary is"], ["how", "How the attack or failure happens"]];
const base = (p: string) => p.split("/").pop()!.split("#")[0];

/** One reusable lab page. Explanations are written for learners and grounded in named sources; quoted text and recorded evidence are labelled as such; nothing undocumented is shown. */
export function LabPage({ id }: { id: string }) {
  const lab = labById(id);
  const [tab, setTab] = useState<Tab>("learn");
  if (!lab) return <div className="page"><header className="page-header"><div><div className="eyebrow">Not found</div><h1>No such lab</h1><p><Link to={CURRICULUM_PATH}>Back to the Curriculum Explorer</Link></p></div></header></div>;
  const s = lab.sections, ex = lab.explainer;
  const have = (e: unknown) => Boolean(e);
  const quoted = SECTION_TITLES.filter(([k]) => s[k]);
  const missing = (Object.keys(s) as (keyof Lab["sections"])[]).filter((k) => !s[k]);
  const hasLearn = Boolean(ex?.summary || ex?.known || s.learn || quoted.length);
  const hasPractice = Boolean(ex?.practice || s.predict || s.defend || lab.native || lab.availability === "workbench" || lab.assets.specimens.length);
  const hasProve = Boolean(ex?.spl || ex?.identifiers || ex?.recorded_table || ex?.cannot_claim || lab.limitations || s.conclude || lab.assets.hunts.length || lab.assets.dashboard || lab.assets.evidence_docs.length || lab.checks.length);
  const tabs = ([["learn", "Learn", hasLearn], ["practice", "Practice", hasPractice], ["prove", "Prove", hasProve], ["all", "All sections (expert)", true]] as [Tab, string, boolean][]).filter((t) => t[2]);
  const show = (t: Tab) => (tab === t || tab === "all") && tabs.some((x) => x[0] === t);
  const full = ex?.status === "full";
  const summaryText = ex?.summary?.text ?? s.idea?.text ?? lab.registry_quote?.quote ?? "";
  const todo = lab.native ? "Open the guided exercise in Practice." : full && lab.availability === "workbench" ? "Read Learn, make your prediction in Practice, then look at the evidence in Prove." : hasPractice ? "Read what is available below." : "Read what the lab's files record, then test yourself in Prove.";
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">{domainName(lab.primary_domain)}{lab.secondary_domain ? ` · also ${domainName(lab.secondary_domain)}` : ""}</div>
      <h1>{lab.title}</h1>
      <p><code>{lab.id}</code> · <Badge tone={availTone(lab.availability)}>{AVAIL[lab.availability].label.toUpperCase()}</Badge>{lab.launchable && <> <Badge tone="observed">ON THE ATTACK SERVICE ALLOWLIST</Badge></>}{lab.integrated && <> <Badge tone="live">NATIVE IN THIS ACADEMY</Badge></>}{lab.level && <> <Badge tone="neutral">{lab.level}</Badge></>}</p>
      <p>{AVAIL[lab.availability].blurb} {REGISTRY_NOTE}</p>
    </div></header>
    {!full && <div className="m-notice" role="note"><Icon name="book" size={18} /><div><strong>Full guided lesson not yet available</strong><p>Only what this lab's own files support is shown below. Anything they do not document is left out rather than filled in.</p></div></div>}
    <StageGuide learning={summaryText || "See below."} todo={todo}
      happened={full ? "A learner explanation grounded in the lab's files, with every source named." : `${(Object.values(s) as unknown[]).filter(have).length} of 10 sections are documented in the lab's files.`}
      next={lab.native ? "Open the guided exercise." : tabs.length > 2 ? `Move through the tabs: ${tabs.filter((t) => t[0] !== "all").map((t) => t[1]).join(", ")}.` : "Check yourself with the knowledge check, if there is one."} />
    {tabs.length > 2 && <div role="tablist" aria-label="Lab sections" className="m-steps">
      {tabs.map(([t, label], i) => <button key={t} type="button" role="tab" aria-selected={tab === t} className={`m-steps__tab ${tab === t ? "is-current" : ""}`} onClick={() => setTab(t)}><span>{t === "all" ? "Everything" : `Step ${i + 1}`}</span><strong>{label}</strong></button>)}
    </div>}

    {show("learn") && <section aria-label="Learn" className="m-card">
      <div className="panel-label">Learn</div><h2>Understand it in plain English</h2>
      {ex?.summary && <div className="m-explain"><Badge tone="live">EXPLANATION</Badge><p className="m-lead">{ex.summary.text}</p><Based on={ex.summary.grounds} /></div>}
      {ex?.glance && <div className="m-glance"><h3>The attack at a glance</h3>
        <dl>{ex.glance.map((g) => <div key={g.id}><dt>{g.label}</dt><dd>{g.text}<Based on={g.grounds} /></dd></div>)}</dl></div>}
      {ex?.path && <AttackPath nodes={ex.path} title="How the attack could travel, from the lab's files" />}
      {ex?.known && <div className="m-glance"><h3>What the lab's files record</h3><ul className="m-rules">{ex.known.map((k) => <li key={k.text}>{k.text}<Based on={k.grounds} /></li>)}</ul></div>}
      {ex?.terms && <div className="m-glance"><h3>Terms you will meet</h3><dl>{ex.terms.map((t) => <div key={t.term}><dt>{t.term}</dt><dd>{t.text}<Based on={[t.source]} /></dd></div>)}</dl></div>}
      {!ex && (s.learn || quoted.length > 0) && <div className="m-quoted"><Badge tone="muted">QUOTED FROM THE LAB'S DOCUMENTS</Badge>
        {s.learn && <Block title="What will I learn?" src={s.learn.source}><LearnBody l={s.learn} /></Block>}
        {quoted.map(([k, title]) => <Block key={k} title={title} src={s[k]!.source}><p>{s[k]!.text}</p></Block>)}</div>}
      {lab.rules.length > 0 && <details className="m-details"><summary>Rules of thumb stated in this lab</summary><ul className="m-rules">{lab.rules.map((r) => <li key={r}>{r}</li>)}</ul></details>}
      {(ex?.path || ex?.glance) && <details className="m-details"><summary>The lab's own words, unedited</summary>
        <div className="m-quoted"><Badge tone="muted">QUOTED FROM THE LAB'S DOCUMENTS</Badge>
          {s.learn && <Block title="Learner objectives" src={s.learn.source}><LearnBody l={s.learn} /></Block>}
          {quoted.map(([k, title]) => <Block key={k} title={title} src={s[k]!.source}><p>{s[k]!.text}</p></Block>)}</div></details>}
      <details className="m-details"><summary>Shared terminology</summary><Glossary /></details>
    </section>}

    {show("practice") && <section aria-label="Practice" className="m-card">
      <div className="panel-label">Practice</div><h2>Predict, then try it</h2>
      {(ex?.practice?.predict || s.predict) && <div className="m-sec"><h3>What should I predict or investigate?</h3>
        {ex?.practice?.predict ? <ul className="m-rules">{ex.practice.predict.map((p) => <li key={p.label}><strong>{p.label}:</strong> {p.text}<small className="m-src">Source: <code>{p.source}</code></small></li>)}</ul>
          : s.predict && <><p>{s.predict.text}</p><Src src={s.predict.source} /></>}</div>}
      {lab.integrated && ex?.workbench ? <><Exercise lab={lab} />{lab.id === "LAB-PI-001" && <PiPractice lab={lab} />}{lab.id === "LAB-RAG-CONTEXT" && <RagPractice lab={lab} />}{SCENARIOS[lab.id] && <ScenarioPractice lab={lab} sc={SCENARIOS[lab.id]} />}</> : <Exercise lab={lab} />}
      {ex?.recorded && <RecordedPractice rec={ex.recorded} />}
      {(ex?.practice?.defender || s.defend) && <div className="m-sec"><h3>How would a defender address the issue?</h3>
        {ex?.practice?.defender ? <div className="m-explain"><Badge tone="live">EXPLANATION</Badge><p>{ex.practice.defender.text}</p><Based on={ex.practice.defender.grounds} /></div>
          : s.defend && <div className="m-quoted"><Badge tone="muted">QUOTED FROM THE LAB'S DOCUMENTS</Badge><p>{s.defend.text}</p><Src src={s.defend.source} /></div>}</div>}
    </section>}

    {show("prove") && <section aria-label="Prove" className="m-card">
      <div className="panel-label">Prove</div><h2>Technical identifiers, evidence and limits</h2>
      {lab.integrated && lab.id === "LAB-PI-001" && <PiLiveEvidence />}
      {lab.integrated && lab.id === "LAB-RAG-CONTEXT" && <RagLiveEvidence />}
      {lab.integrated && SCENARIOS[lab.id] && <ScenarioLiveEvidence sc={SCENARIOS[lab.id]} />}
      {ex?.recorded && <RecordedProve rec={ex.recorded} />}
      {ex?.identifiers && <div className="m-sec"><h3>Technical identifiers</h3><div className="table-wrap"><table><caption className="m-caption">Named in the lab's files</caption><tbody>{ex.identifiers.map((i) => <tr key={i.label}><th scope="row">{i.label}</th><td><code>{i.value}</code></td><td className="m-muted"><code>{base(i.source)}</code></td></tr>)}</tbody></table></div></div>}
      {ex?.recorded_table && <div className="m-sec"><h3>{ex.recorded_table.title} <Badge tone="replay">RECORDED, NOT RE-RUN</Badge></h3>
        <div className="table-wrap"><table className="m-stack"><caption className="m-caption">{ex.recorded_table.caption}</caption><thead><tr>{ex.recorded_table.columns.map((c) => <th scope="col" key={c}>{c}</th>)}</tr></thead>
          <tbody>{ex.recorded_table.rows.map((r, i) => <tr key={i}>{r.map((v, j) => <td key={j} data-label={ex.recorded_table!.columns[j]}>{v}</td>)}</tr>)}</tbody></table></div><Src src={ex.recorded_table.source} /></div>}
      {ex?.spl && <div className="m-sec"><h3>The lab's searches (SPL)</h3><p className="m-muted">Shown as written in the lab. They are not run from this page.</p>
        {ex.spl.map((q) => <details className="m-details" key={q.name}><summary><code>{q.name}</code></summary><pre>{q.text}</pre><CopyButton text={q.text} label="Copy search" /><Src src={q.source} /></details>)}</div>}
      <Evidence lab={lab} />
      {(ex?.cannot_claim || s.conclude) && <div className="m-sec"><h3>What can and cannot be concluded</h3>
        {ex?.cannot_claim && <><p>The lab's own documents say you may not claim:</p><ul className="m-rules">{ex.cannot_claim.items.map((c) => <li key={c}>{c}</li>)}</ul><Src src={ex.cannot_claim.source} /></>}
        {!ex?.cannot_claim && s.conclude && <div className="m-quoted"><Badge tone="muted">QUOTED FROM THE LAB'S DOCUMENTS</Badge><p>{s.conclude.text}</p><Src src={s.conclude.source} /></div>}</div>}
      {lab.limitations && <details className="m-details"><summary>Limitations stated in the lab's manifest ({lab.limitations.items.length})</summary><ul className="m-rules">{lab.limitations.items.map((x) => <li key={x}>{x}</li>)}</ul><Src src={lab.limitations.source} /></details>}
      <Checks lab={lab} />
      <details className="m-details"><summary>Sources, and what the files do not document</summary>
        <ul className="m-rules">{sourcesOf(lab).map((x) => <li key={x}><code>{x}</code></li>)}</ul>
        {missing.length > 0 && <p className="m-muted">Not documented in this lab's files: {missing.map((k) => SECTION_LABEL[k]).join(", ")}.</p>}
        {ex && <p className="m-muted">Explanations were written on {ex.authored.on}. {ex.authored.note}</p>}</details>
    </section>}
    <div className="m-actions"><Link className="button button--secondary" to={CURRICULUM_PATH}>Back to the Curriculum Explorer</Link></div>
  </div>;
}

const SECTION_LABEL: Record<string, string> = { learn: "objectives", idea: "the idea", problem: "the problem", why: "why it matters", controls: "what the attacker controls", boundary: "the trust boundary", how: "how it happens", predict: "what to predict", defend: "the defense", conclude: "conclusions" };
const Src = ({ src }: { src: string }) => <small className="m-src">Source: <code>{src}</code></small>;
const Based = ({ on }: { on: string[] }) => <small className="m-src">Based on: {on.map((x, i) => <span key={x}>{i ? ", " : ""}<code>{base(x)}</code></span>)}</small>;
function LearnBody({ l }: { l: NonNullable<Lab["sections"]["learn"]> }) { return "items" in l ? <ol>{l.items.map((o) => <li key={o}>{o}</li>)}</ol> : <p>{l.text}</p>; }
function Block({ title, src, children }: { title: string; src: string; children: ReactNode }) { return <div className="m-sec"><h3>{title}</h3>{children}<Src src={src} /></div>; }

function Exercise({ lab }: { lab: Lab }) {
  const a = lab.assets;
  return <div className="m-sec"><h3>What exercise or evidence is available?</h3>
    <p><strong>{AVAIL[lab.availability].label}.</strong> {AVAIL[lab.availability].blurb}</p>
    {lab.native && <div className="m-actions"><Link className="button button--primary" to={lab.native}>Open the guided exercise <Icon name="arrow" size={15} /></Link></div>}
    {lab.availability === "workbench" && !lab.integrated && <p className="m-muted">This lab is on the Attack Service allowlist, so a live attack and retest exist there. Nothing runs from this page.{" "}<a href={`/academy/labs/${lab.id}`}>Open the classic lab page (until it is migrated)</a>.</p>}
    {lab.integrated && <p className="m-muted">This lab is integrated natively: the guided sequence below launches its own catalog specimens through the Attack Service. The registry tier stays {AVAIL[lab.availability].label}.</p>}
    {lab.availability === "replay" && <p className="m-muted">Recorded evidence only: nothing is launched and no new run is created.</p>}
    {lab.availability === "content_only" && <p className="m-muted">There is nothing to launch or replay for this lab.</p>}
    {a.specimens.length > 0 && <><h4>Recorded specimen files ({a.specimens.length})</h4><ul className="m-rules">{a.specimens.map((x) => <li key={x}><code>{x}</code></li>)}</ul><Src src={`learning/level_1/${lab.id}/specimens/`} /></>}
  </div>;
}

function Evidence({ lab }: { lab: Lab }) {
  const a = lab.assets;
  if (!a.hunts.length && !a.dashboard && !a.evidence_docs.length) return null;
  return <div className="m-sec"><h3>Evidence assets the lab defines</h3>
    <ul className="m-rules">
      {a.hunts.length > 0 && <li>Splunk hunt queries: <strong>{a.hunts.length}</strong> (<code>{a.hunts.slice(0, 6).join(", ")}{a.hunts.length > 6 ? ", …" : ""}</code>)</li>}
      {a.dashboard && <li>Splunk dashboard: <code>{a.dashboard}</code> (a Dashboard Studio view in Splunk; not linked from the Academy)</li>}
      {a.evidence_docs.length > 0 && <li>Evidence documents: {a.evidence_docs.map((x) => <code key={x}>{x} </code>)}</li>}
    </ul>
    <p className="m-muted">These are assets the repository defines. Their presence does not mean a run exists or that the evidence was validated.</p>
  </div>;
}

function Checks({ lab }: { lab: Lab }) {
  const [shown, setShown] = useState<Record<number, boolean>>({});
  if (!lab.checks.length) return null;
  return <div className="m-sec"><h3>Knowledge check ({lab.checks.length})</h3>
    <p className="m-muted">Think of your answer first, then reveal the reference answer. This is not scored.</p>
    <ol className="m-checks">{lab.checks.map((c, i) => <li key={i}><p>{c.q}</p>
      {c.a ? (shown[i] ? <div className="m-feedback"><strong>Reference answer</strong><p>{c.a}</p></div> : <Button variant="secondary" onClick={() => setShown((x) => ({ ...x, [i]: true }))}>Show the reference answer</Button>) : <p className="m-muted">No reference answer is paired with this question in the source.</p>}
    </li>)}</ol>
    {lab.checks_source && <Src src={lab.checks_source} />}
  </div>;
}

function sourcesOf(lab: Lab): string[] {
  const out = new Set<string>();
  Object.values(lab.sections).forEach((v) => { const x = v as { source?: string } | null; if (x?.source) out.add(x.source.split("#")[0]); });
  const e = lab.explainer;
  e?.summary?.grounds.forEach((g) => out.add(g)); e?.glance?.forEach((g) => g.grounds.forEach((x) => out.add(x))); e?.known?.forEach((g) => g.grounds.forEach((x) => out.add(x)));
  e?.path?.forEach((n) => out.add(n.source)); e?.terms?.forEach((t) => out.add(t.source)); e?.practice?.predict?.forEach((p) => out.add(p.source.split("#")[0])); e?.practice?.defender?.grounds.forEach((x) => out.add(x));
  e?.spl?.forEach((q) => out.add(q.source)); e?.identifiers?.forEach((i) => out.add(i.source)); if (e?.recorded_table) out.add(e.recorded_table.source); if (e?.cannot_claim) out.add(e.cannot_claim.source.split("#")[0]);
  if (lab.checks_source) out.add(lab.checks_source);
  if (lab.registry_quote) out.add(lab.registry_quote.file);
  if (lab.limitations) out.add(lab.limitations.source.split("#")[0]);
  out.add("learning/academy/lab_registry_data.json"); out.add("learning/academy/taxonomy.json");
  if (e) out.add(`learning/academy/explainers/${lab.id}.json`);
  return [...out].sort();
}
