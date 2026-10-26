import { useEffect, useState } from "react";
import { Badge, Button, Icon, LinkButton } from "../ui";
import { Callout } from "../mission/parts";
import { Link, labPath, navigate, ASSURANCE_PATH, JOURNEY_PATH } from "../router";
import { Question } from "../workbench/StudyWorkbench";
import type { StudyQuestion } from "../curriculum";
import { EvidenceBadge, LimitationsList, MappingTable, NotImplemented, ObservationCard, StatusBadge, StepBar, VerificationBadge, classMeaning } from "../assurance/parts";
import { checked, complete, markSeen, resetWorkshop, setAnswer, update, useProgress } from "../assurance/store";
import { STEP_IDS, type EvidenceClass, type Journey, type StepId } from "../assurance/types";

// The journey is evidence, so it lives in its own file and is fetched only when the workshop opens, never in the main bundle.
const FILES = import.meta.glob<{ default: Journey }>("../content/assurance/*.json");
const cache = new Map<string, Promise<Journey>>();
const load = (id: string) => {
  const key = `../content/assurance/${id}.json`;
  if (!cache.has(key)) { const l = FILES[key]; cache.set(key, l ? l().then((m) => m.default) : Promise.reject(new Error("no such journey"))); }
  return cache.get(key)!;
};
function useJourney(id: string) {
  const [s, setS] = useState<{ data?: Journey; err?: boolean }>({});
  useEffect(() => { let live = true; setS({}); load(id).then((data) => live && setS({ data }), () => live && setS({ err: true })); return () => { live = false; }; }, [id]);
  return s;
}

const JOURNEY_ID = "mcp-unauthorized-scope";
const STEP_TITLES: Record<StepId, string> = { learn: "Learn", practice: "Practice", evaluate: "Evaluate", risk: "Assess Risk", controls: "Map Controls", prove: "Prove" };
const q = (id: string, prompt: string, mode: "single" | "multi", candidates: string[], answer: string[], quote?: { file: string; text: string }, how?: string): StudyQuestion => ({ id, prompt, mode, candidates, answer, quote, how });
const KIND_LABEL = { runtime_decision: "A recorded control decision from a committed pack", provenance_check: "A comparison of a Splunk copy with a committed pack", evaluation_result: "A recorded external model evaluation" } as const;

function Ex({ question }: { question: StudyQuestion }) {
  const p = useProgress(), a = p.answers[question.id];
  return <Question q={question} picked={a?.picked ?? []} onPick={(v) => setAnswer(question.id, { picked: v, checked: false })} shown={Boolean(a?.checked)} onCheck={() => setAnswer(question.id, { picked: a?.picked ?? [], checked: true })} />;
}

function exerciseIds(j: Journey): Record<StepId, string[]> {
  return { learn: [], practice: [], evaluate: j.observations.map((o) => `ev-${o.id}`), risk: ["risk-supports"], controls: ["controls-meaning"], prove: [] };
}

/* ---------------------------------------------------------------- hub */
export function AssuranceHub() {
  const p = useProgress();
  const started = p.seen.length > 0 || Object.keys(p.answers).length > 0 || p.practiceConfirmed;
  return <div className="page wk">
    <header className="page-header"><div><div className="eyebrow">SECURITY ASSURANCE · EVALUATION, RISK AND CONTROLS</div><h1>From a security result to a defensible conclusion</h1>
      <p>One workshop walks a single recorded scenario from lesson to proof, keeping what was observed, what is judged, what is mapped to frameworks and what is asserted strictly apart.</p></div></header>

    <section className="wk-sec" aria-labelledby="wk-journey"><h2 id="wk-journey">The workshop journey</h2>
      <article className="wk-card"><header><h3>{"An agent asks for a tool at a scope it was not granted"}</h3><Badge tone="replay">RECORDED EVIDENCE</Badge></header>
        <p>Built from the committed LAB-MCP-003 runs, their Splunk copy comparison, the recorded garak evaluation, the threat catalog and the framework reference file. Nothing is run, searched or scored.</p>
        <ol className="wk-flow" aria-label="Journey steps">{STEP_IDS.map((s, i) => <li key={s}><span aria-hidden="true">{i + 1}</span>{STEP_TITLES[s]}</li>)}</ol>
        <div className="m-actions"><LinkButton href={JOURNEY_PATH} icon="arrow" internal>{started ? "Continue the workshop" : "Start the workshop"}</LinkButton></div></article></section>

    <section className="wk-sec" aria-labelledby="wk-legend"><h2 id="wk-legend">How to read the evidence</h2>
      <p className="m-muted">Every fact in the workshop carries one of these labels, and a verification status. Nothing here is verified.</p>
      <dl className="wk-legend">{(Object.keys(classMeaning) as EvidenceClass[]).map((c) => <div key={c}><dt><EvidenceBadge cls={c} /></dt><dd>{classMeaning[c]}</dd></div>)}
        <div><dt><VerificationBadge status="NOT_VERIFIED" /></dt><dd>No receipt from the host verifier applies. This is the status of everything in this workshop.</dd></div></dl></section>

    <section className="wk-sec" aria-labelledby="wk-next"><h2 id="wk-next">Not yet implemented</h2>
      <p className="m-muted">These tracks are planned. They are shown so nothing is mistaken for working, and none has a page, a figure or a link.</p>
      <div className="wk-grid">
        <NotImplemented title="Evaluation suites" needs="Several probes across several models, with a recorded plan, results and limits. One recorded probe on one model exists today and is used in the journey." />
        <NotImplemented title="Risk register" needs="Impact and likelihood judged by named owners from real evidence. The journey records both as NOT ASSESSED." />
        <NotImplemented title="Compliance and governance dashboard" needs="An actual assessment against a framework. No compliance assertion exists, so there is nothing to total or chart." />
      </div></section>

    <section className="wk-sec" aria-labelledby="wk-reuse"><h2 id="wk-reuse">Existing Academy labs this builds on</h2>
      <ul className="wk-links">{[["LAB-MCP-003", "Scope escalation in tool authorization (the scenario)"], ["LAB-EXTERNAL-EVALUATION-GARAK", "The recorded garak evaluation"], ["LAB-THREAT-MODELING-001", "The architecture and threat catalog"], ["LAB-SPLUNK-DEFENDER-BRIDGE", "Recorded Splunk searches and run provenance"]].map(([id, t]) => <li key={id}><Link to={labPath(id)}>{t}<Icon name="arrow" size={15} /></Link></li>)}</ul></section>
  </div>;
}

/* ---------------------------------------------------------------- steps */
function LearnStep({ j }: { j: Journey }) {
  return <section className="wk-sec"><h2>The security question</h2>
    <blockquote className="wk-quote"><p>{j.learn.question.text}</p><footer>Source: <code>{j.learn.question.file}</code></footer></blockquote>
    <ul className="m-rules">{j.learn.lines.map((l) => <li key={l.text}>{l.text} <small className="m-src">Source: <code>{l.file.split("/").pop()}</code></small></li>)}</ul>
    <Callout kind="info"><strong>Observe, assess, map, assert.</strong> The workshop keeps four things apart: what a source recorded, what you can judge from it, which frameworks it relates to, and what may be asserted. You will meet each in turn.</Callout></section>;
}

function PracticeStep({ j }: { j: Journey }) {
  const p = useProgress();
  return <section className="wk-sec"><h2>Practice in the existing workbench</h2>
    <p>The lab already lets you predict, reveal and compare the three recorded runs. Open it, then come back.</p>
    <div className="m-actions"><LinkButton href={labPath(j.lab_id)} icon="arrow" internal>Open the {j.lab_id} lab</LinkButton></div>
    <label className="wk-confirm"><input type="checkbox" checked={p.practiceConfirmed} onChange={(e) => { const v = e.target.checked; update((x) => ({ ...x, practiceConfirmed: v })); }} /> I completed the Practice workbench <small>(self-reported; it is not evidence)</small></label>
    <p className="m-muted" role="status">{p.practiceConfirmed ? "Marked complete on this browser only." : "Not marked complete. You can still continue."}</p></section>;
}

function EvaluateStep({ j }: { j: Journey }) {
  return <section className="wk-sec"><h2>Five recorded observations</h2>
    <p className="m-muted">Each card is something a committed source recorded. Decide what kind of evidence it is, then check.</p>
    {j.observations.map((o) => <ObservationCard key={o.id} o={o}>
      <details className="m-details"><summary>Recorded facts</summary><dl className="rec-fields">{Object.entries(o.facts).map(([k, v]) => <div key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></div>)}</dl></details>
      <ol className="rec-qs"><Ex question={q(`ev-${o.id}`, `What kind of evidence is "${o.title}"?`, "single", Object.values(KIND_LABEL), [KIND_LABEL[o.kind]], undefined, "the observation's recorded kind")} /></ol></ObservationCard>)}</section>;
}

function RiskStep({ j }: { j: Journey }) {
  const r = j.risks[0], obs = new Map(j.observations.map((o) => [o.id, o])), p = useProgress();
  const ex = q("risk-supports", "Which statements does the recorded evidence support?", "multi", j.assessments.map((a) => a.statement), j.assessments.filter((a) => a.status === "SUPPORTED").map((a) => a.statement), undefined, "the status of each assessment, from its observations");
  return <section className="wk-sec"><h2>The risk, as the sources support it</h2>
    <article className="wk-card"><header><h3>{r.statement}</h3><Badge tone="muted">AUTHORED STATEMENT, NOT EVIDENCE</Badge></header>
      <dl className="wk-kv"><div><dt>Threat</dt><dd>{r.threat.id} · {r.threat.category}<small>{r.threat.question}</small></dd></div>
        <div><dt>Assets at stake</dt><dd><ul>{r.assets.map((a) => <li key={a.id}><code>{a.id}</code> {a.name}</li>)}</ul></dd></div>
        <div><dt>Observed in</dt><dd>{r.observed_in.map((i) => obs.get(i)!.title).join("; ")}</dd></div>
        <div><dt>Impact</dt><dd><StatusBadge status={r.impact.status} /><small>{r.impact.reason}</small></dd></div>
        <div><dt>Likelihood</dt><dd><StatusBadge status={r.likelihood.status} /><small>{r.likelihood.reason}</small></dd></div>
        <div><dt>Evidence gap, as the catalog states it</dt><dd>{r.gap}</dd></div>
        <div><dt>Residual risk, as the catalog states it</dt><dd>{r.residual_risk}</dd></div>
        <div><dt>Owner</dt><dd>NOT ASSIGNED</dd></div></dl></article>
    <h3>Which statements are supported?</h3><ol className="rec-qs"><Ex question={ex} /></ol>
    {checked(p, "risk-supports") && <div className="table-wrap" tabIndex={0} role="region" aria-label="Assessments and their basis; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Each assessment, its status and the basis for it</caption>
      <thead><tr><th scope="col">Statement</th><th scope="col">Status</th><th scope="col">Basis</th></tr></thead>
      <tbody>{j.assessments.map((a) => <tr key={a.id}><th scope="row">{a.statement}</th><td data-label="Status"><StatusBadge status={a.status} /></td><td data-label="Basis">{a.basis}{a.limitations.length > 0 && <small> Limits: {a.limitations.join(" ")}</small>}</td></tr>)}</tbody></table></div>}</section>;
}

function ControlsStep({ j }: { j: Journey }) {
  const mm = j.mapping_meaning;
  return <section className="wk-sec"><h2>The control and its recorded decisions</h2>
    <div className="wk-grid">{j.controls.map((c) => <article className="wk-card" key={c.id}><header><h3>{c.id}</h3><Badge tone="neutral">{c.class}</Badge></header>
      <p>Placement: {c.placement}. <small className="m-src">Code: <code>{c.code_reference}</code></small></p>
      {c.observed_in_recorded_runs.length > 0 ? <ul className="m-rules">{c.observed_in_recorded_runs.map((r) => <li key={r.run}><strong>{r.run}</strong>: {r.decision} <small>({r.reason})</small></li>)}</ul> : <p className="m-muted">{c.note}</p>}</article>)}</div>
    <h2>Four separate facts, never one number</h2><p className="m-muted">{j.coverage_note}</p>
    <dl className="wk-legend">{j.coverage.map((c) => <div key={c.notion}><dt>{c.notion}</dt><dd>{c.statement}{c.quote && <small> <q>{c.quote.text}</q></small>}</dd></div>)}</dl>
    <h2>Framework relationships</h2><MappingTable items={j.mappings} />
    <p className="m-muted">{j.upstream_tags.note} Tags: {j.upstream_tags.tags.join(", ")}.</p>
    <Callout kind="warn"><strong>Compliance assertions: none.</strong> {j.compliance_statement}</Callout>
    <ol className="rec-qs"><Ex question={q("controls-meaning", mm.question, "single", mm.options, mm.answer, mm.quote)} /></ol></section>;
}

function ProveStep({ j }: { j: Journey }) {
  const files = new Map<string, { sha: string; by: string[] }>();
  j.observations.forEach((o) => o.sources.forEach((s) => { const e = files.get(s.file) ?? { sha: s.sha256, by: [] }; e.by.push(o.title); files.set(s.file, e); }));
  const sup = j.assessments.filter((a) => a.status === "SUPPORTED").length;
  return <section className="wk-sec"><h2>What was observed, judged, mapped and asserted</h2>
    <dl className="wk-legend"><div><dt>Observations</dt><dd>{j.observations.length}, every one NOT_VERIFIED</dd></div><div><dt>Assessments</dt><dd>{sup} supported, {j.assessments.length - sup} not supported</dd></div>
      <div><dt>Framework relationships</dt><dd>{j.mappings.length}, none a compliance claim</dd></div><div><dt>Compliance assertions</dt><dd>{j.compliance_assertions.length}</dd></div></dl>
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Observations by kind and class; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Every observation, its kind, class and verification</caption>
      <thead><tr><th scope="col">Observation</th><th scope="col">Kind</th><th scope="col">Class</th><th scope="col">Verification</th></tr></thead>
      <tbody>{j.observations.map((o) => <tr key={o.id}><th scope="row">{o.title}</th><td data-label="Kind">{KIND_LABEL[o.kind]}</td><td data-label="Class"><EvidenceBadge cls={o.evidence_class} /></td><td data-label="Verification"><VerificationBadge status={o.verification.status} /></td></tr>)}</tbody></table></div>
    <h3>Source files and their hashes</h3>
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Source files and SHA-256; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">The files this workshop read, unchanged</caption>
      <thead><tr><th scope="col">File</th><th scope="col">SHA-256</th><th scope="col">Used by</th></tr></thead>
      <tbody>{[...files].map(([f, e]) => <tr key={f}><th scope="row"><code>{f}</code></th><td data-label="SHA-256"><code>{e.sha}</code></td><td data-label="Used by">{[...new Set(e.by)].join("; ")}</td></tr>)}</tbody></table></div>
    <Callout kind="warn"><strong>Verification status: NOT_VERIFIED.</strong> No receipt from the host verifier applies to any run shown, so nothing here is claimed to be Splunk-verified.</Callout>
    <h3>What remains open</h3>
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Remediation actions; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">Actions the sources point to. Each is proposed, none is started and none has an owner.</caption>
      <thead><tr><th scope="col">Action</th><th scope="col">The source line that states the gap</th><th scope="col">Owner</th><th scope="col">Status</th></tr></thead>
      <tbody>{j.remediation.map((x) => <tr key={x.id}><th scope="row">{x.action}</th><td data-label="Source"><q>{x.basis_quote.text}</q> <small className="m-src"><code>{x.basis_quote.file.split("/").pop()}</code></small></td><td data-label="Owner">NOT ASSIGNED</td><td data-label="Status">NOT STARTED</td></tr>)}</tbody></table></div>
    <LimitationsList items={j.limitations} title="What this journey does not prove" level={3} /></section>;
}

/* ---------------------------------------------------------------- journey */
export function AssuranceJourney({ step }: { step: StepId | null }) {
  const { data, err } = useJourney(JOURNEY_ID);
  const p = useProgress();
  const [cleared, setCleared] = useState(false);
  const first = data ? (STEP_IDS.find((s) => !complete(s, p, exerciseIds(data)[s])) ?? "prove") : "learn";
  useEffect(() => { if (data && step === null) navigate(`${JOURNEY_PATH}/${first}`, { replace: true }); }, [data, step]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (step) { markSeen(step); setCleared(false); } }, [step]);
  if (err) return <div className="page wk"><div className="m-sec" role="alert"><h1>The workshop evidence could not be loaded</h1><p>The recorded evidence file did not load. Nothing was changed. A browser keeps a failed file load until the page is reloaded.</p><div className="m-actions"><Button onClick={() => window.location.reload()}>Reload the page</Button><LinkButton href={ASSURANCE_PATH} variant="secondary" internal>Back to the workshop home</LinkButton></div></div></div>;
  if (!data) return <div className="page wk"><div className="m-sec" role="status"><p className="m-muted">Loading the recorded evidence…</p></div></div>;
  if (data.observations.length === 0) return <div className="page wk"><div className="m-sec"><h1>No evidence in this journey</h1><p>This journey has no observations, so there is nothing to evaluate.</p><LinkButton href={ASSURANCE_PATH} internal>Back to the workshop home</LinkButton></div></div>;
  if (step === null) return <div className="page wk"><div className="m-sec" role="status"><p className="m-muted">Opening your current step…</p></div></div>;
  const ids = exerciseIds(data), idx = STEP_IDS.indexOf(step), meta = data.steps[idx];
  const doneCount = STEP_IDS.filter((s) => complete(s, p, ids[s])).length;
  const prev = idx > 0 ? STEP_IDS[idx - 1] : null, next = idx < STEP_IDS.length - 1 ? STEP_IDS[idx + 1] : null;
  const body = { learn: <LearnStep j={data} />, practice: <PracticeStep j={data} />, evaluate: <EvaluateStep j={data} />, risk: <RiskStep j={data} />, controls: <ControlsStep j={data} />, prove: <ProveStep j={data} /> }[step];
  return <div className="page wk">
    <header className="page-header"><div><div className="eyebrow">SECURITY ASSURANCE WORKSHOP · RECORDED EVIDENCE</div><h1>{data.title}</h1>
      <p>Learn, practice, evaluate, assess risk, map controls and prove, on one recorded scenario.</p></div>
      <div className="m-actions"><Button variant="ghost" onClick={() => { resetWorkshop(); setCleared(true); }}>Reset workshop</Button></div></header>
    <div role="status" className="visually-hidden">{cleared ? "Workshop progress cleared." : ""}</div>
    {cleared && <p className="m-muted">Workshop progress cleared on this browser.</p>}
    <section className="wk-progress" aria-label="Progress"><p><strong>Step {idx + 1} of {STEP_IDS.length}: {STEP_TITLES[step]}</strong></p>
      <div className="progress" role="progressbar" aria-label="Workshop progress" aria-valuemin={0} aria-valuemax={STEP_IDS.length} aria-valuenow={doneCount}><span style={{ width: `${(doneCount / STEP_IDS.length) * 100}%` }} /></div>
      <p className="m-muted">{doneCount} of {STEP_IDS.length} steps complete. This is your own progress in the workshop, not a security measure.</p></section>
    <StepBar steps={STEP_IDS.map((s) => ({ id: s, title: STEP_TITLES[s] }))} current={step} base={JOURNEY_PATH} done={(s) => complete(s as StepId, p, ids[s as StepId])} />
    <section className="wk-instruction" aria-label="What to do here"><h2>What to do here</h2><p>{meta.instruction}</p></section>
    {body}
    {!complete(step, p, ids[step]) && step !== "learn" && step !== "prove" && <p className="m-muted">You can continue now. This step is not marked complete until you finish its exercise.</p>}
    <footer className="wk-actions">{prev ? <LinkButton href={`${JOURNEY_PATH}/${prev}`} variant="secondary" internal>Back to {STEP_TITLES[prev]}</LinkButton> : <LinkButton href={ASSURANCE_PATH} variant="secondary" internal>Back to the workshop home</LinkButton>}
      {next ? <LinkButton href={`${JOURNEY_PATH}/${next}`} icon="arrow" internal>{meta.next_action}</LinkButton> : <LinkButton href={ASSURANCE_PATH} icon="arrow" internal>{meta.next_action}</LinkButton>}</footer>
  </div>;
}
