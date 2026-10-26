import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Badge, Button, LinkButton } from "../ui";
import { Callout } from "../mission/parts";
import { EVALS_PATH, Link, RISK_PATH, navigate, type Route } from "../router";
import { LimitationsList, MappingTable, ProvenanceDisclosure } from "../assurance/parts";
import { DraftBar, Fact, LevelBadge, OriginBadge, Problems, time } from "../risk/parts";
import { getDraft, addCustom, clearApproval, clearAssessment, deleteCustom, init, removeAction, saveAction, saveApproval, saveInherent, saveResidual, saveTreatment, setReview, useDraft } from "../risk/store";
import { level } from "../risk/validate";
import type { Action, Candidate, Judgment, Level, Problem, RiskState, Seed, Strategy } from "../risk/types";

const SEEDS = import.meta.glob<{ default: Seed }>("../content/risk/seed.json");
const cache: { p?: Promise<Seed> } = {};
const loadSeed = () => (cache.p ??= SEEDS["../content/risk/seed.json"]().then((m) => m.default));
function useSeed() {
  const [s, setS] = useState<{ seed?: Seed; err?: boolean }>({});
  useEffect(() => { let live = true; loadSeed().then((seed) => { init(seed); if (live) setS({ seed }); }, () => live && setS({ err: true })); return () => { live = false; }; }, []);
  return s;
}
type RiskRoute = Extract<Route, { name: "risk" }>;
const rank = (l: Level | null) => (l ? ["LOW", "MEDIUM", "HIGH"].indexOf(l) : -1);
const strategyLabel = (s: Strategy | null) => (s ? s.charAt(0) + s.slice(1).toLowerCase() : "None recorded");
const reviewLabel = { DRAFT: "Draft", AWAITING_REVIEW: "Awaiting review", REVIEWED: "Review recorded" } as const;
const titleOf = (r: RiskState, c?: Candidate) => (r.custom ? r.custom.title : c!.title);
const hasGap = (r: RiskState, c?: Candidate) => !c || !c.derived.has_linked_evidence || c.derived.controls_without_recorded_evidence.length > 0;

function Failed() { return <div className="m-sec" role="alert"><h2>The risk evidence could not be loaded</h2><p>The source-backed risks did not load. Nothing was changed, and your draft is untouched. A browser keeps a failed file load until the page is reloaded.</p><Button onClick={() => window.location.reload()}>Reload the page</Button></div>; }
const Section = ({ id, title, children }: { id: string; title: string; children: ReactNode }) => <section className="wk-sec" aria-labelledby={id}><h2 id={id}>{title}</h2>{children}</section>;
function Table({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return <div className="table-wrap" tabIndex={0} role="region" aria-label={`${caption}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{caption}</caption>
    <thead><tr>{head.map((h) => <th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => j === 0 ? <th scope="row" key={j}>{c}</th> : <td data-label={head[j]} key={j}>{c}</td>)}</tr>)}</tbody></table></div>;
}

/* ------------------------------------------------------------ overview */
function Overview({ seed }: { seed: Seed }) {
  const d = useDraft(), by = new Map(seed.candidates.map((c) => [c.id, c])), n = d.risks.length;
  const count = (f: (r: RiskState, c?: Candidate) => boolean) => d.risks.filter((r) => f(r, by.get(r.id))).length;
  const tiles = [
    { to: "register", label: "Risks with no inherent assessment", n: count((r) => r.derived.inherent_level === null), note: "NOT ASSESSED until a person enters impact and likelihood." },
    { to: "register/with-findings", label: "Risks with supporting evaluation findings", n: count((_, c) => !!c?.derived.has_linked_findings), note: "Findings from recorded EVAL Center experiments." },
    { to: "register/gaps", label: "Risks with an evidence or control gap", n: count(hasGap), note: "No linked experiment, or a control with no recorded decision." },
    { to: "register/treatment", label: "Risks with a treatment chosen", n: count((r) => r.treatment.strategy !== null), note: `${count((r) => r.treatment.strategy === "ACCEPT" && !r.treatment.approval)} chosen to accept without an approval record.` },
    { to: "register/awaiting-review", label: "Assessments awaiting review", n: count((r) => r.review.status === "AWAITING_REVIEW"), note: "Marked by the person using this draft." },
  ];
  return <>
    <Callout kind="info"><strong>Scope.</strong> Every count below describes this local draft of {n} risks. It is not an enterprise total, and there is no overall score or compliance percentage anywhere in the Risk Center.</Callout>
    <Section id="rk-where" title="Where this draft stands">
      <div className="wk-grid">{tiles.map((t) => <article className="wk-card" key={t.to}><p className="ev-figure"><strong>{t.n}</strong> of {n}</p><h3>{t.label}</h3><p className="m-muted">{t.note}</p><Link to={`${RISK_PATH}/${t.to}`}>Open this view</Link></article>)}</div></Section>
    <Section id="rk-how" title="How a risk is assessed here">
      <p>{seed.methodology.statement}</p><LinkButton href={`${RISK_PATH}/method`} variant="secondary" internal>Read the method</LinkButton>
      <dl className="rk-origins">{seed.methodology.origins.map((o) => <div key={o.id}><dt><OriginBadge o={o.id} method={seed.methodology} /></dt><dd>{o.meaning}</dd></div>)}</dl></Section>
    <Section id="rk-demo" title="A short workshop demonstration">
      <ol className="ev-demo">{[["Open a source-backed risk", "Excessive authority and tool abuse has four linked evaluation findings.", `${RISK_PATH}/TM-T04`], ["Read the evidence and its limits", "Facts and evidence are labelled by origin. Nothing is judged for you.", `${RISK_PATH}/TM-T04`],
        ["Enter your own judgment", "Choose impact and likelihood and write why. The level is looked up from your entries.", `${RISK_PATH}/TM-T04`], ["Record a treatment and request review", "Nothing is shown as approved or complete without a record.", `${RISK_PATH}/TM-T04`],
        ["Export, then reset", "Download the draft, then reset to a clean starting point whenever you like.", RISK_PATH]].map(([t, x, to], i) => <li key={t}><span className="wk-n" aria-hidden="true">{i + 1}</span><div><strong>{t}</strong><p>{x}</p><Link to={to}>{i === 4 ? "Use the draft controls above" : "Go to this step"}</Link></div></li>)}</ol></Section>
    <Section id="rk-not" title="What the Risk Center does not do"><ul className="m-rules"><li>It does not propose impact, likelihood, severity, owners or treatments.</li><li>It does not lower a residual judgment because a control has a recorded test result.</li><li>It does not share, centrally store or approve an assessment, and it does not map anything to compliance.</li></ul></Section>
  </>;
}

/* ------------------------------------------------------------ register */
const FILTERS: Record<string, { label: string; keep: (r: RiskState, c?: Candidate) => boolean }> = {
  all: { label: "All risks", keep: () => true }, unassessed: { label: "Not assessed", keep: (r) => r.derived.inherent_level === null },
  "with-findings": { label: "With evaluation findings", keep: (_, c) => !!c?.derived.has_linked_findings }, gaps: { label: "Evidence and control gaps", keep: hasGap },
  treatment: { label: "Treatment status", keep: () => true }, "awaiting-review": { label: "Awaiting review", keep: (r) => r.review.status === "AWAITING_REVIEW" },
};
function Register({ seed, filter }: { seed: Seed; filter: string }) {
  const d = useDraft(), by = new Map(seed.candidates.map((c) => [c.id, c])), [q, setQ] = useState("");
  const f = FILTERS[filter] ?? FILTERS.all;
  const rows = d.risks.filter((r) => f.keep(r, by.get(r.id)) && (!q || (titleOf(r, by.get(r.id)) + r.id).toLowerCase().includes(q.toLowerCase())));
  const tr = ["MITIGATE", "ACCEPT", "TRANSFER", "AVOID"] as Strategy[];
  return <>
    <nav aria-label="Register views" className="ev-tabs"><ul>{Object.entries(FILTERS).map(([k, v]) => <li key={k}><Link to={k === "all" ? `${RISK_PATH}/register` : `${RISK_PATH}/register/${k}`} aria-current={k === filter ? "page" : undefined} className={k === filter ? "is-current" : ""}>{v.label}</Link></li>)}</ul></nav>
    <div className="ev-filters"><label>Search<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title or id" /></label></div>
    <p role="status" className="m-muted">Showing {rows.length} of {d.risks.length} risks in this draft.</p>
    {filter === "treatment" && <p>Treatment recorded: {tr.map((s) => `${strategyLabel(s)} ${d.risks.filter((r) => r.treatment.strategy === s).length}`).join(", ")}; none recorded {d.risks.filter((r) => r.treatment.strategy === null).length}. Of {d.risks.filter((r) => r.treatment.strategy === "ACCEPT").length} chosen to accept, {d.risks.filter((r) => r.treatment.strategy === "ACCEPT" && r.treatment.approval).length} have an approval record (entered locally, not verified).</p>}
    {rows.length === 0 ? <div className="m-sec"><p>No risk matches this view.</p><LinkButton href={`${RISK_PATH}/register`} variant="secondary" internal>Show all risks</LinkButton></div> :
      <Table caption={`Risk register: ${f.label}`} head={["Risk", "System", "Findings", "Inherent", "Residual", "Treatment", "Review"]}
        rows={rows.map((r) => { const c = by.get(r.id); return [<Link key="l" to={`${RISK_PATH}/${r.id}`}>{r.id}: {titleOf(r, c)}</Link>, r.custom ? r.custom.system || "Not stated" : c!.system.name, c ? String(c.evidence.findings.length) : "0 (no source)",
          <LevelBadge key="i" level={r.derived.inherent_level} />, <LevelBadge key="r" level={r.derived.residual_level} />, strategyLabel(r.treatment.strategy) + (r.treatment.strategy === "ACCEPT" && !r.treatment.approval ? " (no approval recorded)" : ""), reviewLabel[r.review.status]]; })} />}
    <div className="m-actions"><LinkButton href={`${RISK_PATH}/new`} variant="secondary" internal>Add a risk of your own</LinkButton></div>
  </>;
}

/* ------------------------------------------------------------ forms */
const sel = (m: Seed["methodology"]) => ({ impact: m.impact, likelihood: m.likelihood });
function JudgmentForm({ kind, seed, risk, disabled, controls }: { kind: "inherent" | "residual"; seed: Seed; risk: RiskState; disabled?: boolean; controls?: Candidate["controls"] }) {
  const saved = risk.assessment[kind], m = seed.methodology;
  const [v, setV] = useState<Judgment>({ impact: saved.impact, likelihood: saved.likelihood, rationale: saved.rationale });
  const [cc, setCc] = useState<string[]>(kind === "residual" ? (saved as RiskState["assessment"]["residual"]).controls_considered : []);
  const [errs, setErrs] = useState<Problem[]>([]), [msg, setMsg] = useState("");
  const live = level(m, v.impact, v.likelihood), inh = risk.derived.inherent_level, id = `${kind}-${risk.id}`;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const p: Problem[] = [];
    if (!v.impact) p.push({ code: "IMPACT", path: "impact", message: "Choose an impact." });
    if (!v.likelihood) p.push({ code: "LIKELIHOOD", path: "likelihood", message: "Choose a likelihood." });
    if (!v.rationale.trim()) p.push({ code: "RATIONALE", path: "rationale", message: "Write why. A judgment without a rationale is not saved." });
    setErrs(p); setMsg("");
    if (p.length) return;
    kind === "inherent" ? saveInherent(risk.id, v) : saveResidual(risk.id, v, cc);
    setMsg(getDraft().notice);
  };
  const s = sel(m);
  return <form onSubmit={submit} noValidate aria-label={`${kind === "inherent" ? "Inherent" : "Residual"} risk assessment`}>
    <fieldset disabled={disabled} className="rk-fields">
      <label>Impact<select value={v.impact ?? ""} onChange={(e) => setV({ ...v, impact: (e.target.value || null) as Judgment["impact"] })}><option value="">Not assessed</option>{s.impact.map((x) => <option key={x.id} value={x.id}>{x.label}: {x.definition}</option>)}</select></label>
      <label>Likelihood<select value={v.likelihood ?? ""} onChange={(e) => setV({ ...v, likelihood: (e.target.value || null) as Judgment["likelihood"] })}><option value="">Not assessed</option>{s.likelihood.map((x) => <option key={x.id} value={x.id}>{x.label}: {x.definition}</option>)}</select></label>
      {kind === "residual" && controls && controls.length > 0 && <fieldset className="rk-controls"><legend>Controls you considered</legend><p className="m-muted">Ticking a control records that you considered it. It does not lower the level, and a recorded test result does not either.</p>
        {controls.map((c) => <label key={c.id}><input type="checkbox" checked={cc.includes(c.id)} onChange={(e) => setCc(e.target.checked ? [...cc, c.id] : cc.filter((x) => x !== c.id))} /> {c.id} <small>({c.class})</small></label>)}</fieldset>}
      <label>Rationale: why you judged it this way<textarea rows={3} value={v.rationale} maxLength={2000} onChange={(e) => setV({ ...v, rationale: e.target.value })} aria-describedby={errs.length ? `${id}-err` : undefined} /></label>
      <p>Level looked up from your entries: <LevelBadge level={live} /> <OriginBadge o="DERIVED" method={m} /> <small className="m-muted">Shown before saving. Not a measurement.</small></p>
      {kind === "residual" && live && inh && rank(live) > rank(inh) && <p role="alert" className="rk-warn">Your residual level ({live}) is higher than the inherent level ({inh}). Check the rationale. You can still save.</p>}
      <Problems problems={errs} id={`${id}-err`} />
      <div className="m-actions"><Button>{`Save ${kind} assessment`}</Button>{saved.impact && <Button variant="ghost" onClick={() => { clearAssessment(risk.id, kind); setV({ impact: null, likelihood: null, rationale: "" }); setCc([]); setMsg(`${kind === "inherent" ? "Inherent" : "Residual"} assessment cleared.`); setErrs([]); }}>Clear this assessment</Button>}</div>
    </fieldset>
    <p role="status" className="m-muted">{msg}</p>
    <p className="m-muted">Saved: {risk.derived[`${kind}_level` as "inherent_level"] ? <><LevelBadge level={risk.derived[`${kind}_level` as "inherent_level"]} /> <OriginBadge o="ANALYST" method={m} /> entered by you in this browser; not verified.</> : "NOT ASSESSED"}</p>
  </form>;
}

function ActionRow({ risk, a }: { risk: RiskState; a: Action }) {
  const [v, setV] = useState(a), [err, setErr] = useState(""), [ok, setOk] = useState("");
  return <li className="rk-action"><fieldset><legend>{a.id}: {a.text}</legend>
    <label>Status<select value={v.status} onChange={(e) => setV({ ...v, status: e.target.value as Action["status"] })}><option value="PROPOSED">Proposed</option><option value="IN_PROGRESS">In progress</option><option value="COMPLETED">Completed (claimed)</option></select></label>
    <label>Owner (a person or role you name)<input value={v.owner ?? ""} maxLength={200} onChange={(e) => setV({ ...v, owner: e.target.value || null })} /></label>
    {v.status === "COMPLETED" && <label>Evidence the completion rests on<textarea rows={2} value={v.evidence_note} onChange={(e) => setV({ ...v, evidence_note: e.target.value })} /></label>}
    {err && <p role="alert" className="rk-warn">{err}</p>}
    <div className="m-actions"><Button variant="secondary" onClick={() => { if (v.status === "COMPLETED" && !v.evidence_note.trim()) { setErr("A completed action needs the evidence it rests on."); setOk(""); return; } setErr(""); saveAction(risk.id, v); setOk("Action saved."); }}>Save action {a.id}</Button><Button variant="ghost" onClick={() => removeAction(risk.id, a.id)}>Remove {a.id}</Button></div>
    <p role="status" className="m-muted">{ok}</p>
    {a.status === "COMPLETED" && <p className="m-muted">Completion claimed. Evidence note: {a.evidence_note}. Not verified by this page.</p>}</fieldset></li>;
}

function TreatmentSection({ seed, risk }: { seed: Seed; risk: RiskState }) {
  const t = risk.treatment, m = seed.methodology;
  const [strategy, setStrategy] = useState<Strategy | "">(t.strategy ?? ""), [notes, setNotes] = useState(t.notes), [owner, setOwner] = useState(risk.owner ?? ""), [msg, setMsg] = useState("");
  const [ap, setAp] = useState({ by: "", role: "", note: "" }), [apErr, setApErr] = useState(""), [nt, setNt] = useState(""), [no, setNo] = useState(""), [naErr, setNaErr] = useState("");
  return <>
    <form onSubmit={(e) => { e.preventDefault(); saveTreatment(risk.id, (strategy || null) as Strategy | null, notes, owner); setMsg(getDraft().notice); }} aria-label="Risk owner and treatment">
      <div className="rk-fields"><label>Risk owner (a person or role you name; never filled in for you)<input value={owner} maxLength={200} onChange={(e) => setOwner(e.target.value)} placeholder="NOT ASSIGNED" /></label>
        <label>Treatment<select value={strategy} onChange={(e) => setStrategy(e.target.value as Strategy | "")}><option value="">None recorded</option>{m.treatment.map((x) => <option key={x.id} value={x.id}>{x.label}: {x.meaning}</option>)}</select></label>
        <label>Treatment notes<textarea rows={3} value={notes} maxLength={2000} onChange={(e) => setNotes(e.target.value)} /></label></div>
      <div className="m-actions"><Button>Save treatment</Button></div><p role="status" className="m-muted">{msg}</p></form>
    <p>Owner: {risk.owner ?? "NOT ASSIGNED"} <OriginBadge o={risk.owner ? "ANALYST" : "MISSING"} method={m} />. Treatment: {strategyLabel(t.strategy)}{t.strategy === "ACCEPT" && (t.approval ? ` — approval recorded by ${t.approval.by} (${t.approval.role}) at ${t.approval.at}; entered locally, not verified` : " — NO APPROVAL RECORDED")}.</p>
    {t.strategy === "ACCEPT" && <form aria-label="Acceptance approval record" onSubmit={(e) => { e.preventDefault(); if (!ap.by.trim() || !ap.role.trim() || !ap.note.trim()) { setApErr("An approval record needs who, their role and a note."); return; } setApErr(""); saveApproval(risk.id, ap); }}>
      <fieldset className="rk-fields"><legend>Acceptance approval</legend><p className="m-muted">Acceptance is not approved until a person is recorded here. This page cannot verify the record.</p>
        <label>Approved by<input value={ap.by} onChange={(e) => setAp({ ...ap, by: e.target.value })} /></label><label>Their role<input value={ap.role} onChange={(e) => setAp({ ...ap, role: e.target.value })} /></label><label>Note<textarea rows={2} value={ap.note} onChange={(e) => setAp({ ...ap, note: e.target.value })} /></label>
        {apErr && <p role="alert" className="rk-warn">{apErr}</p>}<div className="m-actions"><Button>Record acceptance approval</Button>{t.approval && <Button variant="ghost" onClick={() => clearApproval(risk.id)}>Remove the approval record</Button>}</div></fieldset></form>}
    <h3>Proposed actions</h3>
    {t.actions.length === 0 ? <p className="m-muted">No action proposed.</p> : <ul className="rk-actions">{t.actions.map((a) => <ActionRow key={a.id + a.status + a.evidence_note + a.owner} risk={risk} a={a} />)}</ul>}
    <form aria-label="Propose an action" onSubmit={(e) => { e.preventDefault(); if (!nt.trim()) { setNaErr("Describe the action."); return; } setNaErr(""); saveAction(risk.id, { text: nt.trim(), owner: no.trim() || null, status: "PROPOSED", evidence_note: "" }); setNt(""); setNo(""); }}>
      <div className="rk-fields"><label>New action<input value={nt} maxLength={200} onChange={(e) => setNt(e.target.value)} /></label><label>Owner (optional)<input value={no} maxLength={200} onChange={(e) => setNo(e.target.value)} /></label></div>
      {naErr && <p role="alert" className="rk-warn">{naErr}</p>}<div className="m-actions"><Button variant="secondary">Add action</Button></div></form></>;
}

function ReviewSection({ risk, seed }: { risk: RiskState; seed: Seed }) {
  const r = risk.review, [who, setWho] = useState(""), [note, setNote] = useState(""), [err, setErr] = useState(""), canAsk = risk.derived.inherent_level !== null;
  return <>
    <p>Status: <Badge tone={r.status === "AWAITING_REVIEW" ? "observed" : r.status === "REVIEWED" ? "neutral" : "muted"}>{reviewLabel[r.status].toUpperCase()}</Badge>{r.status === "REVIEWED" && ` by ${r.reviewer} at ${r.at}. Entered locally; not verified.`} <OriginBadge o="ANALYST" method={seed.methodology} /></p>
    {!canAsk && <p className="m-muted">Save an inherent assessment before asking for review.</p>}
    <div className="m-actions">{r.status === "DRAFT" && <Button variant="secondary" disabled={!canAsk} onClick={() => setReview(risk.id, "AWAITING_REVIEW", null, "")}>Mark as awaiting review</Button>}
      {r.status !== "DRAFT" && <Button variant="ghost" onClick={() => setReview(risk.id, "DRAFT", null, "")}>Return to draft</Button>}</div>
    {r.status === "AWAITING_REVIEW" && <form aria-label="Record a review" onSubmit={(e) => { e.preventDefault(); if (!who.trim() || !note.trim()) { setErr("A recorded review needs the reviewer's name and a note."); return; } setErr(""); setReview(risk.id, "REVIEWED", who, note); }}>
      <fieldset className="rk-fields"><legend>Record a review</legend><p className="m-muted">This records who reviewed and what they noted. It is typed in here and cannot be verified by this page.</p>
        <label>Reviewer<input value={who} onChange={(e) => setWho(e.target.value)} /></label><label>Review note<textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} /></label>
        {err && <p role="alert" className="rk-warn">{err}</p>}<div className="m-actions"><Button>Record the review</Button></div></fieldset></form>}
    <h3>History</h3>{r.history.length === 0 ? <p className="m-muted">No history yet.</p> : <Table caption="Review and change history, newest last" head={["When", "Event", "Note"]} rows={r.history.map((h) => [h.at, h.event, h.note || "—"])} />}</>;
}

/* ------------------------------------------------------------ detail */
function Detail({ seed, id }: { seed: Seed; id: string }) {
  const d = useDraft(), risk = d.risks.find((r) => r.id === id), c = seed.candidates.find((x) => x.id === id), m = seed.methodology;
  if (!risk) return <div className="m-sec" role="alert"><h2>There is no risk called {id}</h2><LinkButton href={`${RISK_PATH}/register`} internal>Back to the register</LinkButton></div>;
  const ctl = c?.controls ?? [];
  return <>
    <p className="m-muted"><Link to={`${RISK_PATH}/register`}>Register</Link> / {risk.id}</p>
    <header className="ev-head"><h2>{titleOf(risk, c)}</h2><div className="wk-badges">{c ? <Badge tone="replay">SOURCE-BACKED RISK</Badge> : <Badge tone="neutral">YOUR OWN RISK, NO SOURCE</Badge>}<Badge tone="warning">LOCAL DRAFT</Badge></div></header>
    <dl className="wk-kv"><div><dt>Inherent</dt><dd><LevelBadge level={risk.derived.inherent_level} /></dd></div><div><dt>Residual</dt><dd><LevelBadge level={risk.derived.residual_level} /></dd></div><div><dt>Treatment</dt><dd>{strategyLabel(risk.treatment.strategy)}</dd></div><div><dt>Review</dt><dd>{reviewLabel[risk.review.status]}</dd></div></dl>
    {c ? <Section id="r-facts" title="What the sources state">
      <dl className="wk-kv rk-facts">
        <Fact label="Threat scenario" origin="SOURCE" method={m}>{c.threat_scenario}</Fact>
        <Fact label="System" origin="SOURCE" method={m}>{c.system.name}<small>{c.system.components.map((x) => `${x.name} (${x.status})`).join("; ")}</small></Fact>
        <Fact label="Affected assets" origin="SOURCE" method={m}><ul>{c.assets.map((a) => <li key={a.id}><code>{a.id}</code> {a.name}<small>{a.reason}</small></li>)}</ul></Fact>
        <Fact label="Trust boundaries" origin="SOURCE" method={m}><ul>{c.boundaries.map((b) => <li key={b.id}><code>{b.id}</code> {b.name}<small>{b.question}</small></li>)}</ul></Fact>
        <Fact label="Documented evidence gap" origin="SOURCE" method={m}>{c.documented_gap}<small>As the threat catalog states it. Not an assessment.</small></Fact>
        <Fact label="Documented residual-risk statement" origin="SOURCE" method={m}>{c.documented_residual_risk}<small>As the threat catalog states it. It is not your residual judgment and is not used to compute one.</small></Fact>
        <Fact label="Telemetry the catalog asks for" origin="SOURCE" method={m}>{c.telemetry_required.join(", ")}</Fact>
        {c.inventory && <Fact label="Documented component list" origin="SOURCE" method={m}>{c.inventory.components} components; owner not recorded for {c.inventory.owner_not_recorded.length} of them ({c.inventory.owner_not_recorded.join(", ")}).<small>{c.inventory.note}</small></Fact>}
      </dl><ProvenanceDisclosure sources={c.sources} /></Section> :
      <Section id="r-facts" title="What you entered about this risk"><Callout kind="warn"><strong>No source backs this risk.</strong> It has no linked evaluation evidence and no catalog controls. Everything below was typed by you.</Callout>
        <dl className="wk-kv"><Fact label="Category" origin="ANALYST" method={m}>{risk.custom!.category || "Not stated"}</Fact><Fact label="System" origin="ANALYST" method={m}>{risk.custom!.system || "Not stated"}</Fact><Fact label="Threat scenario" origin="ANALYST" method={m}>{risk.custom!.scenario || "Not stated"}</Fact><Fact label="Affected assets" origin="ANALYST" method={m}>{risk.custom!.assets || "Not stated"}</Fact></dl>
        <div className="m-actions"><Button variant="ghost" onClick={() => { deleteCustom(risk.id); navigate(`${RISK_PATH}/register`); }}>Delete this risk</Button></div></Section>}
    {c && <Section id="r-evidence" title="Linked evaluation evidence">
      <p className="m-muted"><OriginBadge o="DERIVED" method={m} /> Linked by fixed rules from the EVAL Center data. Every linked test case is NOT_VERIFIED, and a finding is not a risk.</p>
      {c.evidence.experiments.length === 0 ? <Callout kind="warn"><strong>No linked evidence.</strong> No experiment in the EVAL Center tests this threat.</Callout> : <>
        <ul className="m-rules">{c.evidence.experiments.map((e) => <li key={e.id}><Link to={`${EVALS_PATH}/results/${e.id}`}>{e.title}</Link> <small>{e.evidence_class}, {e.status}</small></li>)}</ul>
        <p>{c.evidence.cases.length} linked test case(s): {c.evidence.cases.filter((k) => k.evidence_class === "RECORDED").length} recorded, {c.evidence.cases.filter((k) => k.evidence_class === "SIMULATED").length} simulated; {c.evidence.cases.filter((k) => k.verification.status === "VERIFIED").length} verified.</p>
        {c.evidence.findings.length === 0 ? <p className="m-muted">No finding was derived from these experiments.</p> : <Table caption="Findings derived from the linked experiments" head={["Finding", "Observed", "Documented expectation", "Verification", "Severity"]}
          rows={c.evidence.findings.map((f) => [<Link key="f" to={`${EVALS_PATH}/findings`}>{f.title}</Link>, f.observed, f.expected.documented ? f.expected.quote!.text : "NOT DOCUMENTED", f.verification.status, "NOT ASSESSED"])} />}
        <LimitationsList items={c.evidence.limitations} title="Evidence limitations" level={3} /></>}
      {c.evidence.mappings.length > 0 && <><h3>Framework relationships</h3><MappingTable items={c.evidence.mappings} /></>}</Section>}
    {c && <Section id="r-controls" title="Existing controls and control evidence">
      <Callout kind="warn"><strong>A recorded decision is not a residual-risk assessment.</strong> It says what a control decided in one recorded run. The Risk Center never lowers a residual judgment for you.</Callout>
      <Table caption="Controls named by the threat catalog, with the decisions recorded for them" head={["Control", "Class and placement", "Recorded decisions in linked experiments", "Code reference"]}
        rows={ctl.map((k) => { const by: Record<string, number> = {}; k.recorded_decisions.forEach((x) => { const key = `${x.role} ${x.decision}`; by[key] = (by[key] ?? 0) + 1; });
          return [k.id, `${k.class}; ${k.placement}`, k.recorded_decisions.length ? <>{k.recorded_decisions.length} decision event(s): {Object.entries(by).map(([a, n]) => `${a} ×${n}`).join(", ")}. <small>{k.evidence_note}</small></> : k.evidence_note, <code key="c">{k.code_reference}</code>]; })} />
      {c.derived.gaps.length > 0 && <LimitationsList items={c.derived.gaps} title="Evidence and control gaps (derived)" level={3} />}</Section>}
    <Section id="r-inherent" title="Your inherent risk assessment">
      <p className="m-muted">Judge the risk as if no control worked. Impact and likelihood are yours to enter. Nothing is suggested.</p><JudgmentForm key={`i-${risk.id}-${risk.derived.inherent_level}-${risk.assessment.inherent.rationale}`} kind="inherent" seed={seed} risk={risk} /></Section>
    <Section id="r-residual" title="Your residual risk assessment">
      {risk.derived.inherent_level === null && <p role="status" className="rk-warn">Save an inherent assessment first. Residual risk is judged against it.</p>}
      <p className="m-muted">Judge the risk with the controls you name. A recorded test result is evidence, not a judgment.</p>
      <JudgmentForm key={`r-${risk.id}-${risk.derived.residual_level}-${risk.assessment.residual.rationale}-${risk.derived.inherent_level}`} kind="residual" seed={seed} risk={risk} disabled={risk.derived.inherent_level === null} controls={ctl} /></Section>
    <Section id="r-treatment" title="Owner and treatment"><TreatmentSection key={risk.id + risk.treatment.strategy} seed={seed} risk={risk} /></Section>
    <Section id="r-review" title="Review"><ReviewSection risk={risk} seed={seed} /></Section>
  </>;
}

function NewRisk() {
  const [v, setV] = useState({ title: "", category: "", system: "", scenario: "", assets: "" }), [err, setErr] = useState("");
  return <form aria-label="Add a risk of your own" onSubmit={(e) => { e.preventDefault(); if (!v.title.trim()) { setErr("A risk needs a title."); return; } navigate(`${RISK_PATH}/${addCustom(v)}`); }} noValidate>
    <Callout kind="info"><strong>Your own risk has no source.</strong> It is labelled that way everywhere, and it carries no linked evidence or controls.</Callout>
    <div className="rk-fields"><label>Title<input value={v.title} maxLength={200} onChange={(e) => setV({ ...v, title: e.target.value })} aria-describedby={err ? "new-err" : undefined} /></label>
      <label>Category<input value={v.category} maxLength={200} onChange={(e) => setV({ ...v, category: e.target.value })} /></label><label>Related AI system, model, agent or component<input value={v.system} maxLength={200} onChange={(e) => setV({ ...v, system: e.target.value })} /></label>
      <label>Threat scenario<textarea rows={3} value={v.scenario} maxLength={2000} onChange={(e) => setV({ ...v, scenario: e.target.value })} /></label><label>Affected assets<input value={v.assets} maxLength={200} onChange={(e) => setV({ ...v, assets: e.target.value })} /></label></div>
    {err && <p role="alert" id="new-err" className="rk-warn">{err}</p>}<div className="m-actions"><Button>Create the risk</Button><LinkButton href={`${RISK_PATH}/register`} variant="ghost" internal>Cancel</LinkButton></div></form>;
}

function MethodView({ seed }: { seed: Seed }) {
  const m = seed.methodology;
  return <>
    <Callout kind="info"><strong>{m.name}.</strong> {m.statement}</Callout>
    <Section id="m-scales" title="Scales"><Table caption="Impact scale" head={["Impact", "Meaning"]} rows={m.impact.map((x) => [x.label, x.definition])} /><Table caption="Likelihood scale" head={["Likelihood", "Meaning"]} rows={m.likelihood.map((x) => [x.label, x.definition])} /></Section>
    <Section id="m-matrix" title="How a level is looked up">
      <Table caption="Risk level for each impact and likelihood. Rows are impact, columns are likelihood." head={["Impact \\ Likelihood", ...m.likelihood.map((x) => x.label)]} rows={m.impact.map((i) => [i.label, ...m.likelihood.map((l) => <LevelBadge key={l.id} level={m.matrix[i.id][l.id]} />)])} /></Section>
    <Section id="m-rules" title="Rules"><ol className="m-rules">{m.rules.map((x) => <li key={x}>{x}</li>)}</ol><p className="m-muted">Why no numbers: <q>{m.source_rule.text}</q> <small className="m-src">Source: <code>{m.source_rule.file.split("/").pop()}</code></small></p></Section>
    <Section id="m-treat" title="Treatment options"><Table caption="Treatment options" head={["Option", "Meaning"]} rows={m.treatment.map((x) => [x.label, x.meaning])} /></Section>
    <Section id="m-origin" title="Where each field comes from"><dl className="rk-origins">{m.origins.map((o) => <div key={o.id}><dt><OriginBadge o={o.id} method={m} /></dt><dd>{o.meaning}</dd></div>)}</dl></Section>
  </>;
}

/* ------------------------------------------------------------ page */
export default function RiskCenter({ route }: { route: RiskRoute }) {
  const { seed, err } = useSeed();
  const titles: Record<string, string> = { overview: "Risk Center", register: "Risk register", detail: "Risk assessment", new: "Add a risk", method: "Assessment method" };
  const tabs = [["Overview", RISK_PATH, "overview"], ["Register", `${RISK_PATH}/register`, "register"], ["Method", `${RISK_PATH}/method`, "method"]] as const;
  return <div className="page wk ev rk">
    <header className="page-header"><div><div className="eyebrow">AI RISK CENTER · QUALITATIVE ASSESSMENT · LOCAL DRAFT</div><h1>{titles[route.view]}</h1>
      <p>Source-backed risk candidates, your own judgments kept apart from them, and a treatment record. Nothing is scored for you and nothing is approved by saving.</p></div></header>
    <nav aria-label="Risk Center" className="ev-tabs"><ul>{tabs.map(([l, to, v]) => <li key={v}><Link to={to} aria-current={route.view === v || (v === "register" && (route.view === "detail" || route.view === "new")) ? "page" : undefined} className={route.view === v || (v === "register" && (route.view === "detail" || route.view === "new")) ? "is-current" : ""}>{l}</Link></li>)}</ul></nav>
    {err && <Failed />}
    {!seed && !err && <div className="m-sec" role="status"><p className="m-muted">Loading the source-backed risks…</p></div>}
    {seed && <><DraftBar />
      {route.view === "overview" && <Overview seed={seed} />}
      {route.view === "register" && <Register seed={seed} filter={route.filter} />}
      {route.view === "detail" && <Detail seed={seed} id={route.id} />}
      {route.view === "new" && <NewRisk />}
      {route.view === "method" && <MethodView seed={seed} />}</>}
  </div>;
}
