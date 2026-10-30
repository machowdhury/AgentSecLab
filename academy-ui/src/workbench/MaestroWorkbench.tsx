import { useState } from "react";
import { Badge, Button } from "../ui";
import { CopyButton } from "../mission/parts";
import { sha256 } from "../risk/sha256";
import { Link } from "../router";
import data from "../content/maestro.json";
import { assess, emptyModel, exampleModel, levelOf, prioritize } from "../maestro/assess";
import { architectureBrief, exportDoc, markdown } from "../maestro/report";
import { clearDraft, setModel, useDraft } from "../maestro/store";
import type { Assessment, Data, Evidence, Judgment, Model, Threat } from "../maestro/types";

const D = data as unknown as Data;
const IMPACT = D.risk.impact, LIKE = D.risk.likelihood;
const tone = (l: string | null) => (l === "HIGH" ? "high" : l === "MEDIUM" ? "medium" : l === "LOW" ? "low" : "muted") as "high" | "medium" | "low" | "muted";
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));
const blank = (): Judgment => ({ impact: null, likelihood: null, rationale: "" });

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Judge({ label, j, onChange }: { label: string; j: Judgment; onChange: (j: Judgment) => void }) {
  const lv = levelOf(D, j.impact, j.likelihood);
  return <fieldset className="mx-judge"><legend>{label} <Badge tone={tone(lv)}>{lv ?? "NOT ASSESSED"}</Badge></legend>
    <label>Impact <select aria-label={`${label}: impact`} value={j.impact ?? ""} onChange={(e) => onChange({ ...j, impact: (e.target.value || null) as Judgment["impact"] })}><option value="">choose</option>{IMPACT.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}</select></label>
    <label>Likelihood <select aria-label={`${label}: likelihood`} value={j.likelihood ?? ""} onChange={(e) => onChange({ ...j, likelihood: (e.target.value || null) as Judgment["likelihood"] })}><option value="">choose</option>{LIKE.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}</select></label>
    <label>Why <input aria-label={`${label}: reason`} value={j.rationale} maxLength={400} onChange={(e) => onChange({ ...j, rationale: e.target.value })} /></label></fieldset>;
}

function ThreatCard({ t, onChange, onRemove }: { t: Threat; onChange: (t: Threat) => void; onRemove: () => void }) {
  const layer = D.framework.layers.find((l) => l.n === t.layer)!, set = <K extends keyof Threat>(k: K, v: Threat[K]) => onChange({ ...t, [k]: v });
  const multi = (e: React.ChangeEvent<HTMLSelectElement>) => Array.from(e.target.selectedOptions).map((o) => o.value);
  return <div className="m-card mx-threat" role="group" aria-label={`Threat ${t.id}`}>
    <h4>{t.id} <Badge tone="muted">LAYER {t.layer}</Badge> <Badge tone={tone(levelOf(D, t.inherent.impact, t.inherent.likelihood))}>{levelOf(D, t.inherent.impact, t.inherent.likelihood) ?? "INHERENT NOT ASSESSED"}</Badge> <Badge tone={tone(levelOf(D, t.residual.impact, t.residual.likelihood))}>{levelOf(D, t.residual.impact, t.residual.likelihood) ?? "RESIDUAL NOT ASSESSED"}</Badge></h4>
    <label>Threat (the article's label for this layer, or custom)
      <select aria-label={`${t.id}: threat label`} value={t.custom ? "__custom" : t.label} onChange={(e) => (e.target.value === "__custom" ? onChange({ ...t, custom: true, label: "" }) : onChange({ ...t, custom: false, label: e.target.value }))}>
        <option value="">choose</option>{layer.official_threats.map((x) => <option key={x} value={x}>{x}</option>)}<option value="__custom">Custom (explain why below)</option></select></label>
    {t.custom && <label>Custom threat name <input aria-label={`${t.id}: custom threat name`} value={t.label} maxLength={120} onChange={(e) => set("label", e.target.value)} /></label>}
    <label>Kind (as the official Analyzer groups them) <select aria-label={`${t.id}: kind`} value={t.kind} onChange={(e) => set("kind", e.target.value as Threat["kind"])}><option value="traditional">traditional</option><option value="agentic">agentic</option></select></label>
    <label>What could happen{t.custom ? " (for a custom threat, also say why the article's list does not cover it)" : ""} <textarea aria-label={`${t.id}: description`} rows={2} maxLength={600} value={t.description} onChange={(e) => set("description", e.target.value)} /></label>
    <label>Elements involved <select multiple size={4} aria-label={`${t.id}: elements`} value={t.elements} onChange={(e) => set("elements", multi(e))}>{D.acmebank.elements.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
    <label>Evidence status <select aria-label={`${t.id}: evidence status`} value={t.evidence} onChange={(e) => set("evidence", e.target.value as Evidence)}><option value="">choose</option><option value="DEMONSTRATED">DEMONSTRATED (a lab shows it)</option><option value="DOCUMENTED">DOCUMENTED (a file says it)</option><option value="ASSUMED">ASSUMED (no evidence)</option></select></label>
    <label>AgentSecLab scenarios that show or relate to it <select multiple size={5} aria-label={`${t.id}: scenarios`} value={t.scenarios} onChange={(e) => set("scenarios", multi(e))}>{D.acmebank.scenarios.map((x) => <option key={x.lab_id} value={x.lab_id}>{x.lab_id} ({x.family})</option>)}</select></label>
    {t.scenarios.length > 0 && <p className="m-muted">Open: {t.scenarios.map((s, i) => <span key={s}>{i ? ", " : ""}<Link to={`/learn/lab/${s}`}>{s}</Link></span>)}</p>}
    <Judge label={`${t.id} inherent risk (no control works)`} j={t.inherent} onChange={(j) => set("inherent", j)} />
    <label>Controls that exist <select multiple size={5} aria-label={`${t.id}: controls`} value={t.controls} onChange={(e) => set("controls", multi(e))}>{D.acmebank.controls.map((c) => <option key={c.id} value={c.id}>{c.id}: {c.name} [{c.class}]</option>)}</select></label>
    <label>Mitigation recommended <textarea aria-label={`${t.id}: mitigation`} rows={2} maxLength={600} value={t.mitigation} onChange={(e) => set("mitigation", e.target.value)} /></label>
    <Judge label={`${t.id} residual risk (with the controls you named)`} j={t.residual} onChange={(j) => set("residual", j)} />
    <div className="m-actions"><Button variant="ghost" onClick={onRemove}>Remove {t.id}</Button></div></div>;
}

/** The MAESTRO threat-modeling workbench for AcmeBank. Everything is typed by the learner and saved only in this browser; nothing is sent anywhere or run. */
export default function MaestroWorkbench() {
  const { model, saved, notice } = useDraft();
  const [result, setResult] = useState<Assessment | null>(null);
  const [pathName, setPathName] = useState("");
  const upd = (f: (m: Model) => void, note = "") => { const m = clone(model); f(m); setModel(m, note); setResult(null); };
  const nextId = () => `T${model.threats.reduce((n, t) => Math.max(n, Number(t.id.replace(/\D/g, "")) || 0), 0) + 1}`;
  const brief = architectureBrief(model, D);
  return <div className="m-sec mx" data-testid="maestro-workbench">
    <h3>MAESTRO threat model for AcmeBank <Badge tone="replay">LOCAL DRAFT, NOT AN ASSESSMENT</Badge></h3>
    <p className="m-muted">Work through the six steps of the Cloud Security Alliance's MAESTRO method for the AcmeBank agentic architecture. You type everything; it is saved only in this browser and nothing is run, sent or approved. {saved === "memory" ? "Saving is unavailable here, so work is kept in memory only." : ""}</p>
    {notice && <p role="status">{notice}</p>}
    <div className="m-actions">
      <Button variant="secondary" onClick={() => setModel(exampleModel(D), "The worked example was loaded. Its judgments are the lab author's, for a lab system. Replace them with yours.")}>Load the worked example</Button>
      <Button variant="ghost" onClick={() => { clearDraft(); setResult(null); }}>Clear my draft</Button>
      <Button onClick={() => { const t = new Date().toISOString(); download("acmebank-maestro-threat-model.md", markdown(model, D, sha256, t), "text/markdown"); }}>Download report (Markdown)</Button>
      <Button variant="secondary" onClick={() => download("acmebank-maestro-threat-model.json", JSON.stringify(exportDoc(model, D, sha256), null, 2), "application/json")}>Download model (JSON)</Button>
    </div>

    <section aria-label="Step 1 scope" className="m-sec"><h4>1. Scope and purpose</h4>
      <label>What are you modeling, what is in and out of scope, and what do you assume? <textarea aria-label="Scope" rows={3} maxLength={1500} value={model.scope} onChange={(e) => upd((m) => { m.scope = e.target.value; })} /></label></section>

    <section aria-label="Step 2 decomposition" className="m-sec"><h4>2. Decompose the system into the seven layers</h4>
      <p className="m-muted">Put each AcmeBank element on the layer where it mainly belongs. Layer 6 is the article's vertical layer: security and compliance controls that cut across the others. Some elements touch two layers; the repository file shows what they are.</p>
      <ul className="mx-layers">{D.framework.layers.map((l) => <li key={l.n}><strong>{l.n}. {l.name}</strong>{l.vertical ? " (vertical)" : ""}: {l.description}</li>)}</ul>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="AcmeBank elements; scrolls sideways on a narrow screen"><table className="m-stack"><thead><tr><th scope="col">Element</th><th scope="col">Kind</th><th scope="col">Where it is in the repository</th><th scope="col">Your layer</th></tr></thead>
        <tbody>{D.acmebank.elements.map((e) => <tr key={e.id}><th scope="row" data-label="Element">{e.name}<br /><small className="m-muted">{e.note}</small></th><td data-label="Kind">{e.kind}</td><td data-label="Where"><code>{e.evidence.join(", ")}</code></td>
          <td data-label="Your layer"><select aria-label={`Layer for ${e.name}`} value={model.placements[e.id] ?? 0} onChange={(ev) => upd((m) => { m.placements[e.id] = Number(ev.target.value); })}><option value={0}>not placed</option>{D.framework.layers.map((l) => <option key={l.n} value={l.n}>{l.n}. {l.name}</option>)}</select></td></tr>)}</tbody></table></div></section>

    <section aria-label="Step 2b trust boundaries and interactions" className="m-sec"><h4>2b. Trust boundaries, and how agents and tools interact</h4>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Trust boundaries; scrolls sideways on a narrow screen"><table className="m-stack"><thead><tr><th scope="col">Boundary</th><th scope="col">Found it</th><th scope="col">Between layer</th><th scope="col">and layer</th></tr></thead>
        <tbody>{D.acmebank.boundaries.map((b) => { const a = model.boundaries[b.id] ?? { found: false, layers: [0, 0] as [number, number] };
          const put = (f: (x: typeof a) => void) => upd((m) => { const x = clone(a); f(x); m.boundaries[b.id] = x; });
          return <tr key={b.id}><th scope="row" data-label="Boundary">{b.id} {b.name}<br /><small className="m-muted">{b.note}</small></th>
            <td data-label="Found it"><input type="checkbox" aria-label={`Identified ${b.name}`} checked={a.found} onChange={(e) => put((x) => { x.found = e.target.checked; })} /></td>
            {[0, 1].map((i) => <td key={i} data-label={i ? "and layer" : "Between layer"}><select aria-label={`${b.name}: layer ${i + 1}`} value={a.layers[i]} onChange={(e) => put((x) => { x.layers[i] = Number(e.target.value); })}><option value={0}>choose</option>{D.framework.layers.map((l) => <option key={l.n} value={l.n}>{l.n}. {l.name}</option>)}</select></td>)}</tr>; })}</tbody></table></div>
      <h5>Data flows and agent and tool interactions to reason about</h5>
      <ul>{D.acmebank.interactions.map((i) => <li key={i.id}><strong>{i.id}</strong> {i.from} to {i.to}: {i.data} <Badge tone="muted">{i.trust}</Badge> (layers {i.layers[0]} and {i.layers[1]})</li>)}</ul></section>

    <section aria-label="Step 3 layer threats" className="m-sec"><h4>3. Threats, layer by layer</h4>
      <p className="m-muted">For each layer start from the article's threat list, then tailor it to AcmeBank. If a listed threat does not apply (Layer 6's list is about AI security agents, which AcmeBank does not have), say so in a custom threat rather than forcing a label.</p>
      {D.framework.layers.map((l) => { const mine = model.threats.filter((t) => t.layer === l.n);
        return <details key={l.n} open={mine.length > 0} className="mx-layer"><summary>{l.n}. {l.name} <Badge tone="muted">{mine.length} threat{mine.length === 1 ? "" : "s"}</Badge></summary>
          <p className="m-muted">The article lists: {l.official_threats.join("; ")}.</p>
          {mine.map((t) => <ThreatCard key={t.id} t={t} onChange={(n) => upd((m) => { m.threats[m.threats.findIndex((x) => x.id === t.id)] = n; })} onRemove={() => upd((m) => { m.threats = m.threats.filter((x) => x.id !== t.id); m.paths.forEach((p) => { p.steps = p.steps.filter((s) => s.threat !== t.id); }); })} />)}
          <div className="m-actions"><Button variant="secondary" onClick={() => upd((m) => { m.threats.push({ id: nextId(), layer: l.n, label: "", custom: false, kind: "agentic", description: "", elements: [], evidence: "", scenarios: [], controls: [], inherent: blank(), mitigation: "", residual: blank() }); })}>Add a Layer {l.n} threat</Button></div></details>; })}</section>

    <section aria-label="Step 4 cross-layer paths" className="m-sec"><h4>4. Cross-layer attack paths</h4>
      <p className="m-muted">A path chains threats across layers (the article's example runs from infrastructure through a data store to the model). Each step names a threat from your register on that step's layer. The article lists as cross-layer: {D.framework.cross_layer_threats.join(", ")}.</p>
      {model.paths.map((p) => <div className="m-card" key={p.id} role="group" aria-label={`Path ${p.id}`}><h5>{p.id} {p.name}</h5>
        <label>What happens, in one or two sentences <textarea aria-label={`${p.id}: narrative`} rows={2} maxLength={600} value={p.narrative} onChange={(e) => upd((m) => { m.paths.find((x) => x.id === p.id)!.narrative = e.target.value; })} /></label>
        <ol>{p.steps.map((s, i) => <li key={i}>Layer <select aria-label={`${p.id} step ${i + 1} layer`} value={s.layer} onChange={(e) => upd((m) => { const st = m.paths.find((x) => x.id === p.id)!.steps[i]; st.layer = Number(e.target.value); st.threat = ""; })}>{D.framework.layers.map((l) => <option key={l.n} value={l.n}>{l.n}</option>)}</select>{" "}
          <select aria-label={`${p.id} step ${i + 1} threat`} value={s.threat} onChange={(e) => upd((m) => { m.paths.find((x) => x.id === p.id)!.steps[i].threat = e.target.value; })}><option value="">choose a threat on this layer</option>{model.threats.filter((t) => t.layer === s.layer).map((t) => <option key={t.id} value={t.id}>{t.id} {t.label || "(unnamed)"}</option>)}</select>{" "}
          <input aria-label={`${p.id} step ${i + 1} note`} placeholder="what this step does" value={s.note} maxLength={200} onChange={(e) => upd((m) => { m.paths.find((x) => x.id === p.id)!.steps[i].note = e.target.value; })} /></li>)}</ol>
        <div className="m-actions"><Button variant="secondary" onClick={() => upd((m) => { m.paths.find((x) => x.id === p.id)!.steps.push({ layer: 1, threat: "", note: "" }); })}>Add a step to {p.id}</Button> <Button variant="ghost" onClick={() => upd((m) => { m.paths = m.paths.filter((x) => x.id !== p.id); })}>Remove {p.id}</Button></div></div>)}
      <label>New path name <input aria-label="New path name" value={pathName} maxLength={120} onChange={(e) => setPathName(e.target.value)} /></label>
      <Button variant="secondary" disabled={!pathName.trim()} onClick={() => { upd((m) => { m.paths.push({ id: `P${m.paths.reduce((n, p) => Math.max(n, Number(p.id.replace(/\D/g, "")) || 0), 0) + 1}`, name: pathName.trim(), narrative: "", steps: [] }); }); setPathName(""); }}>Add a path</Button></section>

    <section aria-label="Step 5 prioritization" className="m-sec"><h4>5. Risk prioritization</h4>
      <p className="m-muted">{D.risk_method.why}</p>
      {model.threats.length === 0 ? <p className="m-muted">Add threats to see them ranked.</p> :
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Ranked threats; scrolls sideways on a narrow screen"><table className="m-stack"><thead><tr><th scope="col">Rank</th><th scope="col">Threat</th><th scope="col">Layer</th><th scope="col">Inherent</th><th scope="col">Residual</th><th scope="col">Evidence</th></tr></thead>
          <tbody>{prioritize(model, D).map((t, i) => <tr key={t.id}><td data-label="Rank">{i + 1}</td><th scope="row" data-label="Threat">{t.id} {t.label || "(unnamed)"}</th><td data-label="Layer">{t.layer}</td>
            <td data-label="Inherent"><Badge tone={tone(levelOf(D, t.inherent.impact, t.inherent.likelihood))}>{levelOf(D, t.inherent.impact, t.inherent.likelihood) ?? "NOT ASSESSED"}</Badge></td>
            <td data-label="Residual"><Badge tone={tone(levelOf(D, t.residual.impact, t.residual.likelihood))}>{levelOf(D, t.residual.impact, t.residual.likelihood) ?? "NOT ASSESSED"}</Badge></td><td data-label="Evidence">{t.evidence || "not stated"}</td></tr>)}</tbody></table></div>}</section>

    <section aria-label="Step 6 check" className="m-sec"><h4>6. Check your model against the method</h4>
      <p className="m-muted">{D.rubric.pass}</p>
      <div className="m-actions"><Button onClick={() => setResult(assess(model, D))}>Check my model</Button></div>
      {result && <div role="status" data-testid="maestro-result"><p><strong>{result.applied ? "The structure MAESTRO asks for is present." : "The structure MAESTRO asks for is not complete yet."}</strong></p>
        <ul>{result.results.map((r) => <li key={r.id} data-state={r.state}><Badge tone={r.state === "MET" ? "good" : r.state === "PARTIAL" ? "warning" : "high"}>{r.state}</Badge> <strong>{r.id} {r.title}.</strong> {r.detail}</li>)}</ul></div>}
      <details><summary>The criteria in full</summary><ul>{D.rubric.criteria.map((c) => <li key={c.id}><strong>{c.id} {c.title}.</strong> {c.text}</li>)}</ul></details></section>

    <section aria-label="Compare with the official Threat Analyzer" className="m-sec"><h4>7. Compare with the official MAESTRO Threat Analyzer (optional)</h4>
      <p>{D.analyzer.status_here}</p><p className="m-muted">{D.analyzer.provenance_note}</p>
      <pre className="mx-brief" tabIndex={0}>{brief}</pre><CopyButton text={brief} />
      <ol>{D.analyzer.compare.map((c) => <li key={c}>{c}</li>)}</ol>
      <p className="m-muted">Sources: {D.framework.sources.map((s, i) => <span key={s.id}>{i ? "; " : ""}<a href={s.url} rel="noreferrer noopener" target="_blank">{s.title}</a></span>)}.</p></section>
  </div>;
}
