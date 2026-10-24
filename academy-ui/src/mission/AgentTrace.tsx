import { Badge } from "../ui";
import { evidenceText } from "./content";
import { Callout } from "./parts";
import type { RunStep, RunView } from "../types";

const norm = (t: string) => t.toLowerCase().split(/\s+/).filter(Boolean).join(" ");
/** True when a proposed string argument reproduces at least `min` characters of the applicant's notes (the same rule the Loan Desk uses for queue_harm). */
function copiesNotes(value: unknown, notes: string, min = 24): boolean {
  if (typeof value !== "string") return false;
  const v = norm(value), n = norm(notes);
  if (v.length < min || n.length < min) return false;
  for (let i = 0; i + min <= n.length; i++) if (v.includes(n.slice(i, i + min))) return true;
  return false;
}
const show = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));

function ToolStep({ s, view, began }: { s: RunStep; view: RunView; began: boolean | undefined }) {
  const p = s.proposal!, d = s.decision, notes = view.application?.notes ?? "";
  const denied = d?.decision === "DENY", noteDenied = d?.reason === "argument_not_allowed:note";
  const real = p.source === "model";
  const disagree = began !== undefined && s.executed !== undefined && began !== s.executed;
  return <>
    <p><strong>{real ? "The model proposed" : "The TEST DOUBLE proposed"}</strong> <code>{p.tool}</code></p>
    <dl className="m-trace__args" aria-label={`Arguments of the step ${s.step} proposal`}>
      {Object.entries(p.arguments ?? {}).map(([k, v]) => { const copied = copiesNotes(v, notes);
        return <div key={k}><dt>{k}</dt><dd className={copied ? "m-trace__copied" : ""}>{copied ? <mark>{show(v)}</mark> : show(v)}{copied && <span className="m-trace__tag"> copied from the applicant's notes</span>}</dd></div>; })}
    </dl>
    {p.coerced && p.coerced.length > 0 && <p className="m-muted">Number formatting was normalised for: {p.coerced.join(", ")}.</p>}
    <p><strong>Policy decision{d?.control_id ? ` (${d.control_id})` : ""}:</strong> <Badge tone={denied ? "deny" : "allow"}>{d?.decision}</Badge> <code>{d?.reason}</code></p>
    {noteDenied && <Callout kind="good" role="status"><strong>Refused: <code>argument_not_allowed:note</code>.</strong> The review note was not one of the allowed reason codes, so the applicant-controlled text was rejected before any handler ran. <strong>The review handler did not run and this call wrote nothing to the underwriter queue.</strong></Callout>}
    <p><strong>Handler:</strong> {began ? "began (recorded as agentsec.mcp.started)" : denied ? "did not run. Nothing executed for this step." : "no start was recorded for this step"}{disagree ? " (the step record and the event timeline disagree; trust the events)" : ""}</p>
    {began && (s.error ? <p className="m-muted">Handler error: {s.error}</p> : s.result_preview ? <p className="m-muted">Handler result preview (first 300 characters of what it returned): <code>{s.result_preview}</code></p> : <p className="m-muted">No result preview was recorded.</p>)}
  </>;
}

/** The chronological record of one run: what the model proposed, what policy decided, whether a handler began, and what the model did next. Every value is a recorded field; nothing is inferred from an ALLOW. */
export function AgentTrace({ view, label }: { view: RunView; label: string }) {
  const steps = view.steps ?? [], calls = new Map((view.timeline?.tool_calls ?? []).map((c) => [c.step, c]));
  const notes = view.application?.notes ?? "", real = view.model?.proposal_source === "model";
  const done = view.status !== "RUNNING";
  return <section className="m-trace m-sec" aria-label={`What the agent did: ${label}`}>
    <h3>What the agent did <Badge tone={real ? "live" : "warning"}>{real ? "REAL MODEL" : "TEST DOUBLE"}</Badge></h3>
    <p className="m-muted">{real ? `Proposals below came from ${view.model.name} through Ollama.` : "These proposals came from a scripted test double, not a model."} Posture <strong>{view.posture.toUpperCase()}</strong>. Run <code>{view.run_id.slice(0, 8)}…</code>. Each row is a recorded field.</p>
    <div className="m-trace__attacker"><strong>Applicant notes: attacker-controlled customer text</strong>
      <p>{notes ? `“${notes}”` : "(no notes)"}</p><small>This is the only text in the case the applicant wrote. It reaches the model as untrusted data.</small></div>
    {!steps.length && <p className="m-muted">{done ? "The agent recorded no steps." : "Waiting for the first step."}</p>}
    <ol className="m-trace__steps">{steps.map((s, i) => {
      const prev = steps[i - 1], after = prev?.kind === "tool" && prev.decision?.decision === "DENY";
      return <li key={s.step} className={`m-trace__step m-trace__step--${s.kind}`}>
        <div className="m-trace__head"><span>Step {s.step}</span>{s.llm_ms !== undefined && <small>model reply took {s.llm_ms} ms</small>}{after && <Badge tone="muted">next move after the denial</Badge>}</div>
        {s.kind === "tool" && s.proposal && <ToolStep s={s} view={view} began={calls.get(s.step)?.executed} />}
        {s.kind === "invalid_proposal" && <p><strong>Unusable model reply</strong> (<code>{s.reason}</code>). Nothing was proposed, no policy decision was made and no handler ran.</p>}
        {s.kind === "final" && <><p><strong>The model gave its final answer</strong>: recommendation <code>{s.recommendation}</code></p>
          <p className="m-trace__model"><Badge tone="warning">MODEL-WRITTEN, NOT VERIFIED</Badge> {s.summary}</p></>}
      </li>; })}
    </ol>
    {steps.length > 0 && steps[steps.length - 1].kind === "tool" && steps[steps.length - 1].decision?.decision === "DENY" && done && <p className="m-muted">The run ended after this denial.</p>}
    <p className="m-muted">The text the Loan Desk sent back to the model after a denial is not recorded, so it is not shown here.</p>
    {done && view.facts && <div className="m-trace__facts"><h4>Business facts computed by the Loan Desk (not model-written)</h4>
      <p>Screening result against the lab's reference rules: <strong>{view.facts.screening_result.replace(/_/g, " ")}</strong>. {view.facts.basis}</p>
      <ul className="m-rules">{view.facts.items.map((f) => <li key={f.id}>{f.label}: <strong>{f.value} {f.unit}</strong> <small className="m-src">from {f.source}</small></li>)}</ul></div>}
    {done && view.advisory && <div className="m-trace__facts"><h4>The model's recommendation <Badge tone="warning">MODEL-WRITTEN, NOT VERIFIED</Badge></h4>
      <p>{view.advisory.recommendation ? <>Recommendation <code>{view.advisory.recommendation}</code>. </> : null}{view.advisory.summary}</p>
      {view.advisory.differs_from_screening && <Callout kind="warn" role="status">The model's recommendation differs from the screening result computed above.</Callout>}
      {view.advisory.unsupported_figures && view.advisory.unsupported_figures.length > 0 && <p className="m-muted">Figures in the summary that no tool or computation supports: {view.advisory.unsupported_figures.join(", ")}.</p>}</div>}
    <p className="m-muted">Telemetry: {view.evidence?.event_count ?? 0} events emitted locally by AcmeBank. {view.evidence ? evidenceText(view) : ""}</p>
  </section>;
}
