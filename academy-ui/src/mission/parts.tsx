import { useState, type ReactNode } from "react";
import { Badge, Button, FactCard, Icon } from "../ui";
import type { RunView, Slot } from "../types";
import { BRIEFS, GLOSSARY, SEC_LABEL, evidenceText, evidenceTone, storyOf } from "./content";
import type { StepId } from "../stages";
import { keepWaiting, retryLaunch, stopWaiting, useSlot } from "./runStore";
import { reviewCall } from "../runs";

export function Brief({ step }: { step: StepId }) {
  const b = BRIEFS[step];
  return <dl className="m-brief">
    <div><dt>What you are doing</dt><dd>{b.doing}</dd></div>
    <div><dt>Why it matters</dt><dd>{b.why}</dd></div>
    <div><dt>What to do</dt><dd>{b.todo}</dd></div>
    <div><dt>Evidence to inspect</dt><dd>{b.evidence}</dd></div>
    <div><dt>What you will learn</dt><dd>{b.learn}</dd></div>
  </dl>;
}

export function Callout({ kind = "info", children, role }: { kind?: "info" | "warn" | "good"; children: ReactNode; role?: "status" | "alert" }) {
  return <div className={`m-callout m-callout--${kind}`} role={role}>{children}</div>;
}

export function Glossary() {
  return <details className="m-glossary" id="glossary">
    <summary>Glossary: the words this mission uses</summary>
    <dl>{GLOSSARY.map(([id, term, text]) => <div key={id}><dt id={`term-${id}`}>{term}</dt><dd>{text}</dd></div>)}</dl>
  </details>;
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [msg, setMsg] = useState("");
  const copy = () => {
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(() => setMsg("Copied."), () => setMsg("Copy failed; select the text."));
    else setMsg("Select and copy the text.");
  };
  return <><button type="button" className="button button--ghost" onClick={copy}><Icon name="copy" size={15} /> {label}</button><span className="m-muted" role="status"> {msg}</span></>;
}

export function Story({ view }: { view: RunView }) {
  const st = storyOf(view);
  if (!st) return null;
  return <Callout kind={st.kind === "bad" ? "warn" : st.kind === "good" ? "good" : "info"} role="status"><strong>{st.head}</strong> {st.body}</Callout>;
}

export function QueueBlock({ view }: { view: RunView }) {
  const harm = view.queue_harm?.tickets_with_applicant_text ?? [];
  return <div className="m-queue">
    <h3>Underwriter queue: what a human reads</h3>
    {!view.tickets?.length ? <p>Empty. The agent filed nothing in this run.</p> : view.tickets.map((t) => {
      const bad = harm.includes(t.ticket_id);
      return <div className={`m-ticket ${bad ? "m-ticket--harm" : ""}`} key={t.ticket_id}>
        <p className="m-ticket__meta">{t.ticket_id} · {t.applicant_id} · filed by the AI agent</p>
        <p className="m-ticket__note">{t.note}</p>
        {bad && <p className="m-ticket__flag">This note copies text written by the applicant, filed under the agent's authority.</p>}
      </div>;
    })}
  </div>;
}

export function TimelineTable({ view }: { view: RunView }) {
  const calls = new Map((view.timeline?.tool_calls ?? []).map((c) => [c.step, c]));
  const rows = (view.steps ?? []).filter((s) => s.kind === "tool" && s.proposal && s.decision);
  if (!rows.length) return <p>No tool action was proposed.</p>;
  return <div className="table-wrap"><table>
    <caption className="m-caption">Proposed, decided, executed</caption>
    <thead><tr><th scope="col">Step</th><th scope="col">Tool</th><th scope="col">Proposed by</th><th scope="col">Policy decision</th><th scope="col">Executed</th></tr></thead>
    <tbody>{rows.map((s) => <tr key={s.step}>
      <td>{s.step}</td><td><code>{s.proposal!.tool}</code></td><td>{s.proposal!.source === "model" ? "model" : "TEST DOUBLE"}</td>
      <td>{s.decision!.decision} ({s.decision!.reason})</td><td>{calls.get(s.step)?.executed ? "yes, handler began" : "no"}</td>
    </tr>)}</tbody>
  </table></div>;
}

const secTone = (o: string) => (o === "BLOCKED" ? "deny" : "muted") as "deny" | "muted";

export function RunResult({ view, story = true }: { view: RunView; story?: boolean }) {
  const o = view.outcomes;
  const ops = o?.operations;
  const call = reviewCall(view);
  return <>
    {story && <Story view={view} />}
    {view.status === "FAILED" && <Callout kind="warn">{view.stop_reason === "model_unavailable" ? `The model could not be reached. No action was proposed, no policy decision was made and no tool ran. ${view.error ?? ""}` : `The run failed (${view.stop_reason}). ${view.error ?? ""}`}</Callout>}
    {view.status === "INCOMPLETE" && <Callout kind="warn">The agent used up its step budget before finishing. The business workflow is INCOMPLETE.</Callout>}
    {o && view.status !== "RUNNING" && <div className="facts">
      <FactCard label="Security outcome" value={SEC_LABEL[o.security.outcome] ?? o.security.outcome} detail={o.security.blocked.length ? `${o.security.blocked.length} proposed action(s) refused by policy` : o.security.outcome === "NOT_EXERCISED" ? "No policy decision was made about the attack" : "No proposed action was denied"} tone={secTone(o.security.outcome)} />
      <FactCard label="Business workflow" value={o.business.outcome} detail={o.business.reason ? `Stop reason: ${o.business.reason}` : "No stop reason recorded"} tone={o.business.outcome === "COMPLETE" ? "allow" : "muted"} />
      {call && <FactCard label="Review decision" value={call.decision} detail={call.executed ? "Handler began (agentsec.mcp.started)" : "Handler did not run"} tone={call.decision === "ALLOW" ? "allow" : "deny"} />}
    </div>}
    {ops && view.status !== "RUNNING" && <p className="m-muted">Proposed {ops.proposed} · authorized {ops.authorized} · denied {ops.denied}{ops.rejected_malformed ? ` (policy ${ops.policy_denied}, malformed ${ops.rejected_malformed})` : ""} · executed {ops.executed}{ops.denied_but_executed ? ` · DENIED-BUT-EXECUTED ${ops.denied_but_executed}` : " · no denied action ran"}</p>}
  </>;
}

/** The full-width detail of a finished run: which calls were refused and why, the timeline, the queue a human reads, the model's summary. */
export function RunDetails({ view }: { view: RunView }) {
  const o = view.outcomes;
  const rejected = o?.security.rejected_malformed ?? [];
  return <>
    {o && o.security.blocked.length > 0 && <ul className="m-list">{o.security.blocked.map((b) => <li key={`${b.step}-${b.tool}`}>Step {b.step} {b.tool}: {b.reason} {b.executed ? "(EXECUTED ANYWAY)" : "(handler did not run)"}</li>)}</ul>}
    {rejected.length > 0 && <ul className="m-list">{rejected.map((b) => <li key={`${b.step}-${b.tool}`}>Step {b.step} {b.tool}: {b.reason} (malformed call, rejected before any policy decision)</li>)}</ul>}
    {view.steps?.length > 0 && <TimelineTable view={view} />}
    {view.status !== "RUNNING" && <QueueBlock view={view} />}
    {view.advisory && view.status === "COMPLETED" && <p className="m-muted">Model summary (advisory, not verified){view.advisory.unsupported_figures?.length ? ` contains unsupported figures: ${view.advisory.unsupported_figures.join(", ")}` : ""}: {view.advisory.summary}</p>}
  </>;
}

export function EvidenceCard({ view }: { view: RunView }) {
  const tone = evidenceTone(view);
  return <div className={`splunk-evidence-card splunk-evidence-card--${tone}`}>
    <div><span className="pulse" /><div><strong>Evidence for this run</strong><p>Local evidence: {view.evidence.event_count} events emitted by AcmeBank. {evidenceText(view)}</p></div></div>
    <Badge tone={tone === "ok" ? "indexed" : tone === "warn" ? "warning" : "muted"}>{view.evidence.indexed_status.replace(/_/g, " ")}</Badge>
  </div>;
}
