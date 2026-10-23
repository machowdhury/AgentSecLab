import type { ReactNode } from "react";
import { Badge, Button, Icon, type IconName } from "../ui";
import { Link, missionPath } from "../router";
import type { RunView, Slot } from "../types";
import type { StageId } from "../stages";
import { evidenceText, storyOf } from "./content";
import { Callout, CopyButton, EvidenceCard, RunDetails, RunResult } from "./parts";
import { keepWaiting, retryLaunch, stopWaiting, useSlot, useVerify, verifyRun } from "./runStore";

// Everything on this component is derived from the real run view and run phase. Nothing is timed, estimated or animated for effect:
// a step is "done" only when the backend state shows it happened, "active" only while the run is RUNNING, and counts are the recorded counts.

export type OutcomeKind = "RUNNING" | "ATTACK_SUCCEEDED" | "BLOCKED" | "NOT_EXERCISED" | "FAILED" | "INCOMPLETE" | "COMPLETED";
type StepState = "done" | "active" | "pending" | "warn" | "failed";

const OUTCOME: Record<OutcomeKind, { label: string; icon: IconName; tone: "bad" | "good" | "warn" | "plain" }> = {
  RUNNING: { label: "RUNNING", icon: "clock", tone: "plain" },
  ATTACK_SUCCEEDED: { label: "ATTACK SUCCEEDED", icon: "target", tone: "bad" },
  BLOCKED: { label: "ATTACK BLOCKED", icon: "shield", tone: "good" },
  NOT_EXERCISED: { label: "NOT EXERCISED", icon: "help", tone: "warn" },
  FAILED: { label: "EXECUTION FAILED", icon: "status", tone: "warn" },
  INCOMPLETE: { label: "RUN INCOMPLETE", icon: "status", tone: "warn" },
  COMPLETED: { label: "COMPLETED", icon: "check", tone: "plain" },
};

const isMalformed = (reason?: string) => Boolean(reason && (reason.startsWith("invalid_arguments") || reason === "unknown_tool"));
const evName = (e: unknown) => (e as Record<string, unknown> | null)?.["event.name"];

export function runOutcome(v: RunView): OutcomeKind {
  if (v.status === "RUNNING") return "RUNNING";
  if (v.status === "FAILED") return "FAILED";
  if (v.queue_harm?.tickets_with_applicant_text?.length) return "ATTACK_SUCCEEDED";
  if (v.outcomes?.security.outcome === "BLOCKED") return "BLOCKED";
  if (v.outcomes?.security.outcome === "NOT_EXERCISED") return "NOT_EXERCISED";
  return v.status === "INCOMPLETE" ? "INCOMPLETE" : "COMPLETED";
}

export interface Step { id: string; label: string; icon: IconName; state: StepState; detail: string }

function verification(v: RunView): { state: StepState; detail: string } {
  const st = v.evidence.indexed_status, sp = v.evidence.splunk;
  const local = v.evidence.event_count;
  if (st === "SPLUNK_VERIFIED") return { state: "done", detail: `SPLUNK-VERIFIED by the host verifier: ${sp?.indexed_events ?? "?"} indexed of ${sp?.local_events ?? local} local events.` };
  if (st === "PENDING") return { state: "active", detail: "Waiting for the host verifier to search Splunk." };
  if (["SPLUNK_MISMATCH", "VERIFICATION_FAILED", "INVALID_RECORD", "STALE"].includes(st)) return { state: "failed", detail: `${st.replace(/_/g, " ")}: the indexed events do not match the ${local} local events.` };
  return { state: "pending", detail: `Not verified yet. ${local} local events recorded. ${v.status === "RUNNING" ? "Verification is possible once the run finishes." : "Press Verify in Investigate."}` };
}

export function runSteps(v: RunView | undefined, submitting: boolean): Step[] {
  if (!v) return [
    { id: "prep", label: "Preparing", icon: "clock", state: submitting ? "active" : "pending", detail: submitting ? "Sending the application to the Loan Desk." : "Waiting for you to launch." },
  ];
  const running = v.status === "RUNNING";
  const calls = (v.steps ?? []).filter((s) => s.kind === "tool" && s.proposal);
  const tools = [...new Set(calls.map((s) => s.proposal!.tool))];
  const decided = calls.filter((s) => s.decision);
  const allow = decided.filter((s) => s.decision!.decision === "ALLOW").length;
  const malformed = decided.filter((s) => s.decision!.decision !== "ALLOW" && isMalformed(s.decision!.reason)).length;
  const denied = decided.filter((s) => s.decision!.decision !== "ALLOW" && !isMalformed(s.decision!.reason)).length;
  const replies = (v.timeline?.events ?? []).filter((e) => evName(e) === "agentsec.llm.completed").length || (v.steps ?? []).length;
  const ver = verification(v);
  const out = runOutcome(v);
  const list: Step[] = [
    { id: "prep", label: "Preparing", icon: "clock", state: "done", detail: `Run accepted · ${v.posture.toUpperCase()} posture · model ${v.model.name}.` },
    { id: "agent", label: "Agent activity", icon: "terminal", state: replies ? (running ? "active" : "done") : running ? "active" : "failed", detail: replies ? `${replies} model repl${replies === 1 ? "y" : "ies"} recorded.` : running ? "Waiting for the model's first reply." : "The model produced no usable reply." },
    { id: "tools", label: "Tool calls", icon: "play", state: calls.length ? (running ? "active" : "done") : running ? "pending" : "warn", detail: calls.length ? `${calls.length} proposed: ${tools.join(", ")}.` : running ? "No tool call proposed yet." : "No tool call was proposed." },
    { id: "policy", label: "Policy evaluation", icon: "shield", state: decided.length === 0 ? (running ? "pending" : "warn") : malformed === decided.length ? "warn" : running ? "active" : "done",
      detail: decided.length ? `${allow} ALLOW · ${denied} DENY by policy${malformed ? ` · ${malformed} malformed (never evaluated)` : ""}.` : running ? "No decision yet." : "No policy decision was made." },
    { id: "evidence", label: "Evidence verification", icon: "search", state: ver.state, detail: ver.detail },
    { id: "outcome", label: "Outcome", icon: OUTCOME[out].icon, state: running ? "pending" : out === "FAILED" || out === "INCOMPLETE" || out === "NOT_EXERCISED" ? "warn" : "done", detail: running ? "Appears when the run finishes." : OUTCOME[out].label.toLowerCase() },
  ];
  // While running, only the most recently reached step is "active"; earlier steps that already have recorded data are done.
  const active = list.map((x, i) => (x.state === "active" && i > 0 && i < 4 ? i : -1)).filter((i) => i >= 0);
  active.slice(0, -1).forEach((i) => { list[i].state = "done"; });
  return list;
}

/** Shared by the Loan Desk and MCP experiences: a vertical list of steps whose states and details the caller derived from real records. */
export function StepList({ steps, label, finished }: { steps: Step[]; label: string; finished: boolean }) {
  const reached = steps.filter((s) => s.state !== "pending").length;
  return <>
    <p className={`m-prog__status ${finished ? "" : "is-running"}`} role="status">{finished ? "Run finished. Check the outcome and the evidence status below." : `In progress: ${reached} of ${steps.length} steps reached. The outcome is not known yet.`}</p>
    <ol className="m-prog" aria-label={label}>
      {steps.map((s) => <li key={s.id} className={`is-${s.state}`}>
        <span className="m-prog__dot" aria-hidden="true"><Icon name={s.state === "done" ? "check" : s.icon} size={14} /></span>
        <div><strong>{s.label}</strong><span className="visually-hidden"> ({s.state})</span><p>{s.detail}</p></div>
      </li>)}
    </ol>
  </>;
}

export function RunProgress({ slot, view, submitting }: { slot: Slot; view?: RunView; submitting: boolean }) {
  return <StepList steps={runSteps(view, submitting)} label={`Progress of the ${slot} run, from the Loan Desk's recorded state`} finished={Boolean(view && view.status !== "RUNNING")} />;
}

/** The outcome in one glance: label, the plain-language result, the real queue ticket when the attack landed, and the next action. */
export function OutcomeBanner({ view, slot, next }: { view: RunView; slot: Slot; next?: { label: string; stage: StageId } }) {
  const kind = runOutcome(view);
  if (kind === "RUNNING") return null;
  const o = OUTCOME[kind], story = storyOf(view);
  const ticket = view.tickets?.find((t) => view.queue_harm.tickets_with_applicant_text.includes(t.ticket_id));
  const retry = kind === "FAILED" || kind === "NOT_EXERCISED" || kind === "INCOMPLETE";
  return <div className={`m-outcome m-outcome--${o.tone}`} role="status">
    <div className="m-outcome__head"><Icon name={o.icon} size={20} /><strong>{o.label}</strong></div>
    <p>{story?.head ?? (view.status === "FAILED" ? "The model could not be reached. No action was proposed and no tool ran." : "The run ended before a result could be read.")}</p>
    {ticket && <p className="m-outcome__ticket">Queue ticket {ticket.ticket_id}: “{ticket.note}”</p>}
    {kind === "BLOCKED" && view.outcomes && <p className="m-muted">{view.outcomes.security.blocked.map((b) => `step ${b.step} ${b.tool}: ${b.reason}`).join(" · ")}</p>}
    <div className="m-actions">
      {retry ? <><Button onClick={() => retryLaunch(slot)}>Run it again <Icon name="play" size={15} /></Button><span className="m-muted">The same application, a new run. Nothing is retried automatically.</span></>
        : next && <Link className="button button--primary" to={missionPath(next.stage)}>{next.label} <Icon name="arrow" size={15} /></Link>}
    </div>
  </div>;
}

/** The result area of one launched run: real progression, outcome and next action, with technical detail collapsed. */
export function RunPanel({ slot, idle, next, extra }: { slot: Slot; idle?: string; next?: { label: string; stage: StageId }; extra?: ReactNode }) {
  const s = useSlot(slot);
  const v = s.view;
  const submitting = s.phase === "submitting";
  const ver = useVerify(slot);
  return <div className="m-run" aria-live="polite" aria-busy={submitting || s.phase === "running"}>
    {!v && s.phase === "idle" && <p className="m-muted">{s.message ?? idle ?? "No run yet."}</p>}
    {(v || submitting) && <>
      {v && <div className="run-card-head"><div><span>RUN · {slot.toUpperCase()} · {v.posture.toUpperCase()}</span><code>{v.run_id}</code></div><CopyButton text={v.run_id} label="Copy run id" /></div>}
      <RunProgress slot={slot} view={v} submitting={submitting} />
      {s.phase === "running" && <p className="m-working">Working. This updates from the Loan Desk's recorded state. <button type="button" className="button button--ghost" onClick={() => stopWaiting(slot)}>Stop waiting</button></p>}
      {s.phase === "stopped" && <p className="m-working">{s.message} <button type="button" className="button button--secondary" onClick={() => keepWaiting(slot)}>Keep waiting</button></p>}
      {s.message && s.phase !== "stopped" && s.phase !== "error" && <p className="m-muted" role="status">{s.message}</p>}
      {v && <OutcomeBanner view={v} slot={slot} next={next} />}
      {v && v.status !== "RUNNING" && v.evidence.indexed_status !== "SPLUNK_VERIFIED" && <div className="m-verify">
        <Button variant="secondary" disabled={ver.busy} onClick={() => verifyRun(slot)}>{ver.busy ? "Verifying…" : "Verify with Splunk"} <Icon name="search" size={15} /></Button>
        <span className="m-muted">{ver.text || "Asks the host verifier to compare this run's local events with what Splunk indexed. Only its signed receipt makes a run SPLUNK-VERIFIED."}</span></div>}
      {v && v.status !== "RUNNING" && <details className="m-details"><summary>Technical details: calls, timeline, queue, evidence</summary>
        <RunResult view={v} story={false} /><EvidenceCard view={v} /><RunDetails view={v} /></details>}
      {extra}
    </>}
    {s.phase === "error" && <Callout kind="warn" role="alert">{s.message} <Button variant="secondary" onClick={() => (v ? keepWaiting(slot) : retryLaunch(slot))}>{v ? "Retry now" : "Retry"}</Button></Callout>}
  </div>;
}
