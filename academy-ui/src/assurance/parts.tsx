import type { ReactNode } from "react";
import { Badge } from "../ui";
import { Link } from "../router";
import type { EvidenceClass, Mapping, Observation, Source, Status } from "./types";

const classTone = { LIVE: "live", RECORDED: "replay", SIMULATED: "simulated", DOCUMENTED: "muted" } as const;
const classMeaning: Record<EvidenceClass, string> = {
  LIVE: "Produced by a run made for this purpose, observed as it happened.",
  RECORDED: "Read from a committed record of an earlier run. Nothing is re-run.",
  SIMULATED: "Produced by a labelled simulation, never by a real system.",
  DOCUMENTED: "Written down in a committed document. Nothing was measured by this page.",
};
export { classMeaning };
export const EvidenceBadge = ({ cls }: { cls: EvidenceClass }) => <Badge tone={classTone[cls]}>{cls}</Badge>;
export const VerificationBadge = ({ status }: { status: "NOT_VERIFIED" | "VERIFIED" }) => <Badge tone={status === "VERIFIED" ? "allow" : "unverified"}>{status}</Badge>;
const statusTone: Record<Status, "allow" | "observed" | "deny" | "muted"> = { SUPPORTED: "allow", PARTLY_SUPPORTED: "observed", NOT_SUPPORTED: "deny", NOT_ASSESSED: "muted" };
export const StatusBadge = ({ status }: { status: Status }) => <Badge tone={statusTone[status]}>{status.replace("_", " ")}</Badge>;

/** Where a fact comes from: the file, its SHA-256 and the part of it that was read. */
export function ProvenanceDisclosure({ sources }: { sources: Source[] }) {
  return <details className="m-details"><summary>Where this comes from</summary>
    <dl className="rec-fields">{sources.map((s) => <div key={s.file + s.locator}><dt><code>{s.file}</code></dt><dd>{s.locator}. SHA-256 <code>{s.sha256}</code></dd></div>)}</dl></details>;
}

export const LimitationsList = ({ items, title = "Limitations", level = 4 }: { items: string[]; title?: string; level?: 3 | 4 }) => {
  const H = `h${level}` as "h3" | "h4";
  return <div className="wk-limits"><H>{title}</H><ul className="m-rules">{items.map((x) => <li key={x}>{x}</li>)}</ul></div>;
};

export const ObservationCard = ({ o, children, showKind = false }: { o: Observation; children?: ReactNode; showKind?: boolean }) =>
  <article className="wk-card" aria-labelledby={`obs-${o.id}`}>
    <header><h3 id={`obs-${o.id}`}>{o.title}</h3><div className="wk-badges"><EvidenceBadge cls={o.evidence_class} /><VerificationBadge status={o.verification.status} />{showKind && <Badge tone="neutral">{o.kind.replace("_", " ")}</Badge>}</div></header>
    <p>{o.statement}</p>
    <ProvenanceDisclosure sources={o.sources} />
    <LimitationsList items={o.limitations} />
    {children}
  </article>;

/** Framework relationships exactly as the framework reference file records them. A relationship is never a compliance claim. */
export function MappingTable({ items }: { items: Mapping[] }) {
  return <div className="table-wrap" tabIndex={0} role="region" aria-label="Framework relationships; scrolls sideways on a narrow screen"><table className="m-stack">
    <caption className="m-caption">Educational relationships from learning/academy/framework_refs.json. None is a compliance assertion.</caption>
    <thead><tr><th scope="col">Framework</th><th scope="col">Identifier</th><th scope="col">Title</th><th scope="col">Relationship</th><th scope="col">Reference status</th><th scope="col">Why it is related, and the limits</th></tr></thead>
    <tbody>{items.map((m) => <tr key={m.framework + m.id}><th scope="row">{m.framework}</th><td data-label="Identifier"><code>{m.id}</code></td><td data-label="Title">{m.name}</td>
      <td data-label="Relationship"><Badge tone="observed">{m.relationship}</Badge></td><td data-label="Reference status">{m.verification_status.replace(/_/g, " ")}</td>
      <td data-label="Why it is related">{m.rationale}<details className="m-details"><summary>Source and limits</summary><p>{m.version_or_date}. <a href={m.source_url} rel="noopener">source</a></p><p>{m.limits || "No limit recorded beyond: a relationship is not a certified mapping."}</p></details></td></tr>)}</tbody></table></div>;
}

export function NotImplemented({ title, needs }: { title: string; needs: string }) {
  return <article className="wk-card wk-card--idle"><header><h3>{title}</h3><Badge tone="muted">NOT IMPLEMENTED</Badge></header><p>{needs}</p><p className="m-muted">No page, figure or score exists for this yet.</p></article>;
}

export function StepBar({ steps, current, base, done }: { steps: { id: string; title: string }[]; current: string; base: string; done: (id: string) => boolean }) {
  return <nav aria-label="Workshop steps" className="wk-steps"><ol>{steps.map((s, i) => {
    const cur = s.id === current, d = done(s.id);
    return <li key={s.id} className={`${cur ? "is-current" : ""} ${d ? "is-done" : ""}`}><Link to={`${base}/${s.id}`} aria-current={cur ? "step" : undefined}><span className="wk-n" aria-hidden="true">{d ? "✓" : i + 1}</span><span>{s.title}<small>{cur ? "current step" : d ? "complete" : "not complete"}</small></span></Link></li>;
  })}</ol></nav>;
}
