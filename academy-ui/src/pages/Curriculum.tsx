import { useState } from "react";
import { Badge, Icon } from "../ui";
import { StageGuide } from "../StageGuide";
import { FOUNDATIONS_PATH, Link, labPath, MCP_PATH, missionPath } from "../router";
import { useMission } from "../store";
import { AVAIL, AVAIL_ORDER, CURRICULUM, REGISTRY_NOTE, labsOf, type Availability, type Lab } from "../curriculum";

export const availTone = (a: Availability) => ({ guided: "live", workbench: "observed", replay: "replay", content_only: "muted" } as const)[a];

/** All 12 domains and their registered labs. Beginners follow the start-here path; experienced users search, filter or jump straight to a lab. */
export function Curriculum() {
  const m = useMission();
  const route = [
    { to: FOUNDATIONS_PATH, title: "AI & Agent Foundations", sub: "Four short lessons. No background needed.", done: (m.foundationsRead?.length ?? 0) >= 4, go: "Start with the basics" },
    { to: missionPath(), title: "Loan Desk mission", sub: "A live agent, a real attack, and the evidence.", done: m.completed, go: "Start the Loan Desk mission" },
    { to: MCP_PATH, title: "MCP Tool Authorization", sub: "Why a tool request is not a tool grant.", done: Boolean(m.mcp?.retest), go: "Try MCP Tool Authorization" },
  ];
  const next = route.find((r) => !r.done);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Availability | "all">("all");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const needle = q.trim().toLowerCase();
  const narrowed = Boolean(needle) || filter !== "all";
  const match = (l: Lab) => (filter === "all" || l.availability === filter) && (!needle || `${l.id} ${l.title}`.toLowerCase().includes(needle));
  const total = (a: Availability) => CURRICULUM.labs.filter((l) => l.availability === a).length;
  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allOpen = open.size === CURRICULUM.domains.length;
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">Curriculum Explorer</div><h1>12 domains, {CURRICULUM.labs.length} registered labs</h1>
      <p>Every lab follows the same shape: learn it, practice it, prove it. Each label below says what the registry records for the lab. {REGISTRY_NOTE}</p>
    </div></header>
    <section className="m-start" aria-labelledby="h-start">
      <div><div className="eyebrow">New here? Start here</div><h2 id="h-start">{next ? "Your first route through the curriculum" : "You have finished the first route"}</h2>
        <p>You do not need a security or AI background. These three steps take you from the basics to a live attack and its evidence. The twelve domains below are for when you want to go further or jump straight to a topic.</p>
        {next && <Link className="button button--primary m-start__cta" to={next.to}>{next.go} <Icon name="arrow" size={16} /></Link>}</div>
      <ol className="m-start__steps">{route.map((r, i) => <li key={r.to} className={r.done ? "is-done" : r === next ? "is-next" : ""}>
        <span className="m-start__n" aria-hidden="true">{r.done ? <Icon name="check" size={16} /> : i + 1}</span>
        <div><Link to={r.to}>{r.title}</Link><small>{r.sub}</small><span className="visually-hidden">{r.done ? " (done)" : r === next ? " (up next)" : ""}</span></div></li>)}</ol>
    </section>
    <StageGuide learning="How agentic AI security is organised: twelve domains, each with registered labs."
      todo="Start with the path below, or search and filter to go straight to a lab."
      happened={`${CURRICULUM.labs.length} labs registered: ${AVAIL_ORDER.map((a) => `${total(a)} ${AVAIL[a].label.toLowerCase()}`).join(", ")}.`}
      next="Open a lab, then work through Learn, Practice and Prove." />
    <section className="m-curfilter" aria-label="Find a lab">
      <div className="m-field"><label htmlFor="cur-search">Search by lab name or id</label><input id="cur-search" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="for example MCP, memory, LAB-PI-001" autoComplete="off" /></div>
      <div role="group" aria-label="Filter by availability" className="m-chipbar">
        {(["all", ...AVAIL_ORDER] as const).map((a) => <button type="button" key={a} className={`m-chip ${filter === a ? "is-current" : ""}`} aria-pressed={filter === a} onClick={() => setFilter(a)}>{a === "all" ? "All" : `${AVAIL[a].label} (${total(a)})`}</button>)}
      </div>
      {!narrowed && <button type="button" className="button button--ghost" onClick={() => setOpen(allOpen ? new Set() : new Set(CURRICULUM.domains.map((d) => d.id)))}>{allOpen ? "Collapse all domains" : "Expand all domains"}</button>}
    </section>
    <p className="m-muted" role="status">{narrowed ? `${CURRICULUM.labs.filter(match).length} lab(s) match.` : "Select a domain to see its labs."}</p>
    {CURRICULUM.domains.map((d) => {
      const labs = labsOf(d.id).filter(match);
      const all = labsOf(d.id);
      if (narrowed && !labs.length) return null;
      const isOpen = narrowed || open.has(d.id);
      return <section className="m-domain" key={d.id} aria-labelledby={`dom-${d.id}`}>
        <h2 id={`dom-${d.id}`}><button type="button" aria-expanded={isOpen} onClick={() => !narrowed && toggle(d.id)}>
          <span className="m-domain__id">{d.id.replace("D", "")}</span><span className="m-domain__name">{d.name}</span>
          <span className="m-domain__count">{all.length ? `${all.length} lab${all.length === 1 ? "" : "s"}` : "no registered lab"}</span><Icon name="chevron" size={16} /></button></h2>
        {isOpen && <div className="m-domain__body">
          {!all.length && <p className="m-muted">No lab is registered for this domain in <code>learning/academy/lab_registry_data.json</code>. The native lessons are the learning content here.</p>}
          {d.id === "D01" && <p><Link to={FOUNDATIONS_PATH}>AI &amp; Agent Foundations lessons <Icon name="arrow" size={14} /></Link></p>}
          <ul className="m-lablist">{labs.map((l) => <li key={l.id}>
            <Link to={labPath(l.id)}><strong>{l.title}</strong><code>{l.id}</code></Link>
            <span className="m-chips"><Badge tone={availTone(l.availability)}>{AVAIL[l.availability].label.toUpperCase()}</Badge>{l.level && <Badge tone="neutral">{l.level}</Badge>}{l.secondary_domain && <Badge tone="muted">ALSO {l.secondary_domain.replace("D", "")}</Badge>}</span>
          </li>)}</ul>
        </div>}
      </section>;
    })}
    <p className="m-muted">Source: <code>learning/academy/taxonomy.json</code> (domains), <code>lab_registry_data.json</code> (labs, tiers, domains), <code>curriculum.json</code> (levels). Inventory date {CURRICULUM.inventory_date}. Domain names follow the original curriculum; the taxonomy file titles differ slightly for D10 and D12 and are kept in the export.</p>
  </div>;
}
