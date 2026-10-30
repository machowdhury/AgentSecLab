import { useState } from "react";
import { Badge, Icon, LinkButton } from "../ui";
import { Link, ASSURANCE_STUDY_PATH, CURRICULUM_PATH, assuranceTabPath, findingPath, type AssuranceTab } from "../router";
import { REASONS, TAB_LABEL, WINDOWS, overviewUrl, readWindow, saveWindow, useLoad, type Card, type Overview, type Tile, type WindowKey } from "./live";
import { Banner, ClassBadge, ClassTabs, ProvenanceBar, StatusPill } from "./liveParts";

function TileView({ t }: { t: Tile }) {
  const none = t.of === 0;
  return <div className="as-tile" role="group" aria-label={`${t.label}: ${none ? "no operations to judge" : `${t.n} of ${t.of}`}`}>
    <div className="as-tile__l">{t.label}</div>
    <div className="as-tile__n">{none ? <span className="as-tile__none">No operations yet</span> : <>{t.n} <small>of {t.of}</small></>}</div>
    <p className="as-tile__d">{t.definition}</p>
    {t.id === "did_not_hold" && <p className="as-tile__d">{t.by_design ? `${t.by_design} more executed in the intentionally vulnerable profile (by design, counted separately). ` : ""}Out of: {t.of_definition}.</p>}
    {t.id === "retests" && !none && <p className="as-tile__d">{t.not_validated ?? 0} retested but not validated · {t.no_retest ?? 0} with no retest yet</p>}
  </div>;
}

function AttentionItem({ c, tab, primary }: { c: Card; tab: AssuranceTab; primary: boolean }) {
  return <li className="as-attn"><StatusPill status={c.status} byDesign={c.by_design && c.status === "VERIFIED_INEFFECTIVE"} label={c.status === "VERIFIED_INEFFECTIVE" ? "Did not hold" : c.status === "INSUFFICIENT_EVIDENCE" ? "Evidence gap" : tab === "recorded" ? "No retest recorded" : "Needs a retest"} />
    <div className="as-attn__main"><h3>{c.title}</h3><p>{c.context} · {c.mode} · {c.profile}</p></div>
    <LinkButton href={findingPath(tab, c.finding_id)} variant={primary ? "primary" : "secondary"} icon={primary ? "arrow" : undefined} internal>{tab === "live" ? (primary ? "Investigate" : "Open") : "Explore"}<span className="visually-hidden">: {c.title}</span></LinkButton></li>;
}

function Disclosures({ o }: { o: Overview }) {
  const d = o.disclosure!;
  const statusLabel = (s: string) => ({ VERIFIED_EFFECTIVE: "Verified effective", VERIFIED_INEFFECTIVE: "Verified ineffective", FINDING_OBSERVED: "Finding observed", INSUFFICIENT_EVIDENCE: "Insufficient evidence" } as Record<string, string>)[s] ?? s;
  return <div className="as-disc">
    <details><summary><span>Control effectiveness</span><small>{d.controls.tested} of {d.controls.of} controls have evidence</small></summary>
      <div className="as-controls">{d.controls.items.map((c) => {
        const tot = c.findings;
        return <div key={c.id} className="as-control"><h4>{c.id}</h4><p>{c.name}</p>
          {c.tested ? <><div className="as-stack" role="img" aria-label={`${c.name}: ${["VERIFIED_EFFECTIVE", "VERIFIED_INEFFECTIVE", "FINDING_OBSERVED", "INSUFFICIENT_EVIDENCE"].map((s) => `${c.counts[s] ?? 0} ${statusLabel(s).toLowerCase()}`).join(", ")}`}>
            {["VERIFIED_EFFECTIVE", "VERIFIED_INEFFECTIVE", "FINDING_OBSERVED", "INSUFFICIENT_EVIDENCE"].map((s) => (c.counts[s] ?? 0) > 0 && <i key={s} className={`as-seg as-seg--${STATUS_SEG[s]}`} style={{ width: `${((c.counts[s] ?? 0) / tot) * 100}%` }} />)}</div>
            <p className="as-control__n">{tot} finding{tot === 1 ? "" : "s"}</p></> : <p className="as-control__n"><Badge tone="muted">NOT TESTED</Badge> no attack or retest has exercised it</p>}</div>;
      })}</div></details>
    <details><summary><span>Evidence gaps</span><small>{d.gaps.n} operation{d.gaps.n === 1 ? "" : "s"}</small></summary>
      {d.gaps.n === 0 ? <p className="as-empty">No evidence gaps in this view.</p> : <ul className="as-list">{d.gaps.items.map((c) => <li key={c.finding_id}><Link to={findingPath(o.tab, c.finding_id)}>{c.title}</Link> <span>{c.context}</span></li>)}</ul>}</details>
    <details><summary><span>Not tested yet</span><small>{d.not_tested.n} of {d.not_tested.of} controls</small></summary>
      {d.not_tested.n === 0 ? <p className="as-empty">Every control has been exercised by an attack or a retest.</p> : <p>No attack or retest has exercised: {d.not_tested.ids.join(", ")}. Run ATTACK then RETEST in the workshops that use them (<Link to={CURRICULUM_PATH}>Curriculum Explorer</Link>).</p>}</details>
    <details><summary><span>All findings by status</span><small>{d.by_status.total} operation{d.by_status.total === 1 ? "" : "s"}</small></summary>
      <table className="as-table"><caption className="visually-hidden">Findings by status in this view</caption><thead><tr><th scope="col">Status</th><th scope="col">Findings</th></tr></thead>
        <tbody>{d.by_status.items.map((s) => <tr key={s.label}><th scope="row">{s.label}</th><td>{s.n}</td></tr>)}</tbody></table></details>
    <details><summary><span>How these numbers are computed</span><small>rules, grain, denominators</small></summary><ul className="as-list as-list--plain">{d.how.map((h) => <li key={h}>{h}</li>)}</ul></details>
  </div>;
}
const STATUS_SEG: Record<string, string> = { VERIFIED_EFFECTIVE: "eff", VERIFIED_INEFFECTIVE: "ineff", FINDING_OBSERVED: "obs", INSUFFICIENT_EVIDENCE: "ins" };

export function AssuranceOverview({ tab }: { tab: AssuranceTab }) {
  const [win, setWin] = useState<WindowKey>(readWindow);
  const res = useLoad<Overview>(overviewUrl(tab, tab === "recorded" ? "all" : win));
  const data = !res.loading && "data" in res ? res.data : null;
  const fixturesDenied = !res.loading && "error" in res && res.status === 403;
  const heading = data?.state === "ok" ? data.headline!.text : data?.state === "empty" ? `No ${tab === "live" ? "live runs" : "runs"} in this window` : data?.state === "unavailable" ? "Live assurance is unavailable" : res.loading ? "Loading assurance…" : fixturesDenied ? "The operator role is needed" : "This view could not be loaded";
  return <div className="page as">
    <header className="page-header"><div><div className="eyebrow">Security Assurance</div><h1>{heading}</h1></div><Link to={ASSURANCE_STUDY_PATH} className="as-study">Study journey <Icon name="chevron" size={14} /></Link></header>
    <ClassTabs tab={tab} />
    {tab !== "recorded" && <div className="as-bar"><ClassBadge cls={tab === "live" ? "LIVE" : "TEST_FIXTURE"} />
      <div role="radiogroup" aria-label="Time window" className="as-chips">{WINDOWS.map(([k, l]) => <button key={k} type="button" role="radio" aria-checked={win === k} className={`as-chip ${win === k ? "is-on" : ""}`} onClick={() => { setWin(k); saveWindow(k); }}>{l}</button>)}</div></div>}
    {tab === "recorded" && <div className="as-bar"><ClassBadge cls="RECORDED" /></div>}
    <Banner tab={tab} />
    {data && <ProvenanceBar p={data.provenance} tabLabel={TAB_LABEL[tab]} windowLabel={data.window.label} />}
    <div role="status" aria-live="polite">
      {res.loading && <p className="as-empty">Reading the evidence…</p>}
      {fixturesDenied && <div className="as-state"><p>The test-fixture view is for the operator role. Sign in as the operator to see it.</p></div>}
      {!res.loading && "error" in res && !fixturesDenied && <div className="as-state as-state--bad"><p>The assurance view could not be loaded ({res.error}). Nothing is shown rather than a guess. Reload, or check that the Attack Service is running.</p></div>}
      {data?.state === "unavailable" && <div className="as-state as-state--na"><h2>Nothing was read</h2><p>{REASONS[data.reason ?? ""] ?? "Splunk could not be read, so there are no numbers."}</p>
        <p>The <Link to={assuranceTabPath("recorded")}>recorded examples</Link> do not need Splunk, and are never your current posture.</p></div>}
      {data?.state === "empty" && <div className="as-state"><h2>No runs to judge</h2><p>{tab === "live" ? "Splunk holds no live run for this window. Launch an attack in a LIVE workshop, then come back; telemetry arrives within a minute." : "No runs in this view."} An empty view is not a pass: no control was exercised.</p>
        {tab === "live" && <LinkButton href={CURRICULUM_PATH} variant="secondary" internal>Choose a workshop</LinkButton>}</div>}
    </div>
    {data?.state === "ok" && <>
      <section aria-labelledby="as-attn-h" className="as-hero"><h2 id="as-attn-h" className="visually-hidden">{tab === "recorded" ? "Findings to explore" : "Needs attention"}</h2>
        {data.attention!.length ? <ul>{data.attention!.map((c, i) => <AttentionItem key={c.finding_id} c={c} tab={tab} primary={i === 0} />)}</ul>
          : <p className="as-empty">{tab === "recorded" ? "No findings to explore here." : "No did-not-hold findings, evidence gaps or unvalidated attacks in this view."} That is what the evidence in this window shows; it does not extend to anything not exercised.</p>}
        {data.headline!.attention > data.attention!.length && <details className="as-more"><summary>All {data.headline!.attention} items</summary><ul>{data.attention_all!.slice(3).map((c) => <AttentionItem key={c.finding_id} c={c} tab={tab} primary={false} />)}</ul></details>}
      </section>
      <section aria-label="Key numbers" className="as-tiles">{data.tiles!.map((t) => <TileView key={t.id} t={t} />)}</section>
      <Disclosures o={data} />
    </>}
  </div>;
}
