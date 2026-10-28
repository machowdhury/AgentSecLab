import { Icon } from "../ui";
import { useConfig } from "../config";
import { useMission } from "../store";
import { Link, missionPath } from "../router";
import { ALL_CELLS } from "./notebooks";
import { evidenceText, splunkSearchUrl } from "./content";
import { CopyButton } from "./parts";
import { useSlot, useVerify } from "./runStore";

/** The learner's own investigation: real run ids, the searches they ran, what Splunk returned, their notes, and each run's verification state. Nothing here is generated. */
export function InvestigationRecord() {
  const { config } = useConfig();
  const m = useMission();
  const a = useSlot("attack").view, r = useSlot("retest").view;
  const va = useVerify("attack"), vr = useVerify("retest");
  const ran = ALL_CELLS.map((c) => ({ c, e: m.notebook?.[c.id] })).filter((x) => x.e?.ran);
  const runs = [
    { label: "Baseline attack run", id: a?.run_id ?? m.runs.attack, view: a, ver: va, stage: "attack" as const },
    { label: "Defended retest run", id: r?.run_id ?? m.runs.retest, view: r, ver: vr, stage: "retest" as const },
  ];
  return <section className="m-section m-record" aria-labelledby="h-record">
    <div className="lesson-label">Your investigation</div>
    <h2 id="h-record">What you found, from your own runs</h2>
    <div className="m-record__runs">
      {runs.map((x) => <div className="m-record__run" key={x.label}>
        <strong>{x.label}</strong>
        {x.id ? <><code>{x.id}</code>
          <span>{x.view ? `LOCAL evidence: ${x.view.evidence.event_count} events emitted by AcmeBank. ${x.ver.text || evidenceText(x.view)}` : "Run details are not available right now. Reopen the stage to reload them."}</span>
          <Link to={missionPath(x.stage === "attack" ? "investigate" : "retest")}>Back to this run's evidence <Icon name="arrow" size={14} /></Link></>
          : <span>Not run yet.</span>}
      </div>)}
    </div>
    <p className="m-muted">Indexed event counts you saw are your own observations. A run is SPLUNK-VERIFIED only when the host verifier says so; the status above is what it reported.</p>
    {!ran.length ? <p className="m-empty">You have not run any Splunk search in the notebook yet. Open Investigate or Retest and run a search; it will be recorded here.</p>
      : <ol className="m-record__list">{ran.map(({ c, e }) => { const x = e!.ran!; return <li key={c.id}>
        <h3>{c.title} <span className="m-record__stage">{c.stage === "retest" ? "Retest" : "Investigate"}</span></h3>
        <p className="m-muted">Run{x.runs.length > 1 ? "s" : ""} {x.runs.map((id) => <code key={id}>{id}</code>)} · {new Date(x.at).toLocaleString()} · {x.rows} row{x.rows === 1 ? "" : "s"} returned{x.truncated ? " (capped)" : ""}</p>
        {x.preview.length > 0 && <pre className="m-record__rows" aria-label="First rows returned by Splunk">{x.preview.join("\n")}</pre>}
        {x.changed.length > 0 && <p><strong>Rows that differed:</strong> {x.changed.length} (see the Retest stage for the full table)</p>}
        {e!.note ? <blockquote className="m-quote">Your note: {e!.note}</blockquote> : <p className="m-muted">You did not add a note for this search.</p>}
        <details><summary>The exact SPL that ran</summary><pre>{x.spl}</pre><div className="m-actions"><CopyButton text={x.spl} label="Copy search" />{config.urls.splunk_web && <a className="button button--secondary" href={splunkSearchUrl(config.urls.splunk_web, x.spl)} target="_blank" rel="noopener">Open in Splunk <Icon name="arrow" size={15} /></a>}</div></details>
      </li>; })}</ol>}
  </section>;
}
