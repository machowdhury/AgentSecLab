import { useCallback, useEffect, useState } from "react";
import { Button } from "../ui";
import { Link, comparePath, findingPath } from "../router";
import { api } from "../api";
import { updateMission, useMission } from "../store";
import { AssuranceInvestigate } from "./Investigate";
import { REASONS } from "./live";

export interface RunFinding { finding_id: string; title: string; status: string; status_label: string; by_design: boolean; hop: number | null; control_id: string; mode: string; retest: string }
export type RunFindings = { loading: true } | { loading: false; state: "ok"; found: boolean; findings: RunFinding[]; run?: { complete: boolean; terminal: boolean; events: number } } | { loading: false; state: "unavailable"; reason: string } | { loading: false; state: "error"; status: number };

/** The assurance findings the rules produced for one of the learner's LIVE runs. `refresh` asks again (telemetry reaches Splunk a little after the run). */
export function useRunFindings(runId: string | undefined): { res: RunFindings; refresh: () => void } {
  const [res, setRes] = useState<RunFindings>({ loading: true });
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!runId) return;
    let live = true;
    setRes({ loading: true });
    api(`/api/assurance/runs/${runId}/findings`).then((r) => {
      if (!live) return;
      if (!r.ok) setRes({ loading: false, state: "error", status: r.status });
      else if (r.data.state === "unavailable") setRes({ loading: false, state: "unavailable", reason: r.data.reason });
      else setRes({ loading: false, state: "ok", found: Boolean(r.data.found), findings: r.data.findings ?? [], run: r.data.run });
    });
    return () => { live = false; };
  }, [runId, n]);
  return { res, refresh: useCallback(() => setN((x) => x + 1), []) };
}

export interface NotebookRun { slot: string; id: string; label?: string }

/** The Investigate stage of a LIVE workshop: the same notebook cells the Security Assurance finding opens, bound to the learner's own run. */
export function SplCellNotebook({ lab, runs }: { lab: string; runs: NotebookRun[] }) {
  const have = runs.filter((r) => r.id);
  const [slot, setSlot] = useState<string>(have.find((r) => /^attack/i.test(r.slot))?.slot ?? have[0]?.slot ?? "attack");
  const run = have.find((r) => r.slot === slot) ?? have[0];
  const { res, refresh } = useRunFindings(run?.id);
  const [pick, setPick] = useState(0);
  useEffect(() => { setPick(0); }, [run?.id]);
  const mark = useCallback(() => updateMission((s) => (s.workbench?.[lab]?.investigated ? s : { ...s, workbench: { ...s.workbench, [lab]: { ...s.workbench?.[lab], investigated: true } } })), [lab]);
  if (!run) return <p className="m-muted">Run the attack first. The notebook is bound to your own run, so it has nothing to read yet.</p>;
  return <div className="as-runnb">
    {have.length > 1 && <div role="radiogroup" aria-label="Which of your runs to investigate" className="as-chips">{have.map((r) => <button key={r.slot} type="button" role="radio" aria-checked={slot === r.slot} className={`as-chip ${slot === r.slot ? "is-on" : ""}`} onClick={() => setSlot(r.slot)}>{r.label ?? `${r.slot.toUpperCase()} run`}</button>)}</div>}
    <div role="status" aria-live="polite">
      {res.loading && <p className="m-muted">Looking for this run's findings…</p>}
      {!res.loading && res.state === "unavailable" && <div className="as-state as-state--na"><p>{REASONS[res.reason] ?? "Splunk could not be read."} Nothing was searched, so there is nothing to investigate yet. Your run and its local record are unaffected.</p><Button variant="secondary" onClick={refresh}>Check again</Button></div>}
      {!res.loading && res.state === "error" && <div className="as-state as-state--bad"><p>The findings of this run could not be loaded (HTTP {res.status || "no answer"}). Nothing is shown rather than a guess.</p><Button variant="secondary" onClick={refresh}>Try again</Button></div>}
      {!res.loading && res.state === "ok" && !res.found && <div className="as-state"><p>Splunk holds no scored event for this run yet. Telemetry usually arrives within a minute. That is not a pass and not a failure: nothing has been judged.</p><Button variant="secondary" onClick={refresh}>Check again</Button></div>}
    </div>
    {!res.loading && res.state === "ok" && res.found && res.findings.length === 0 && <div className="as-state"><p>The run is in Splunk but the rules produced no finding for it.</p></div>}
    {!res.loading && res.state === "ok" && res.found && res.findings.length > 0 && <>
      {res.run && !res.run.complete && <p className="as-gapnote" role="note">This run's events are incomplete so far ({res.run.events} found). The rules will report insufficient evidence until the missing events arrive.</p>}
      {res.findings.length > 1 && <div className="m-field"><label htmlFor={`${lab}-nbf`}>This run has {res.findings.length} findings. Which one do you want to read?</label>
        <select id={`${lab}-nbf`} value={pick} onChange={(e) => setPick(Number(e.target.value))}>{res.findings.map((f, i) => <option key={f.finding_id} value={i}>{f.title} · {f.hop !== null ? `hop ${f.hop} · ` : ""}{f.status_label}</option>)}</select></div>}
      <AssuranceInvestigate tab="live" id={res.findings[Math.min(pick, res.findings.length - 1)].finding_id} embedded onRan={mark} />
    </>}
  </div>;
}

/** Links from a workshop stage to the finding of the learner's run and, once a retest exists, to the comparison. */
export function RunFindingLinks({ runId, withCompare }: { runId: string | undefined; withCompare: boolean }) {
  const { res } = useRunFindings(runId);
  if (!runId || res.loading || res.state !== "ok" || !res.found || !res.findings.length) return null;
  const f = res.findings[0];
  return <p className="m-muted">The assurance rules judged this run: <strong>{f.status_label}</strong>. <Link to={findingPath("live", f.finding_id)}>Open the finding</Link>{withCompare && <> · <Link to={comparePath("live", f.finding_id)}>Compare the attack with its retest</Link></>}.</p>;
}

/** The Explain-evidence stage: what the rules concluded about the learner's own runs, the learner's notebook conclusions, and the learner's own words. */
export function ExplainEvidence({ lab, runs, completion }: { lab: string; runs: NotebookRun[]; completion: string[] }) {
  const m = useMission();
  const attack = runs.find((r) => r.slot === "attack");
  const { res } = useRunFindings(attack?.id);
  const text = m.workbench?.[lab]?.explain ?? "";
  const save = (v: string) => updateMission((s) => ({ ...s, workbench: { ...s.workbench, [lab]: { ...s.workbench?.[lab], explain: v } } }));
  const found = !res.loading && res.state === "ok" && res.found ? res.findings : [];
  const concl = found.flatMap((f) => Object.entries(m.investigations?.[f.finding_id] ?? {}).filter(([, v]) => v.conclusion).map(([k, v]) => ({ key: `${f.finding_id}-${k}`, text: v.conclusion! })));
  return <div className="as-explain">
    {!attack ? <p className="m-muted">Run the attack and the retest first. This stage explains the evidence your own runs produced.</p>
      : <>
        <h4>What the assurance rules concluded about your attack run</h4>
        {res.loading ? <p className="m-muted">Reading the findings…</p>
          : res.state !== "ok" ? <p className="m-muted">Splunk could not be read, so the rules have nothing to report yet. Nothing here is a pass.</p>
            : !res.found ? <p className="m-muted">Splunk holds no scored event for your attack run yet, so the rules have judged nothing.</p>
              : <ul className="m-rules">{res.findings.map((f) => <li key={f.finding_id}><strong>{f.title}</strong>{f.hop !== null ? ` (hop ${f.hop})` : ""}: {f.status_label}. Retest: {f.retest === "VALIDATED" ? "validated by a linked, verified-effective retest" : f.retest === "NOT_VALIDATED" ? "a retest exists but is not verified effective" : f.retest === "NO_RETEST" ? "no retest yet" : "not applicable"}. <Link to={findingPath("live", f.finding_id)}>Open the finding</Link></li>)}</ul>}
        {concl.length > 0 && <><h4>Your own conclusions from the notebook</h4><ul className="m-rules">{concl.map((c) => <li key={c.key}>{c.text}</li>)}</ul></>}
      </>}
    {completion.length > 0 && <details className="m-details"><summary>You are done when</summary><ol>{completion.map((t) => <li key={t}>{t}</li>)}</ol></details>}
    <div className="m-field"><label htmlFor={`${lab}-explain`}>In your own words: what does the evidence show, and what does it not show? (saved in this browser; it is not evidence)</label>
      <textarea id={`${lab}-explain`} rows={4} maxLength={1200} value={text} onChange={(e) => save(e.target.value)} /></div>
  </div>;
}
