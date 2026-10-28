import { SplunkLink } from "../config";
import { useEffect, useState } from "react";
import { Badge, Button, Icon } from "../ui";
import { StageGuide } from "../StageGuide";
import { Link, MASTERY_PATH, FOUNDATIONS_PATH } from "../router";
import { updateMission, useMission } from "../store";
import { Callout, CopyButton } from "../mission/parts";
import { StepList } from "../mission/RunProgress";
import { KIND, checkEvidence, compareHandoff, hopOf, launchMcp, loadManifest, loadRecord, mcpSteps, outcomeOf, type McpEvidence, type McpManifest, type McpRecord } from "../mcp/mcp";

type Mode = "attack" | "retest";

/** MCP Tool Authorization as one guided exercise, from the existing launch and evidence endpoints. */
export function Mcp() {
  const m = useMission();
  const st = m.mcp ?? {};
  const [man, setMan] = useState<McpManifest | null | undefined>(undefined);
  const [recs, setRecs] = useState<Partial<Record<Mode, McpRecord | null>>>({});
  const [evid, setEvid] = useState<Record<string, McpEvidence | null>>({});
  const [busy, setBusy] = useState<Mode | "">("");
  const [err, setErr] = useState("");
  const [cmp, setCmp] = useState<{ search_url: string; starter_spl: string } | null>(null);
  const save = (patch: Partial<NonNullable<typeof m.mcp>>) => updateMission((s) => ({ ...s, mcp: { ...s.mcp, ...patch } }));

  useEffect(() => { loadManifest().then(setMan); }, []);
  useEffect(() => { // records live in the Attack Service's memory: re-read them, never trust a stored copy
    (["attack", "retest"] as Mode[]).forEach((k) => { const id = st[k]; if (id && recs[k] === undefined) loadRecord(id).then((r) => setRecs((x) => ({ ...x, [k]: r }))); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [st.attack, st.retest]);
  const a = recs.attack ?? null, r = recs.retest ?? null;
  useEffect(() => { setCmp(null); if (a && r) compareHandoff(a.run_id, r.run_id).then(setCmp); }, [a?.run_id, r?.run_id]); // eslint-disable-line react-hooks/exhaustive-deps

  const launch = async (mode: Mode) => {
    setBusy(mode); setErr("");
    const res = await launchMcp(mode === "attack" ? "ATTACK" : "RETEST");
    setBusy("");
    if (res.error || !res.record) { setErr(res.error ?? "The launch failed."); return; }
    setRecs((x) => ({ ...x, [mode]: res.record })); save({ [mode]: res.record.run_id });
  };
  const check = async (rec: McpRecord) => { setEvid((e) => ({ ...e, [rec.run_id]: undefined as never })); const v = await checkEvidence(rec.run_id); setEvid((e) => ({ ...e, [rec.run_id]: v })); };

  const ap = man?.prediction?.ATTACK, rp = man?.prediction?.RETEST;
  const done = (a ? 1 : 0) + (r ? 1 : 0) + (st.locked ? 1 : 0);
  const ha = a && hopOf(a), hr = r && hopOf(r);
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">Guided exercise · {man?.control_id ?? "CTRL-MCP-001"}</div><h1>MCP Tool Authorization</h1>
      <p>{man?.security_question ?? "Does a tool request become a tool grant, or does CTRL-MCP-001 decide before the handler starts?"}</p>
    </div></header>
    <StageGuide learning="A tool request is not a tool grant: a control decides before the handler starts, and a decision is not proof of execution."
      todo={!st.locked ? "Predict the decision, then launch the attack." : !a ? "Launch the attack." : !r ? "Replay the same request on the defended profile." : "Compare the two runs and read their evidence."}
      happened={`${done} of 3 steps done${a ? ` · attack: ${KIND[outcomeOf(a).kind].label.toLowerCase()}` : ""}${r ? ` · retest: ${KIND[outcomeOf(r).kind].label.toLowerCase()}` : ""}.`}
      next={r ? "Check the evidence, then test yourself in Mastery." : "Work through the steps below in order."} />

    {man === null && <Callout kind="warn" role="alert">The lab description could not be loaded from the Attack Service. The exercise below still uses the live launch API.</Callout>}
    <section className="m-card" aria-labelledby="h-mcp-scn">
      <div className="panel-label">Scenario</div><h2 id="h-mcp-scn">What the attacker wants, and where the boundary is</h2>
      <div className="m-twocol">
        <div><h3>Attacker objective</h3><p>{ap?.attack_objective ?? "Send a tool request the agent was never granted and see whether it runs."}</p>{ap?.attacker_influence && <p className="m-muted">{ap.attacker_influence}</p>}</div>
        <div><h3>Authorization boundary</h3><p>{ap?.which_control ?? rp?.which_control ?? "CTRL-MCP-001 decides before the tool handler. Splunk observes; it never allows or denies."}</p>{ap?.security_property && <p className="m-muted">{ap.security_property}</p>}</div>
      </div>
      <ol className="m-flow" aria-label="Request flow">{["Agent request", "tools/call", "CTRL-MCP-001 decides", "Tool handler (only if allowed)", "Telemetry", "Splunk (observes)"].map((x) => <li key={x}>{x}</li>)}</ol>
    </section>

    <section className="m-card" aria-labelledby="h-mcp-pred">
      <div className="panel-label">Step 1 · Predict</div><h2 id="h-mcp-pred">What will CTRL-MCP-001 decide?</h2>
      <p>{ap?.predict_before_launch ?? "Before you launch, write down: will the control ALLOW or DENY the ungranted request?"}</p>
      <form className="m-prediction" onSubmit={(e) => { e.preventDefault(); if (st.prediction) save({ locked: true }); }}>
        <fieldset disabled={Boolean(st.locked)}><legend>The ungranted lookup_customer_tier request on the intentionally vulnerable ATTACK experiment will be…</legend>
          {["ALLOW", "DENY"].map((v) => <label className="m-choice" key={v}><input type="radio" name="mcp-pred" checked={st.prediction === v} onChange={() => save({ prediction: v })} /><span>{v}</span></label>)}</fieldset>
        {st.locked ? <div className="recorded"><Icon name="check" size={18} /><span><strong>Prediction locked: {st.prediction}</strong>Stored only in this browser. It cannot affect the run.</span></div>
          : <Button onClick={() => st.prediction && save({ locked: true })} disabled={!st.prediction}>Lock prediction</Button>}
      </form>
    </section>

    <section className="m-card" aria-labelledby="h-mcp-att">
      <div className="panel-label">Step 2 · Attack</div><h2 id="h-mcp-att">Launch the ungranted request</h2>
      <p>{ap?.what_will_change ?? "A new run is created and the control records its decision."} {ap?.what_will_not_change}</p>
      <div className="m-actions"><Button onClick={() => launch("attack")} disabled={!st.locked || busy !== ""}>{busy === "attack" ? "Launching…" : a ? "Launch ATTACK again" : "Launch ATTACK (vulnerable profile)"} <Icon name="play" size={15} /></Button>
        {!st.locked && <span className="m-muted">Lock your prediction first.</span>}</div>
      {a && <Run rec={a} ev={evid[a.run_id]} onCheck={() => check(a)} prediction={st.prediction} />}
    </section>

    <section className="m-card" aria-labelledby="h-mcp-ret">
      <div className="panel-label">Step 3 · Defend and retest</div><h2 id="h-mcp-ret">Replay the same request on the defended profile</h2>
      <p>{rp?.attack_objective ?? "The tool, scope and arguments stay identical; only the server-owned profile changes."} {rp?.what_will_not_change}</p>
      <div className="m-actions"><Button onClick={() => launch("retest")} disabled={!a || busy !== ""}>{busy === "retest" ? "Launching…" : r ? "Launch RETEST again" : "Launch RETEST (defended profile)"} <Icon name="play" size={15} /></Button>
        {!a && <span className="m-muted">Run the attack first.</span>}</div>
      {r && <Run rec={r} ev={evid[r.run_id]} onCheck={() => check(r)} />}
    </section>
    {err && <Callout kind="warn" role="alert">{err}</Callout>}

    {a && r && ha && hr && <section className="m-card" aria-labelledby="h-mcp-cmp">
      <div className="panel-label">Compare</div><h2 id="h-mcp-cmp">Same request, different configuration</h2>
      <div className="table-wrap"><table><caption className="m-caption">Baseline attack versus defended retest, from the two launch records</caption>
        <thead><tr><th scope="col">Fact</th><th scope="col">Attack ({a.profile})</th><th scope="col">Retest ({r.profile})</th></tr></thead>
        <tbody>{([["Tool requested", ha["tool.name"], hr["tool.name"]], ["CTRL-MCP-001 decision", ha["control.decision"], hr["control.decision"]], ["Reason", ha["control.reason"].split(":")[0], hr["control.reason"].split(":")[0]],
          ["Handler ran", String(ha["handler.invoked"]), String(hr["handler.invoked"])], ["mcp.started recorded", String(ha["mcp.started"]), String(hr["mcp.started"])], ["Outcome", KIND[outcomeOf(a).kind].label, KIND[outcomeOf(r).kind].label]] as string[][]).map(([k, x, y]) =>
          <tr key={k} className={x !== y ? "is-different" : ""}><th scope="row">{k}</th><td>{x}</td><td>{y}</td></tr>)}</tbody></table></div>
      {st.prediction && <p className="m-score" role="status">You predicted <strong>{st.prediction}</strong> for the attack; the control recorded <strong>{ha["control.decision"]}</strong>{st.prediction === ha["control.decision"] ? " (match)." : " (differs)."}</p>}
      <div className="learning-note"><Icon name="book" size={18} /><div><strong>What this shows, and what it does not</strong>
        <p>The same request produced a different decision because the server-owned configuration changed. A DENY is not automatically SAFE, an ALLOW is not proof the handler ran (read the handler row), and missing mcp.started alone is not proof of prevention. Splunk observes these events; it never allowed or denied anything.</p></div></div>
      <div className="m-actions">{cmp && <SplunkLink className="button button--secondary" href={cmp.search_url} target="_blank" rel="noopener">Open both runs in Splunk <Icon name="arrow" size={15} /></SplunkLink>}
        <Link className="button button--primary" to={MASTERY_PATH}>Test yourself in Mastery <Icon name="arrow" size={15} /></Link>
        <Link className="button button--ghost" to={FOUNDATIONS_PATH}>Review “Tools and MCP”</Link></div>
      {cmp && <details className="m-details"><summary>Starter SPL for both runs</summary><pre>{cmp.starter_spl}</pre><CopyButton text={cmp.starter_spl} label="Copy search" /></details>}
    </section>}
  </div>;
}

function Run({ rec, ev, onCheck, prediction }: { rec: McpRecord; ev: McpEvidence | null | undefined; onCheck: () => void; prediction?: string }) {
  const o = outcomeOf(rec), k = KIND[o.kind], h = hopOf(rec);
  return <div className="m-run m-mcp-run">
    <div className="run-card-head"><div><span>RUN · {rec.mode} · {rec.profile.toUpperCase()}</span><code>{rec.run_id}</code></div><CopyButton text={rec.run_id} label="Copy run id" /></div>
    <StepList steps={mcpSteps(rec, ev === null ? { evidence_state: "ERROR", splunk_ok: false, probe_error: "evidence endpoint unavailable" } : ev)} label={`Progress of the ${rec.mode} run, from the launch record`} finished />
    <div className={`m-outcome m-outcome--${k.tone}`} role="status">
      <div className="m-outcome__head"><Icon name={o.kind === "BLOCKED" ? "shield" : o.kind === "ATTACK_SUCCEEDED" ? "target" : "status"} size={20} /><strong>{k.label}</strong></div>
      <p>{o.head}</p>
      {prediction && h && rec.mode === "ATTACK" && <p className="m-muted">You predicted {prediction}; the control recorded {h["control.decision"]}.</p>}
    </div>
    <div className="m-verify"><Button variant="secondary" onClick={onCheck}>Check Splunk for this run <Icon name="search" size={15} /></Button>
      <SplunkLink className="button button--ghost" href={rec.search_handoff.search_url} target="_blank" rel="noopener">Open in Splunk <Icon name="arrow" size={15} /></SplunkLink>
      <span className="m-muted">This asks Splunk whether events for this run.id exist. It never makes the run SPLUNK-VERIFIED.</span></div>
    <details className="m-details"><summary>Technical details: the recorded hop, lifecycle and flags</summary>
      <div className="table-wrap"><table><caption className="m-caption">Authorization hop</caption><tbody>{h ? Object.entries(h).map(([k2, v]) => <tr key={k2}><th scope="row">{k2}</th><td>{String(v)}</td></tr>) : <tr><td>No hop recorded.</td></tr>}</tbody></table></div>
      <p className="m-muted">Lifecycle: {rec.lifecycle.join(" → ")} · local events {rec.local_event_count} · hec.ok {String(rec["hec.ok"])} · otlp.ok {String(rec["otlp.ok"])} · terminal {rec.runtime.terminal}</p>
      {rec.note && <p className="m-muted">{rec.note}</p>}
    </details>
  </div>;
}
