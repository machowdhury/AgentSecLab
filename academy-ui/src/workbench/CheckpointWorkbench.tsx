import { useState } from "react";
import { Badge, Button } from "../ui";
import { Callout, CopyButton } from "../mission/parts";
import type { Checkpoint } from "../curriculum";
import { StudyPractice, StudyProve } from "./StudyWorkbench";
import { SplunkPractice, SplunkProve } from "./SplunkWorkbench";
import { NOT_RECORDED, answer, answerable, classification, dig, differing, field, items, modeOf, modes, order, selectWhere, text } from "./checkpoint";

const tone = (d?: string) => d === "ALLOW" || d === "MATCH" || d === "yes" ? "allow" : d === "DENY" || d === "MISMATCH" || d === "no" ? "deny" : d === "ERROR" || d === "FAIL_OPEN" ? "warning" : "muted";
const badge = (cp: Checkpoint) => `${classification(cp)} — NOT A LIVE RUN`;

const verification = (cp: Checkpoint) => cp.spec.kind === "inventory"
  ? `This is a ${classification(cp)} component list. Nothing on it was measured by this page, and no owner, version pin, digest, AI-BOM or compliance claim is made beyond what the packet states in its own words. No receipt from a verifier is attached.`
  : `These records are ${classification(cp)}. No runtime event and no verifier receipt exist for them, so this page makes no claim that any approval, credential check, delegation, recall or tool call was executed, measured, deleted or verified. "Execution observed: YES" is the packet's assertion of separate simulated start evidence, not a real handler start.`;

type Picks = Record<string, Record<string, string>>;

function ModePractice({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec, names = order(cp), preds = spec.predictions ?? [];
  const [sel, setSel] = useState(names[0]);
  const [picks, setPicks] = useState<Picks>({});
  const [state, setState] = useState<Record<string, "predicted" | "skipped">>({});
  const [dpick, setDpick] = useState<Record<number, string[]>>({});
  const [dshown, setDshown] = useState<Record<number, boolean>>({});
  const m = modeOf(cp, sel), mine = picks[sel] ?? {}, st = state[sel];
  const usable = preds.filter((p) => answerable(cp, sel, p));
  const revealed = names.filter((n) => state[n]);
  const rows = revealed.length >= 2 ? [...(spec.setup ?? []), ...(spec.outcome ?? [])].map((f) => ({ f, vals: revealed.map((n) => field(modeOf(cp, n), f.field) ?? NOT_RECORDED) })) : [];
  const pairs: [string, string][] = [["BASELINE", "ATTACK"], ["ATTACK", "RETEST"]].filter(([a, b]) => names.includes(a) && names.includes(b)) as [string, string][];
  return <div className="m-sec rec" data-testid="checkpoint-workbench">
    <h3>Checkpoint workbench <Badge tone="replay">{badge(cp)}</Badge></h3>
    <p className="m-muted">These cases come from a committed {classification(cp)} packet. Nothing is launched, no model is called and nothing is sent to Splunk. Your predictions are not evidence.</p>
    {spec.context && <dl className="rec-setup" aria-label="The packet's standing facts">{spec.context.map((c) => <div key={c.path}><dt>{c.label}</dt><dd><code>{text(dig(cp.packet, c.path))}</code></dd></div>)}</dl>}
    <div role="group" aria-label="Cases in the packet" className="rec-runs">{names.map((n) => <button key={n} type="button" aria-pressed={n === sel} className={`rec-run ${n === sel ? "is-current" : ""}`} onClick={() => setSel(n)}>{n}<small>{state[n] ? "revealed" : "not yet predicted"}</small></button>)}</div>

    <div className="m-sec rec-predict"><h4>1. Predict <Badge tone="muted">YOUR PREDICTION IS NOT EVIDENCE</Badge></h4>
      <dl className="rec-setup">{(spec.setup ?? []).filter((f) => field(m, f.field) !== undefined).map((f) => <div key={f.field}><dt>{f.label}</dt><dd><code>{field(m, f.field)}</code></dd></div>)}</dl>
      {usable.map((p) => <fieldset key={p.id} disabled={Boolean(st)}><legend>{p.question}</legend>
        <div className="rec-options">{p.options.map((o) => <label key={o}><input type="radio" name={`${sel}-${p.id}`} value={o} checked={mine[p.id] === o} onChange={() => setPicks({ ...picks, [sel]: { ...mine, [p.id]: o } })} /> {o}</label>)}</div></fieldset>)}
      {!st && <div className="m-actions"><Button disabled={usable.some((p) => !mine[p.id])} onClick={() => setState({ ...state, [sel]: "predicted" })}>Reveal the packet's record</Button><Button variant="ghost" onClick={() => setState({ ...state, [sel]: "skipped" })}>Skip the predictions and show the record</Button></div>}
      {st && <div role="status" className="rec-reveal">
        {usable.map((p) => { const a = answer(cp, sel, p); return <p key={p.id}>{p.question} {st === "predicted" && <>You predicted <strong>{mine[p.id]}</strong>. </>}Packet: <Badge tone={tone(a.answer)}>{a.answer}</Badge>{st === "predicted" ? (mine[p.id] === a.answer ? " — your prediction matched." : " — your prediction did not match.") : ""}
          {a.reason && <> Reason recorded: <code>{a.reason}</code>.</>}{a.how && <span className="m-muted"> Computed from the packet's own values: {a.how}.</span>}</p>; })}
        <dl className="rec-fields">{(spec.outcome ?? []).map((f) => <div key={f.field}><dt>{f.label}</dt><dd>{field(m, f.field) ?? <span className="m-muted">{NOT_RECORDED}</span>}</dd></div>)}</dl>
        <small className="m-src">Source: <code>{cp.packet_file}</code>, mode {sel}</small></div>}
    </div>

    <div className="m-sec"><h4>2. Spot the difference</h4>
      <p className="m-muted">Tick the request details that differ between two cases. Leave all clear if you think none differ. The answer is computed from the packet's fields.</p>
      {pairs.map(([a, b], i) => { const diff = differing(cp, a, b, spec.diff ?? []), ticked = dpick[i] ?? [], done = dshown[i];
        return <fieldset key={i} disabled={done}><legend>{a} compared with {b}</legend>
          <div className="rec-options">{(spec.diff ?? []).map((f) => <label key={f.field}><input type="checkbox" checked={ticked.includes(f.field)} onChange={(e) => setDpick({ ...dpick, [i]: e.target.checked ? [...ticked, f.field] : ticked.filter((x) => x !== f.field) })} /> {f.label}</label>)}</div>
          {!done && <Button variant="secondary" onClick={() => setDshown({ ...dshown, [i]: true })}>Check against the packet</Button>}
          {done && <div role="status" className="rec-reveal"><p>{diff.length === 0 ? <>The packet records <strong>no difference</strong> in these details.</> : <>They differ in: <strong>{(spec.diff ?? []).filter((f) => diff.includes(f.field)).map((f) => f.label).join(", ")}</strong>.</>} You ticked {ticked.length ? (spec.diff ?? []).filter((f) => ticked.includes(f.field)).map((f) => f.label).join(", ") : "nothing"}{ticked.length === diff.length && ticked.every((x) => diff.includes(x)) ? " — that matches." : " — that does not match."}</p>
            <dl className="rec-fields">{(spec.diff ?? []).map((f) => <div key={f.field}><dt>{f.label}</dt><dd>{a}: {field(modeOf(cp, a), f.field) ?? NOT_RECORDED}<br />{b}: {field(modeOf(cp, b), f.field) ?? NOT_RECORDED}</dd></div>)}</dl></div>}
        </fieldset>; })}
    </div>

    <div className="m-sec"><h4>3. Compare the cases you have revealed</h4>
      {rows.length === 0 ? <p className="m-muted">Reveal at least two cases to compare them. Only revealed cases appear.</p> : <div className="table-wrap" tabIndex={0} role="region" aria-label="Comparison of the revealed cases; scrolls sideways on a narrow screen"><table><caption className="m-caption">Fields of each revealed case, as the packet records them</caption>
        <thead><tr><th scope="col">Field</th>{revealed.map((n) => <th scope="col" key={n}>{n}</th>)}</tr></thead>
        <tbody>{rows.map(({ f, vals }) => { const d = new Set(vals).size > 1; return <tr key={f.field} className={d ? "rec-differs" : ""}><th scope="row">{f.label}{d && <small> (differs)</small>}</th>{vals.map((v, i) => <td key={i}>{v}</td>)}</tr>; })}</tbody></table></div>}
    </div>
  </div>;
}

function InventoryPractice({ cp }: { cp: Checkpoint }) {
  const spec = cp.spec, qs = spec.questions ?? [], list = items(cp), names = list.map((i) => String(i[spec.name_field!]));
  const [ticks, setTicks] = useState<Record<string, string[]>>({});
  const [done, setDone] = useState<Record<string, boolean>>({});
  return <div className="m-sec rec" data-testid="checkpoint-workbench">
    <h3>Checkpoint workbench <Badge tone="replay">{badge(cp)}</Badge></h3>
    <p className="m-muted">This is a documented component list read from a committed packet. Nothing on it was measured by this page, and it is not an AI-BOM.</p>
    <div className="table-wrap" tabIndex={0} role="region" aria-label="The documented components; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">The packet's component list, unedited</caption>
      <thead><tr><th scope="col">Name</th>{spec.columns!.map(([, l]) => <th scope="col" key={l}>{l}</th>)}</tr></thead>
      <tbody>{list.map((i) => <tr key={String(i[spec.name_field!])}><th scope="row">{String(i[spec.name_field!])}</th>{spec.columns!.map(([k, l]) => <td key={k} data-label={l}>{text(i[k])}</td>)}</tr>)}</tbody></table></div>
    <div className="m-sec"><h4>Read the list, then check <Badge tone="muted">YOUR ANSWER IS NOT EVIDENCE</Badge></h4>
      <ol className="rec-qs">{qs.map((q) => { const want = selectWhere(cp, q), got = ticks[q.id] ?? [], shown = done[q.id], ok = want.length === got.length && want.every((w) => got.includes(w));
        return <li className="rec-q" key={q.id}><fieldset disabled={shown}><legend>{q.prompt}</legend>
          <div className="rec-options">{names.map((n) => <label key={n}><input type="checkbox" checked={got.includes(n)} onChange={(e) => setTicks({ ...ticks, [q.id]: e.target.checked ? [...got, n] : got.filter((x) => x !== n) })} /> {n}</label>)}</div></fieldset>
          {!shown && <div className="m-actions"><Button onClick={() => setDone({ ...done, [q.id]: true })}>Check against the packet</Button></div>}
          {shown && <div role="status" className="rec-reveal"><p>The packet's list: <strong>{want.length ? want.join(", ") : "none"}</strong>. You ticked {got.length ? got.join(", ") : "nothing"}{ok ? " — that matches." : " — that does not match."}</p>
            <p className="m-muted">The lab's own wording: <q>{q.quote.text}</q> <small className="m-src">Source: <code>{q.quote.file.split("/").pop()}</code></small></p></div>}
        </li>; })}</ol></div>
  </div>;
}

/** Practice for a simulated or documented packet checkpoint: predict each case, spot the difference, compare. Nothing here launches a run. */
export function CheckpointPractice({ cp }: { cp: Checkpoint }) {
  if (cp.spec.kind === "splunk") return <SplunkPractice cp={cp} />;
  if (cp.spec.kind === "study") return <StudyPractice cp={cp} />;
  return cp.spec.kind === "inventory" ? <InventoryPractice cp={cp} /> : <ModePractice cp={cp} />;
}

/** Prove for a checkpoint: the decisive fields of each case, the packet's own assertions and limits, provenance and the lab's search. */
export function CheckpointProve({ cp }: { cp: Checkpoint }) {
  if (cp.spec.kind === "splunk") return <SplunkProve cp={cp} />;
  if (cp.spec.kind === "study") return <StudyProve cp={cp} />;
  const spec = cp.spec;
  return <div className="m-sec rec" data-testid="checkpoint-prove">
    <h3>The decisive evidence, and where it comes from <Badge tone="replay">{badge(cp)}</Badge></h3>
    <Callout kind="warn"><strong>Verification status: not verified here.</strong> {verification(cp)}</Callout>
    {spec.kind === "inventory" ? <div className="m-sec"><h4>What the packet says, question by question</h4>
      <ul className="m-rules">{(spec.questions ?? []).map((q) => <li key={q.id}>{q.prompt} <strong>{selectWhere(cp, q).join(", ") || "none"}</strong></li>)}</ul></div>
      : <div className="table-wrap" tabIndex={0} role="region" aria-label="Decisive fields of each case; scrolls sideways on a narrow screen"><table className="m-stack"><caption className="m-caption">The decisive fields of each case, in the packet's own words</caption>
        <thead><tr><th scope="col">Case</th>{(spec.decisive ?? []).map((d) => <th scope="col" key={d.field}>{d.label}</th>)}</tr></thead>
        <tbody>{modes(cp).map((m) => <tr key={String(m.mode)}><th scope="row">{String(m.mode)}</th>{(spec.decisive ?? []).map((d) => <td key={d.field} data-label={d.label}>{field(m, d.field) ?? NOT_RECORDED}</td>)}</tr>)}</tbody></table></div>}
    <div className="m-sec"><h4>What the packet itself asserts</h4>
      <dl className="rec-fields">{(spec.packet_facts ?? []).map((f) => <div key={f.path}><dt>{f.label}</dt><dd>{text(dig(cp.packet, f.path))}</dd></div>)}</dl></div>
    {(spec.tables ?? []).map((t) => <div className="m-sec" key={t.path}><h4>{t.title}</h4><div className="table-wrap" tabIndex={0} role="region" aria-label={`${t.title}; scrolls sideways on a narrow screen`}><table className="m-stack"><caption className="m-caption">{t.title}, unedited</caption>
      <thead><tr>{t.columns.map(([, l]) => <th scope="col" key={l}>{l}</th>)}</tr></thead>
      <tbody>{(dig(cp.packet, t.path) as Record<string, unknown>[]).map((r, i) => <tr key={i}>{t.columns.map(([k, l]) => <td key={k} data-label={l}>{text(r[k])}</td>)}</tr>)}</tbody></table></div></div>)}
    {(spec.lists ?? []).map((l) => <div className="m-sec" key={l.path}><h4>{l.title}</h4><ul className="m-rules">{(dig(cp.packet, l.path) as string[]).map((x) => <li key={x}>{x}</li>)}</ul></div>)}
    <details className="m-details"><summary>Provenance of the packet</summary>
      <dl className="rec-fields"><div><dt>Packet file</dt><dd><code>{cp.packet_file}</code></dd></div><div><dt>Packet id</dt><dd><code>{text(cp.packet.packet_id)}</code></dd></div>
        <div><dt>SHA-256 of the file</dt><dd><code>{cp.sha256}</code></dd></div><div><dt>Classification</dt><dd>{classification(cp)}</dd></div></dl>
      <p className="m-muted">The packet is shown unchanged. Its classification is the packet's own. Nothing on this page upgrades a simulated or documented record to a live or measured one.</p></details>
    {cp.spl.length > 0 && <div className="m-sec"><h3>The lab's search (SPL)</h3>
      <p className="m-muted">Shown as written in the lab. It is not run from this page.</p>
      {cp.spl.map((q) => <details className="m-details" key={q.source}><summary><code>{q.name}</code></summary><pre>{q.text}</pre><CopyButton text={q.text} label="Copy search" /><small className="m-src">Source: <code>{q.source}</code></small></details>)}</div>}
  </div>;
}
