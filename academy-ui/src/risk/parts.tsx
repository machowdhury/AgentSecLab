import { useId, useRef, useState, type ReactNode } from "react";
import { Badge, Button } from "../ui";
import { exportDoc, importText, resetDraft, useDraft } from "./store";
import type { Level, Method, Origin, Problem } from "./types";

const levelTone = { LOW: "allow", MEDIUM: "warning", HIGH: "deny" } as const;
export function LevelBadge({ level }: { level: Level | null }) { return level ? <Badge tone={levelTone[level]}>{level}</Badge> : <Badge tone="muted">NOT ASSESSED</Badge>; }
const originTone: Record<Origin, "replay" | "observed" | "neutral" | "muted"> = { SOURCE: "replay", DERIVED: "observed", ANALYST: "neutral", MISSING: "muted" };
export function OriginBadge({ o, method }: { o: Origin; method: Method }) { const m = method.origins.find((x) => x.id === o)!; return <span title={m.meaning}><Badge tone={originTone[o]}>{m.label.toUpperCase()}</Badge></span>; }
export const time = (iso: string | null) => (iso ? new Date(iso).toLocaleTimeString() : "");

/** A labelled row whose value always says where it came from. */
export function Fact({ label, origin, method, children }: { label: string; origin: Origin; method: Method; children: ReactNode }) {
  return <div><dt>{label} <OriginBadge o={origin} method={method} /></dt><dd>{children}</dd></div>;
}

export function Problems({ problems, id }: { problems: Problem[]; id?: string }) {
  if (!problems.length) return null;
  return <div role="alert" id={id} className="rk-errors"><p><strong>{problems.length} problem{problems.length > 1 ? "s" : ""} to fix:</strong></p>
    <ul>{problems.slice(0, 20).map((p, i) => <li key={i}><code>{p.code}</code> {p.path !== "$" && <code>{p.path}</code>} {p.message}</li>)}</ul>{problems.length > 20 && <p>…and {problems.length - 20} more.</p>}</div>;
}

/** Every Risk Center page shows this: the draft is local, and these three controls keep it portable and resettable. */
export function DraftBar() {
  const d = useDraft();
  const [confirm, setConfirm] = useState(false);
  const [imp, setImp] = useState<{ ok: boolean; text: string; warning?: string; problems?: Problem[] } | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const uid = useId();
  const download = () => {
    const doc = exportDoc(), a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" })); a.download = "risk-assessment-draft.json"; document.body.appendChild(a); a.click(); a.remove();
    setImp({ ok: true, text: `Exported ${doc.risks.length} risks to risk-assessment-draft.json. The file is a local draft: not approved.` });
  };
  const upload = async (f: File | undefined) => {
    if (!f) return;
    const r = importText(await f.text());
    setImp(r.ok ? { ok: true, text: r.summary, warning: r.warning } : { ok: false, text: "The file was not imported and your draft is unchanged.", problems: r.problems });
    if (file.current) file.current.value = "";
  };
  return <section className="rk-bar" aria-label="Your local draft">
    <p><Badge tone="warning">LOCAL DRAFT</Badge> <strong>Stored only in this browser.</strong> Not shared, not centrally persisted, and not approved. Saving never approves anything.</p>
    <p role="status" className="m-muted">{d.notice || (d.saved === "saved" ? `Saved to this browser at ${time(d.savedAt)}.` : d.saved === "memory" ? "This browser would not store the draft, so it is kept in memory and will be lost on reload." : "No changes saved yet.")}</p>
    <div className="m-actions">
      <Button variant="secondary" onClick={download}>Export JSON</Button>
      <Button variant="secondary" onClick={() => file.current?.click()}>Import JSON</Button>
      <input ref={file} id={`${uid}-file`} type="file" accept="application/json,.json" className="visually-hidden" aria-label="Choose a risk assessment JSON file to import" onChange={(e) => upload(e.target.files?.[0])} />
      {!confirm ? <Button variant="ghost" onClick={() => setConfirm(true)}>Reset draft</Button> :
        <span role="group" aria-label="Confirm reset" className="rk-confirm">Discard every edit and start again from the source-backed risks? <Button onClick={() => { resetDraft(); setConfirm(false); setImp(null); }}>Yes, reset</Button> <Button variant="ghost" onClick={() => setConfirm(false)}>Cancel</Button></span>}
    </div>
    {imp && (imp.ok ? <div role="status"><p>{imp.text}</p>{imp.warning && <p className="m-muted">{imp.warning}</p>}</div> : <><p role="status">{imp.text}</p><Problems problems={imp.problems!} /></>)}
  </section>;
}
