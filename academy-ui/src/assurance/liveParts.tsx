import { useEffect, useRef, type ReactNode } from "react";
import { Badge } from "../ui";
import { Link, assuranceTabPath, type AssuranceTab } from "../router";
import { CopyButton } from "../mission/parts";
import { TAB_LABEL, type Provenance } from "./live";

export const STATUS_CLASS: Record<string, string> = { VERIFIED_EFFECTIVE: "eff", VERIFIED_INEFFECTIVE: "ineff", FINDING_OBSERVED: "obs", INSUFFICIENT_EVIDENCE: "ins", NOT_TESTED: "not", VERIFICATION_UNAVAILABLE: "na" };
export const CATEGORY: Record<string, string> = { VERIFIED_EFFECTIVE: "Held", VERIFIED_INEFFECTIVE: "Did not hold", FINDING_OBSERVED: "Observed", INSUFFICIENT_EVIDENCE: "Evidence gap" };

/** Status as words plus colour, never colour alone. */
export const StatusPill = ({ status, label, byDesign }: { status: string; label?: string; byDesign?: boolean }) =>
  <span className={`as-pill as-pill--${byDesign ? "design" : STATUS_CLASS[status] ?? "not"}`}>{byDesign ? "By design" : label ?? CATEGORY[status] ?? status}</span>;

export const ClassBadge = ({ cls }: { cls: string }) =>
  cls === "LIVE" ? <Badge tone="live">LIVE</Badge> : cls === "RECORDED" ? <Badge tone="recorded">RECORDED</Badge> : <Badge tone="muted">TEST FIXTURE</Badge>;

/** Evidence class is a tab: the three classes are never combined into one view. */
export function ClassTabs({ tab }: { tab: AssuranceTab }) {
  return <nav aria-label="Evidence class" className="as-tabs"><ul>{(["live", "recorded", "fixtures"] as AssuranceTab[]).map((t) =>
    <li key={t}><Link to={assuranceTabPath(t)} aria-current={tab === t ? "page" : undefined} className={tab === t ? "is-on" : ""}>{TAB_LABEL[t]}</Link></li>)}</ul></nav>;
}

export function Banner({ tab }: { tab: AssuranceTab }) {
  if (tab === "recorded") return <div className="as-banner as-banner--rec" role="note"><strong>Recorded examples.</strong> Captured earlier and committed to this repository. They show how controls behaved then, not your lab's current security posture.</div>;
  if (tab === "fixtures") return <div className="as-banner as-banner--fix" role="note"><strong>Test fixtures.</strong> Synthetic data made to test this view's rules (a lost event, a run still arriving, a control that stopped working). It is never real evidence.</div>;
  return null;
}

const when = (iso: string | null) => (iso ? iso.replace("T", " ").replace("Z", " UTC") : "");
export function ProvenanceBar({ p, windowLabel }: { p: Provenance; tabLabel?: string; windowLabel: string }) {
  const other = Object.entries(p.other_classes_not_counted).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k === "TEST_FIXTURE" ? "fixture" : k.toLowerCase()} run${n === 1 ? "" : "s"}`);
  return <p className="as-source">Source: {p.source} · {p.events} events from {p.runs} run{p.runs === 1 ? "" : "s"} · {windowLabel}{p.window_start ? ` (runs that started after ${when(p.window_start)})` : ""} · refreshed {when(p.computed_at)} ·
    {" "}{p.grain}{other.length ? ` · not counted here: ${other.join(", ")}` : ""}</p>;
}

/** An accessible dialog: labelled, modal, Escape closes, focus moves in and returns to the opener. */
export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const el = ref.current!;
    // Only focusable elements that are really shown: a closed <details> keeps its buttons and <pre> in the DOM but they cannot take focus.
    const focusables = () => Array.from(el.querySelectorAll<HTMLElement>("a[href], button:not([disabled]), summary, textarea, [tabindex]:not([tabindex='-1'])")).filter((n) => n.getClientRects().length > 0);
    const root = document.documentElement;
    root.classList.add("as-lock");                       // the page behind must not scroll while the dialog is open
    focusables()[0]?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
      if (e.key !== "Tab") return;
      const f = focusables();
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", key);
    return () => { document.removeEventListener("keydown", key); root.classList.remove("as-lock"); opener?.focus?.(); };
  }, [onClose]);
  return <div className="as-scrim" onClick={onClose}><div ref={ref} className="as-drawer" role="dialog" aria-modal="true" aria-labelledby="as-drawer-h" onClick={(e) => e.stopPropagation()}>
    <div className="as-drawer__head"><h2 id="as-drawer-h">{title}</h2><button type="button" className="button button--ghost" onClick={onClose}>Close</button></div>{children}</div></div>;
}

export { CopyButton };
