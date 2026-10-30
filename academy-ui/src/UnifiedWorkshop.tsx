import { unifiedStages, unifiedNumber, type UnifiedStageId } from "./stages";
import { LAB_ID, stageComplete, useMission, type MissionState } from "./store";

const long = (t: string | undefined) => (t ?? "").trim().length >= 20;

/** Which of the eight unified stages the learner has really completed in this workshop, read from the learner's own recorded progress. */
export function progressOf(lab: string, m: MissionState): Record<UnifiedStageId, boolean> {
  if (lab === LAB_ID) {
    const done: Record<UnifiedStageId, boolean> = { learn: m.seen.includes("learn"), predict: Boolean(m.prediction.locked), baseline: Boolean(m.runs.explore), attack: Boolean(m.runs.attack),
      investigate: stageComplete("investigate", m), defend: m.defenseApplied, retest: Boolean(m.runDone.retest), explain: m.completed };
    return done;
  }
  const wb = m.workbench?.[lab];
  const mcp = lab === "LAB-MCP-001";
  const predict = mcp ? Boolean(m.mcp?.locked) : Boolean(wb?.prediction?.locked);
  const attack = mcp ? Boolean(m.mcp?.attack) : Boolean(wb?.runs?.attack);
  const retest = mcp ? Boolean(m.mcp?.retest) : Boolean(wb?.runs?.retest);
  return { learn: predict || attack, predict, baseline: mcp ? Boolean(m.mcp?.baseline) : Boolean(wb?.runs?.baseline), attack, investigate: Boolean(wb?.investigated), defend: retest, retest, explain: long(wb?.explain) };
}

/** The unified sequence for a LIVE workshop. Each stage says what it is and whether the learner has done it; choosing one goes to its section. */
export function UnifiedRail({ lab, onSelect, current, lockedReason }: { lab: string; onSelect: (s: UnifiedStageId) => void; current?: UnifiedStageId[]; lockedReason?: (s: UnifiedStageId) => string }) {
  const done = progressOf(lab, useMission());
  const next = unifiedStages.find((s) => !done[s.id])?.id;
  return <nav aria-label="Workshop stages" className="uw-rail"><ol>{unifiedStages.map((s) => {
    const state = done[s.id] ? "done" : s.id === next ? "next" : "todo";
    const here = current?.includes(s.id), why = lockedReason?.(s.id) ?? "";
    return <li key={s.id} className={`uw-stage uw-stage--${state}${here ? " uw-stage--here" : ""}${why ? " uw-stage--locked" : ""}`}>
      <button type="button" onClick={() => onSelect(s.id)} aria-disabled={why ? "true" : undefined} title={why || undefined} aria-current={here ? "step" : !current && state === "next" ? "step" : undefined}>
        <span className="uw-n" aria-hidden="true">{unifiedNumber(s.id)}</span><span className="uw-l">{s.label}</span>
        <span className="uw-s">{state === "done" ? "done" : state === "next" ? "next" : "to do"}<span className="visually-hidden">: stage {unifiedNumber(s.id)} of {unifiedStages.length}{why ? `. Locked: ${why}` : ""}</span></span></button></li>;
  })}</ol></nav>;
}

/** "Stage N of 8" heading for a section of a LIVE workshop; data-stage lets the rail scroll to it. */
export function StageSection({ stage, id, title, children }: { stage: UnifiedStageId; id: string; title: string; children: React.ReactNode }) {
  return <section className="m-wbstep" data-stage={stage} aria-labelledby={id}><h3 id={id}><span>{unifiedNumber(stage)}</span> {title} <small className="m-muted">stage {unifiedNumber(stage)} of {unifiedStages.length}</small></h3>{children}</section>;
}

/** Scroll to a stage's section once the Practice tab is showing. */
export function goToStage(stage: UnifiedStageId): void {
  window.setTimeout(() => { const el = document.querySelector(`[data-stage="${stage}"]`) as HTMLElement | null; if (el) { el.scrollIntoView({ block: "start" }); (el.querySelector("h3") as HTMLElement | null)?.focus?.(); } }, 60);
}
