import { CURRICULUM_PATH, EVALS_PATH, GOV_PATH, Link, MCP_PATH, RISK_PATH, labPath, missionPath } from "./router";
import { labById } from "./curriculum";
import { goToStage } from "./UnifiedWorkshop";
import type { UnifiedStageId } from "./stages";

/** A lab page listens for this to open its Practice tab at the stage the flow bar asked for. */
export const STAGE_EVENT = "agentsec:stage";

type Step = { label: string; to: string; on: boolean; stage?: UnifiedStageId };

/** The flow bar always points at the workshop the learner is in: the Loan Desk, MCP Tool Authorization, or the lab page. Outside a workshop, Attack and Investigate lead to the Curriculum Explorer, where a workshop is chosen. */
function steps(path: string): Step[] {
  const lab = /\/learn\/lab\/(LAB-[A-Z0-9-]+)$/.exec(path)?.[1];
  const loan = path.includes("/learn/loan-desk"), mcp = path.endsWith("/learn/mcp");
  const live = lab ? labById(lab)?.mode === "LIVE" : false;
  const here = lab ? labPath(lab) : mcp ? MCP_PATH : undefined;
  const learn: Step = { label: "Learn", to: here ?? (loan ? missionPath("learn") : CURRICULUM_PATH), on: path.includes("/curriculum") || Boolean(lab) || mcp || (loan && /\/loan-desk(\/(learn|prepare))?$/.test(path)), stage: "learn" };
  const mid: Step[] = loan
    ? [{ label: "Attack", to: missionPath("attack"), on: path.endsWith(missionPath("attack")) }, { label: "Investigate", to: missionPath("investigate"), on: [missionPath("investigate"), missionPath("defend"), missionPath("retest"), missionPath("explain")].some((x) => path.endsWith(x)) }]
    : here && (live || mcp) ? [{ label: "Attack", to: here, on: false, stage: "attack" }, { label: "Investigate", to: here, on: false, stage: "investigate" }]
      : here ? [{ label: "Investigate", to: here, on: false }]
        : [{ label: "Attack", to: CURRICULUM_PATH, on: false }, { label: "Investigate", to: CURRICULUM_PATH, on: false }];
  return [learn, ...mid, { label: "EVAL", to: EVALS_PATH, on: path.startsWith(EVALS_PATH) }, { label: "Risk", to: RISK_PATH, on: path.startsWith(RISK_PATH) }, { label: "Governance", to: GOV_PATH, on: path.startsWith(GOV_PATH) }];
}

export function WorkshopFlow({ path }: { path: string }) {
  return <nav aria-label="Workshop path" className="wf"><ol>{steps(path).map((s) =>
    <li key={s.label}><Link to={s.to} aria-current={s.on ? "step" : undefined} className={s.on ? "is-current" : ""}
      onClick={() => { if (s.stage) { window.dispatchEvent(new CustomEvent(STAGE_EVENT, { detail: s.stage })); goToStage(s.stage); } }}>{s.label}</Link></li>)}</ol></nav>;
}
