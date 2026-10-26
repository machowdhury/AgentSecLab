import { CURRICULUM_PATH, EVALS_PATH, GOV_PATH, Link, RISK_PATH, missionPath } from "./router";

const STEPS: [string, string, (p: string) => boolean][] = [
  ["Learn", CURRICULUM_PATH, (p) => p.includes("/curriculum") || p.includes("/lab/") || /\/loan-desk(\/(learn|prepare))?$/.test(p)],
  ["Attack", missionPath("attack"), (p) => p.endsWith("/loan-desk/attack")],
  ["Investigate", missionPath("investigate"), (p) => /\/loan-desk\/(investigate|defend|retest|explain)$/.test(p)],
  ["EVAL", EVALS_PATH, (p) => p.startsWith(EVALS_PATH)],
  ["Risk", RISK_PATH, (p) => p.startsWith(RISK_PATH)],
  ["Governance", GOV_PATH, (p) => p.startsWith(GOV_PATH)],
];

export function WorkshopFlow({ path }: { path: string }) {
  return <nav aria-label="Workshop path" className="wf"><ol>{STEPS.map(([label, to, on]) => <li key={label}><Link to={to} aria-current={on(path) ? "step" : undefined} className={on(path) ? "is-current" : ""}>{label}</Link></li>)}</ol></nav>;
}
