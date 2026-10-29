import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from "react";
import { isStage, type StageId } from "./stages";
import { STEP_IDS, type StepId } from "./assurance/types";

// Real URLs (History API) under /learn: Back, Forward, Refresh and deep links all work, and the Flask route serves the same page for each.
export const BASE = "/learn";
export const CHALLENGES_PATH = "/learn/challenges";
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
window.addEventListener("popstate", emit);
const subscribe = (cb: () => void) => { listeners.add(cb); return () => { listeners.delete(cb); }; };

export function usePath(): string {
  return useSyncExternalStore(subscribe, () => window.location.pathname, () => BASE);
}

export function navigate(to: string, opts: { replace?: boolean } = {}): void {
  if (to === window.location.pathname) return;
  window.history[opts.replace ? "replaceState" : "pushState"](null, "", to);
  emit();
  window.scrollTo({ top: 0 });
}

export function Link({ to, children, onClick, ...rest }: { to: string; children: ReactNode } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href">) {
  const go = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
  return <a href={to} onClick={go} {...rest}>{children}</a>;
}

export type EvalView = "overview" | "catalog" | "results" | "compare" | "findings" | "export";
export const EVAL_VIEWS: EvalView[] = ["overview", "catalog", "results", "compare", "findings", "export"];
export type RiskView = { view: "overview" } | { view: "register"; filter: string } | { view: "method" } | { view: "new" } | { view: "detail"; id: string };
export const RISK_FILTERS = ["all", "unassessed", "with-findings", "gaps", "treatment", "awaiting-review"];
export type GovView = "overview" | "frameworks" | "threats" | "export";
export const GOV_VIEWS: GovView[] = ["overview", "frameworks", "threats", "export"];
export type Route = { name: "challenges" } | { name: "governance"; view: GovView } | { name: "risk" } & RiskView | { name: "evals"; view: EvalView; id: string | null } | { name: "assurance"; step: StepId | null | "hub" } | { name: "home" } | { name: "acmebank" } | { name: "path" } | { name: "foundations" } | { name: "mastery" } | { name: "mcp" } | { name: "curriculum" } | { name: "lab"; id: string } | { name: "mission"; stage: StageId | null } | { name: "missing" };

export function matchRoute(path: string): Route {
  const parts = path.replace(/\/+$/, "").split("/").filter(Boolean); // ["learn", ...]
  if (parts[0] !== "learn") return { name: "missing" };
  if (parts.length === 1) return { name: "home" };
  if (parts.length === 2 && parts[1] === "acmebank") return { name: "acmebank" };  // retired: redirected to the Prepare stage
  if (parts.length === 2 && parts[1] === "curriculum") return { name: "curriculum" };
  if (parts.length === 2 && parts[1] === "challenges") return { name: "challenges" };
  if (parts[1] === "governance" && parts.length <= 3 && (parts.length === 2 || (GOV_VIEWS as string[]).includes(parts[2]) && parts[2] !== "overview")) return { name: "governance", view: (parts[2] ?? "overview") as GovView };
  if (parts[1] === "risk") {
    if (parts.length === 2) return { name: "risk", view: "overview" };
    if (parts[2] === "register" && parts.length <= 4 && (parts.length === 3 || RISK_FILTERS.includes(parts[3]))) return { name: "risk", view: "register", filter: parts[3] ?? "all" };
    if ((parts[2] === "method" || parts[2] === "new") && parts.length === 3) return { name: "risk", view: parts[2] as "method" | "new" } as Route;
    if (parts.length === 3 && /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/.test(parts[2]) && !["register", "method", "new"].includes(parts[2])) return { name: "risk", view: "detail", id: parts[2] };
  }
  if (parts[1] === "evals") {
    if (parts.length === 2) return { name: "evals", view: "overview", id: null };
    const v = parts[2] as EvalView;
    if ((EVAL_VIEWS as string[]).includes(v) && v !== "overview") {
      if ((v === "results" || v === "compare") && parts.length <= 4 && (parts.length === 3 || /^[a-z0-9-]+$/.test(parts[3]))) return { name: "evals", view: v, id: parts[3] ?? null };
      if ((v === "catalog" || v === "findings" || v === "export") && parts.length === 3) return { name: "evals", view: v, id: null };
    }
  }
  if (parts[1] === "assurance") {
    if (parts.length === 2) return { name: "assurance", step: "hub" };
    if (parts[2] === "mcp-unauthorized-scope" && parts.length === 3) return { name: "assurance", step: null };
    if (parts[2] === "mcp-unauthorized-scope" && parts.length === 4 && (STEP_IDS as string[]).includes(parts[3])) return { name: "assurance", step: parts[3] as StepId };
  }
  if (parts.length === 3 && parts[1] === "lab" && /^LAB-[A-Z0-9-]+$/.test(parts[2])) return { name: "lab", id: parts[2] };
  if (parts.length === 2 && ["path", "foundations", "mastery", "mcp"].includes(parts[1])) return { name: parts[1] as "path" | "foundations" | "mastery" | "mcp" };
  if (parts[1] === "loan-desk") {
    if (parts.length === 2) return { name: "mission", stage: null };
    if (parts.length === 3 && isStage(parts[2])) return { name: "mission", stage: parts[2] };
  }
  return { name: "missing" };
}

export const GOV_PATH = `${BASE}/governance`;
export const RISK_PATH = `${BASE}/risk`;
export const EVALS_PATH = `${BASE}/evals`;
export const ASSURANCE_PATH = `${BASE}/assurance`, JOURNEY_PATH = `${BASE}/assurance/mcp-unauthorized-scope`;
export const PATH_PATH = `${BASE}/path`, FOUNDATIONS_PATH = `${BASE}/foundations`, MASTERY_PATH = `${BASE}/mastery`, MCP_PATH = `${BASE}/mcp`, CURRICULUM_PATH = `${BASE}/curriculum`;
export const labPath = (id: string) => `${BASE}/lab/${id}`;
export const missionPath = (stage?: StageId) => `${BASE}/loan-desk${stage ? `/${stage}` : ""}`;
