import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from "react";
import { isStage, type StageId } from "./stages";
import { STEP_IDS, type StepId } from "./assurance/types";

// Real URLs (History API) under /learn: Back, Forward, Refresh and deep links all work, and the Flask route serves the same page for each.
export const BASE = "/learn";
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

export type Route = { name: "assurance"; step: StepId | null | "hub" } | { name: "home" } | { name: "acmebank" } | { name: "path" } | { name: "foundations" } | { name: "mastery" } | { name: "mcp" } | { name: "curriculum" } | { name: "lab"; id: string } | { name: "mission"; stage: StageId | null } | { name: "missing" };

export function matchRoute(path: string): Route {
  const parts = path.replace(/\/+$/, "").split("/").filter(Boolean); // ["learn", ...]
  if (parts[0] !== "learn") return { name: "missing" };
  if (parts.length === 1) return { name: "home" };
  if (parts.length === 2 && parts[1] === "acmebank") return { name: "acmebank" };  // retired: redirected to the Prepare stage
  if (parts.length === 2 && parts[1] === "curriculum") return { name: "curriculum" };
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

export const ASSURANCE_PATH = `${BASE}/assurance`, JOURNEY_PATH = `${BASE}/assurance/mcp-unauthorized-scope`;
export const PATH_PATH = `${BASE}/path`, FOUNDATIONS_PATH = `${BASE}/foundations`, MASTERY_PATH = `${BASE}/mastery`, MCP_PATH = `${BASE}/mcp`, CURRICULUM_PATH = `${BASE}/curriculum`;
export const labPath = (id: string) => `${BASE}/lab/${id}`;
export const missionPath = (stage?: StageId) => `${BASE}/loan-desk${stage ? `/${stage}` : ""}`;
