import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from "react";
import { isStage, type StageId } from "./stages";

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

export type Route = { name: "home" } | { name: "acmebank" } | { name: "mission"; stage: StageId | null } | { name: "missing" };

export function matchRoute(path: string): Route {
  const parts = path.replace(/\/+$/, "").split("/").filter(Boolean); // ["learn", ...]
  if (parts[0] !== "learn") return { name: "missing" };
  if (parts.length === 1) return { name: "home" };
  if (parts.length === 2 && parts[1] === "acmebank") return { name: "acmebank" };
  if (parts[1] === "loan-desk") {
    if (parts.length === 2) return { name: "mission", stage: null };
    if (parts.length === 3 && isStage(parts[2])) return { name: "mission", stage: parts[2] };
  }
  return { name: "missing" };
}

export const ACMEBANK_PATH = `${BASE}/acmebank`;
export const missionPath = (stage?: StageId) => `${BASE}/loan-desk${stage ? `/${stage}` : ""}`;
