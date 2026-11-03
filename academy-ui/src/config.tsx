import { createContext, useContext, useEffect, useState, type AnchorHTMLAttributes, type ReactNode } from "react";
import { api } from "./api";

export interface MissionConfig {
  id: string; lab_id: string; duration_minutes: string; objectives: string[]; prerequisites: string[]; boundaries: string[];
  default_application: Record<string, string>; normal_notes: string; attack_notes: string;
}
// gateway: the opt-in HTTPS gateway fronts this UI. It does not route Splunk Web, AcmeBank or the classic Academy pages, so the server reports those URLs as null and
// the UI shows no link to them (a link to a route the gateway does not implement would be dead).
export interface LearnConfig { version: string; gateway?: boolean; role?: "operator" | "learner" | null; urls: { splunk_web: string | null; acmebank: string | null; ctf?: string | null }; mission: MissionConfig | null }

// Until the server answers, service URLs come from the hostname the browser is already using (never a hard-coded host).
const here = (port: number) => `${window.location.protocol}//${window.location.hostname.includes(":") ? `[${window.location.hostname}]` : window.location.hostname}:${port}`;
const fallback: LearnConfig = { version: "", urls: { splunk_web: here(8000), acmebank: here(5000) }, mission: null };
const Ctx = createContext<{ config: LearnConfig; loaded: boolean; failed: boolean }>({ config: fallback, loaded: false, failed: false });

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [value, setValue] = useState({ config: fallback, loaded: false, failed: false });
  useEffect(() => {
    api<LearnConfig>("/api/learn/config").then((r) => setValue(r.ok ? { config: r.data, loaded: true, failed: false } : { config: fallback, loaded: true, failed: true }));
  }, []);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
export const useConfig = () => useContext(Ctx);
/** A link that opens Splunk Web. Behind the HTTPS gateway Splunk Web is not published, so such a link would be dead: render nothing there. */
export function SplunkLink(props: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { config } = useConfig();
  return config.gateway ? null : <a {...props} />;
}

export type EnvState = { level: "checking" | "ready" | "attention"; detail: string };
/** Reads the real service checks; never claims readiness it did not measure. */
export function useEnvironment(): EnvState {
  const [env, setEnv] = useState<EnvState>({ level: "checking", detail: "Checking the lab…" });
  useEffect(() => {
    api("/api/academy/status").then((r) => {
      if (!r.ok) { setEnv({ level: "attention", detail: "The Attack Service did not report its status." }); return; }
      const checks: { name: string; state: string }[] = r.data.checks || [];
      const state = (n: string) => checks.find((c) => c.name === n)?.state;
      const web = state("Splunk Web (reachability)"), rest = state("Splunk REST (configured endpoint)");
      const bad = ["Attack Service", "AcmeBank runtime"].filter((n) => state(n) !== "AVAILABLE");
      // Splunk: the configured REST endpoint (external modes) must have passed every stage; otherwise the configured Splunk Web must answer. Reachability is all Splunk Web can show.
      if (rest !== undefined ? rest !== "AVAILABLE" : web !== "AVAILABLE") bad.push(rest !== undefined ? "Splunk REST (configured endpoint)" : "Splunk Web (reachability)");
      setEnv(bad.length ? { level: "attention", detail: `Not available: ${bad.join(", ")}` }
        : { level: "ready", detail: rest !== undefined ? "Attack Service and AcmeBank answered; the configured Splunk endpoint passed connectivity, authentication, authorization and a trivial search. Indexing is not checked here." : "Attack Service and AcmeBank answered; Splunk Web is reachable. That is reachability only: login, search and indexing are not checked here." });
    });
  }, []);
  return env;
}

/** Who the gateway authenticated. Starting a run or a live search needs the operator role; the gateway refuses everyone else (403). `blocked` is true only when the
 *  role is known to be learner, so a lab without the gateway (role unknown) is never gated here: the server stays the one that decides. */
export function useRole() {
  const { config, loaded } = useConfig();
  const role = config.role ?? null;
  return { role, loaded, blocked: role === "learner" };
}
export const NEEDS_OPERATOR = "You are signed in as the learner role, which is read-only. Starting a run or a live search needs the operator role: sign in as operator (the password is in .gateway/credentials.txt on the lab host). Reading, recorded evidence and results stay available.";
/** A visible reason beside a disabled launch control. Renders nothing for the operator. */
export function OperatorNote() {
  const { blocked } = useRole();
  return blocked ? <p className="m-muted" role="note"><strong>Operator role needed.</strong> {NEEDS_OPERATOR}</p> : null;
}
