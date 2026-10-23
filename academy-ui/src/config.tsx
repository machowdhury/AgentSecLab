import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "./api";

export interface MissionConfig {
  id: string; lab_id: string; duration_minutes: string; objectives: string[]; prerequisites: string[]; boundaries: string[];
  default_application: Record<string, string>; normal_notes: string; attack_notes: string;
}
export interface LearnConfig { version: string; urls: { splunk_web: string; acmebank: string }; mission: MissionConfig | null }

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

export type EnvState = { level: "checking" | "ready" | "attention"; detail: string };
/** Reads the real service checks; never claims readiness it did not measure. */
export function useEnvironment(): EnvState {
  const [env, setEnv] = useState<EnvState>({ level: "checking", detail: "Checking the lab…" });
  useEffect(() => {
    api("/api/academy/status").then((r) => {
      if (!r.ok) { setEnv({ level: "attention", detail: "The Attack Service did not report its status." }); return; }
      const need = ["Attack Service", "AcmeBank runtime", "Splunk Web (reachability)"];
      const checks: { name: string; state: string }[] = r.data.checks || [];
      const bad = need.filter((n) => checks.find((c) => c.name === n)?.state !== "AVAILABLE");
      setEnv(bad.length ? { level: "attention", detail: `Not available: ${bad.join(", ")}` } : { level: "ready", detail: "Attack Service, AcmeBank and Splunk Web answered." });
    });
  }, []);
  return env;
}
