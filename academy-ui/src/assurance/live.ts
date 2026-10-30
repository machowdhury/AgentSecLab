import { useEffect, useState } from "react";
import { api } from "../api";
import type { AssuranceTab } from "../router";

export type WindowKey = "24h" | "7d" | "all";
export const WINDOWS: [WindowKey, string][] = [["24h", "24 hours"], ["7d", "Last 7 days"], ["all", "All time"]];
export const TAB_LABEL: Record<AssuranceTab, string> = { live: "Live · this lab", recorded: "Recorded examples", fixtures: "Test fixtures" };

export interface Card { finding_id: string; status: string; status_label: string; by_design: boolean; title: string; context: string; run_id: string; mode: string; profile: string; rule_id: string; retest: string; control_id: string; lab_id: string | null; priority?: number }
export interface Tile { id: string; label: string; n: number; of: number; definition: string; by_design?: number; of_definition?: string; not_validated?: number; no_retest?: number }
export interface Provenance { source: string; events: number; runs: number; grain: string; computed_at: string | null; window_start: string | null; other_classes_not_counted: Record<string, number>; evidence_rule: string }
export interface ControlRow { id: string; name: string; class: string; tested: boolean; counts: Record<string, number>; findings: number }
export interface Overview {
  tab: AssuranceTab; evidence_class: string; window: { key: WindowKey; label: string }; state: "ok" | "empty" | "unavailable"; reason?: string; provenance: Provenance;
  headline?: { attention: number; text: string }; attention?: Card[]; attention_all?: Card[]; tiles?: Tile[];
  disclosure?: { controls: { tested: number; of: number; items: ControlRow[] }; gaps: { n: number; items: Card[] }; not_tested: { n: number; of: number; ids: string[] };
    by_status: { total: number; items: { status: string; label: string; n: number; by_design: boolean }[] }; how: string[] };
}
export interface Detail {
  state: "ok" | "unavailable"; reason?: string; tab: AssuranceTab;
  finding?: Record<string, any> & { finding_id: string; title: string; status: string; status_label: string; run_id: string; mode: string; profile: string; evidence_class: string; control_id: string; hop: number | null; spl: string; by_design: boolean };
  timeline?: { sequence: number | null; name: string; hop: number | null; decision: string | null; executed: boolean | null; focus: boolean }[]; missing_sequences?: number[];
  run?: { complete: boolean; terminal: boolean; contiguous: boolean; events: number; duplicates: number };
  events?: { sequence: number | null; name: string; hop: number | null; json: string; truncated: boolean }[]; events_truncated?: boolean;
  linked_retest?: { run_id: string; status: string; status_label: string; finding_id: string } | null;
  workshop?: { lab_id: string | null; run_id: string; mode: string; adoptable: boolean }; provenance?: Provenance;
}

const base = (tab: AssuranceTab) => (tab === "fixtures" ? "/api/assurance/fixtures" : "/api/assurance");
export const overviewUrl = (tab: AssuranceTab, w: WindowKey) => `${base(tab)}/overview?${tab === "fixtures" ? "" : `tab=${tab}&`}window=${w}`;
export const findingUrl = (tab: AssuranceTab, id: string, w: WindowKey) => `${base(tab)}/findings/${id}?${tab === "fixtures" ? "" : `tab=${tab}&`}window=${w}`;

export type Load<T> = { loading: true } | { loading: false; data: T } | { loading: false; error: string; status: number };

export function useLoad<T>(url: string): Load<T> {
  const [s, setS] = useState<Load<T>>({ loading: true });
  useEffect(() => {
    let live = true;
    setS({ loading: true });
    api<T>(url).then((r) => { if (live) setS(r.ok ? { loading: false, data: r.data } : { loading: false, error: r.data && (r.data as any).error ? String((r.data as any).error) : "request_failed", status: r.status }); });
    return () => { live = false; };
  }, [url]);
  return s;
}

const KEY = "agentsec.assurance.window";
export function readWindow(): WindowKey {
  try { const v = window.sessionStorage.getItem(KEY); if (v === "24h" || v === "7d" || v === "all") return v; } catch { /* convenience only */ }
  return "7d";
}
export function saveWindow(w: WindowKey) { try { window.sessionStorage.setItem(KEY, w); } catch { /* convenience only */ } }

export const REASONS: Record<string, string> = {
  not_provisioned: "Search access to Splunk is not set up on this lab, so nothing was searched. There are no numbers here, and that is not a pass. Ask the lab owner to run ./agentsec splunk-access.",
  not_configured: "Splunk search access is configured incorrectly, so nothing was searched. There are no numbers here, and that is not a pass.",
  unreachable: "The Attack Service cannot reach Splunk right now, so nothing was searched. There are no numbers here, and that is not a pass.",
  access_denied: "Splunk refused the lab's search identity, so nothing was searched. There are no numbers here, and that is not a pass.",
  timeout: "Splunk took too long to answer, so nothing was read. There are no numbers here, and that is not a pass.",
  too_large: "The telemetry for this window is larger than one view can read. Choose a shorter window.",
  search_failed: "Splunk could not run the search, so nothing was read. There are no numbers here, and that is not a pass.",
};

export interface InvParam { name: string; kind: "int" | "enum"; default: string | number; label: string; lo?: number; hi?: number; choices?: string[]; choice_labels?: Record<string, string> }
export interface InvCell { id: string; title: string; question: string; proves: string; not_proves: string; hint: string; params: InvParam[]; columns: string[]; spl: string | null }
export interface Investigation {
  state: "ok" | "unavailable"; reason?: string; tab: AssuranceTab; mode: "splunk" | "local"; search_ready: boolean; source: string; window: string;
  origin: { finding_id: string; title: string; run_id: string; control_id: string; hop: number | null; evidence_class: string; attack_id: string | null; mode: string; profile: string; status: string; status_label: string; lab_id: string | null; adoptable: boolean };
  next: { defend: string; retest: string | null; retest_outcome: string | null };
  cells: InvCell[];
}
export interface CellResult { status: string; ok?: boolean; source?: string; columns?: string[]; rows?: string[][]; row_count?: number; truncated?: boolean; row_cap?: number; duration_ms?: number; error?: string; spl?: string | null; evidence_class?: string; window?: string; note?: string; params?: Record<string, string | number> }
export interface CmpSide { finding_id: string; run_id: string; mode: string; profile: string; status: string; status_label: string; by_design: boolean; hop: number | null; complete: boolean | null; events: number | null }
export interface CmpRow { hop: number; attack: { decision: string; reason: string; handler_started: boolean; executed: boolean } | null; retest: { decision: string; reason: string; handler_started: boolean; executed: boolean } | null }
export interface Comparison {
  state: "ok" | "unavailable"; reason?: string; tab: AssuranceTab; evidence_class: string; finding_id: string; kind: "none" | "no_retest" | "linked"; message?: string; outcome?: string; comparable?: boolean;
  control_id?: string; attack?: CmpSide; retest?: CmpSide; rows?: CmpRow[]; notes?: string[]; candidates?: number; how?: string[];
}
const fbase = (tab: AssuranceTab, id: string) => (tab === "fixtures" ? `/api/assurance/fixtures/findings/${id}` : `/api/assurance/findings/${id}`);
const q = (tab: AssuranceTab, w: WindowKey) => (tab === "fixtures" ? `window=${w}` : `tab=${tab}&window=${w}`);
export const investigationUrl = (tab: AssuranceTab, id: string, w: WindowKey) => `${fbase(tab, id)}/investigation?${q(tab, w)}`;
export const comparisonUrl = (tab: AssuranceTab, id: string, w: WindowKey) => `${fbase(tab, id)}/comparison?${q(tab, w)}`;
export const exploreUrl = (tab: AssuranceTab, id: string, cell: string, w: WindowKey, params: Record<string, string | number>) =>
  `${fbase(tab, id)}/explore/${cell}?${q(tab, w)}${Object.entries(params).map(([k, v]) => `&${k}=${encodeURIComponent(String(v))}`).join("")}`;
export const cellRunUrl = (id: string, cell: string, w: WindowKey) => `/api/assurance/findings/${id}/cells/${cell}?window=${w}`;
export const searchUrl = (id: string, sid: string, w: WindowKey) => `/api/assurance/findings/${id}/searches/${sid}?window=${w}`;
