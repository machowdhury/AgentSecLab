// Typed client for the Attack Service's existing live-lab contract: POST /api/launch, GET /api/launches/<id>, GET /api/launches/<id>/evidence and
// POST /api/compare-handoff. The classic lab pages call exactly these. The server owns the allowlist, the profile and every control decision; this
// client only names a lab, a catalog specimen and a mode, and reports what comes back. It never launches on its own and never retries.
export const LAUNCH_TIMEOUT_MS = 200000; // the Attack Service waits up to 180 s for the target

export interface Hop {
  "hop.index": number; agent_id: string; agent_name: string; "control.decision": string; "control.reason": string;
  "operation.attempted": boolean; "operation.executed": boolean; "operation.outcome": string;
  "llm.started": boolean; "llm.completed": boolean; "llm.failed": boolean; llm_error?: string | null;
}
export interface LaunchRecord {
  run_id: string; lab_id: string; specimen_id: string; mode: string; profile: string; runtime_status: string; evidence_state: string; lifecycle: string[];
  local_event_count: number | null; "otlp.ok": boolean | null; "hec.ok": boolean | null; splunk_verified: boolean; intentionally_vulnerable?: boolean; vulnerable_label?: string;
  runtime: { hops: Hop[]; blocked: boolean; block_reason: string | null; terminal: string; llm_call_count: number; expected_behavior?: string; actual_behavior?: string; error_stage?: string | null };
  search_handoff: { search_url: string; starter_spl: string }; note?: string;
}
export interface Evidence { evidence_state: string; splunk_attempted?: boolean; splunk_ok?: boolean; splunk_count?: number | null; probe_error?: string | null }
export type LaunchError = { kind: "unreachable" | "timeout" | "rejected" | "not_json" | "http" | "failed"; message: string; status: number };
export type LaunchResult = { record: LaunchRecord } | { error: LaunchError };

const json = async (r: Response) => r.json().catch(() => null);

export async function launchLab(labId: string, specimenId: string, mode: string): Promise<LaunchResult> {
  const ctl = new AbortController();
  const timer = window.setTimeout(() => ctl.abort(), LAUNCH_TIMEOUT_MS);
  try {
    const r = await window.fetch("/api/launch", { method: "POST", headers: { "Content-Type": "application/json" }, signal: ctl.signal, body: JSON.stringify({ lab_id: labId, specimen_id: specimenId, mode, execution: "live" }) });
    const data = await json(r);
    if (!data) return { error: { kind: "not_json", status: r.status, message: "The Attack Service answered with something that is not JSON. No run id was received." } };
    if (data.run_id && r.ok && data.error_class !== "ERROR") {
      if (data.runtime_status !== "COMPLETED") return { error: { kind: "failed", status: r.status, message: `The launch was accepted (run ${data.run_id}) but the runtime reported ${data.runtime_status}. Nothing was concluded from it.` } };
      return { record: data as LaunchRecord };
    }
    if (r.status === 503 || r.status === 502 || r.status === 504) return { error: { kind: "unreachable", status: r.status, message: "The target application is not reachable from the Attack Service, so no run was created. This is not a control decision." } };
    return { error: { kind: "rejected", status: r.status, message: String(data.detail ?? data.error ?? `The launch was refused (HTTP ${r.status}).`) } };
  } catch (e) {
    const aborted = e instanceof DOMException && e.name === "AbortError";
    return { error: { kind: aborted ? "timeout" : "unreachable", status: 0, message: aborted ? `No answer within ${LAUNCH_TIMEOUT_MS / 1000} s. The server may still finish the run, but no run id was received and nothing was retried.` : "The Attack Service could not be reached. No run was created." } };
  } finally { window.clearTimeout(timer); }
}

export async function loadLaunch(id: string): Promise<LaunchRecord | null> {
  try { const r = await window.fetch(`/api/launches/${encodeURIComponent(id)}`); return r.ok ? ((await json(r)) as LaunchRecord) : null; } catch { return null; }
}
export async function probeEvidence(id: string): Promise<Evidence | null> {
  try { const r = await window.fetch(`/api/launches/${encodeURIComponent(id)}/evidence?timeout_seconds=0`); return r.ok ? ((await json(r)) as Evidence) : null; } catch { return null; }
}
export async function compareRuns(attack: string, retest: string): Promise<{ search_url: string; starter_spl: string } | null> {
  try { const r = await window.fetch("/api/compare-handoff", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ attack_run_id: attack, retest_run_id: retest }) }); return r.ok ? await json(r) : null; } catch { return null; }
}
