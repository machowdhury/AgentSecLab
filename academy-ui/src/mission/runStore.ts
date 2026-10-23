import { useSyncExternalStore } from "react";
import { api, post, problemText } from "../api";
import type { Posture, RunView, Slot } from "../types";
import { getMission, markProgress, updateMission } from "../store";
import { evidenceText } from "./content";

// Runs live at module level so a run keeps polling while the learner moves between stages. Views are always read from the service.
export const POLL_MS = 700;
export const POLL_MAX_MS = 150000;
const SLOTS: Slot[] = ["explore", "attack", "retest"];

export type Phase = "idle" | "submitting" | "running" | "stopped" | "error";
export interface SlotState { phase: Phase; view?: RunView; message?: string; fieldErrors?: Record<string, string> }
export interface VerifyState { text: string; busy: boolean }
interface Store { slots: Record<Slot, SlotState>; verify: Record<Slot, VerifyState> }

let store: Store = {
  slots: { explore: { phase: "idle" }, attack: { phase: "idle" }, retest: { phase: "idle" } },
  verify: { explore: { text: "", busy: false }, attack: { text: "", busy: false }, retest: { text: "", busy: false } },
};
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
const subscribe = (cb: () => void) => { listeners.add(cb); return () => { listeners.delete(cb); }; };
const snapshot = () => store;

function setSlot(slot: Slot, patch: Partial<SlotState>) { store = { ...store, slots: { ...store.slots, [slot]: { ...store.slots[slot], ...patch } } }; emit(); }
function setVerify(slot: Slot, patch: Partial<VerifyState>) { store = { ...store, verify: { ...store.verify, [slot]: { ...store.verify[slot], ...patch } } }; emit(); }

export const useSlot = (slot: Slot): SlotState => useSyncExternalStore(subscribe, snapshot).slots[slot];
export const useVerify = (slot: Slot): VerifyState => useSyncExternalStore(subscribe, snapshot).verify[slot];
export const useViews = () => useSyncExternalStore(subscribe, snapshot).slots;

const timers: Partial<Record<Slot, number>> = {};
const stopped = new Set<Slot>();
const lastLaunch: Partial<Record<Slot, { application: Record<string, string>; posture: Posture }>> = {};

function forget(slot: Slot, message: string) {
  window.clearTimeout(timers[slot]);
  updateMission((s) => {
    const runs = { ...s.runs }, launched = { ...s.launched }, runDone = { ...s.runDone };
    delete runs[slot]; delete launched[slot]; delete runDone[slot];
    return { ...s, runs, launched, runDone };
  });
  setSlot(slot, { phase: "idle", view: undefined, message });
}

function poll(slot: Slot, runId: string, started: number) {
  stopped.delete(slot);
  const tick = async (tries: number) => {
    if (stopped.has(slot)) return;
    const res = await api<RunView>(`/api/missions/loan-desk/runs/${encodeURIComponent(runId)}`);
    if (stopped.has(slot)) return;
    if (!res.ok) {
      if (res.status === 404) { forget(slot, "That run no longer exists (the Attack Service or AcmeBank was restarted). Launch it again."); return; }
      if (tries < 6) {
        setSlot(slot, { message: `${problemText(res)} Retrying (${tries + 1} of 6)…` });
        timers[slot] = window.setTimeout(() => tick(tries + 1), Math.min(8000, 1000 * (tries + 1)));
      } else setSlot(slot, { phase: "error", message: `Disconnected. ${problemText(res)}` });
      return;
    }
    const view = res.data;
    if (view.status === "RUNNING") {
      if (Date.now() - started > POLL_MAX_MS) {
        setSlot(slot, { view, phase: "stopped", message: `This is taking longer than expected (over ${POLL_MAX_MS / 1000} s). The run may still finish; use Keep waiting.` });
        return;
      }
      setSlot(slot, { view, phase: "running", message: tries > 0 ? "Connection restored." : undefined });
      timers[slot] = window.setTimeout(() => tick(0), POLL_MS);
    } else {
      updateMission((s) => ({ ...s, runDone: { ...s.runDone, [slot]: true } }));
      setSlot(slot, { view, phase: "idle", message: tries > 0 ? "Connection restored." : undefined });
    }
  };
  tick(0);
}

export function stopWaiting(slot: Slot) {
  stopped.add(slot); window.clearTimeout(timers[slot]);
  setSlot(slot, { phase: "stopped", message: "Stopped waiting. The run continues inside AcmeBank." });
}
export function keepWaiting(slot: Slot) {
  const id = getMission().runs[slot];
  if (id) { setSlot(slot, { phase: "running", message: undefined }); poll(slot, id, Date.now()); }
}

export async function launch(slot: Slot, application: Record<string, string>, posture: Posture) {
  const now = store.slots[slot].phase;
  if (now === "submitting" || now === "running") return;
  lastLaunch[slot] = { application, posture };
  setSlot(slot, { phase: "submitting", view: undefined, message: undefined, fieldErrors: undefined });
  const res = await post("/api/missions/loan-desk/runs", { application, posture });
  if (res.status === 202) {
    updateMission((s) => ({ ...s, runs: { ...s.runs, [slot]: res.data.run_id }, launched: { ...s.launched, [slot]: new Date().toISOString() }, runDone: { ...s.runDone, [slot]: false } }));
    markProgress("in_progress");
    setSlot(slot, { phase: "running", view: res.data });
    poll(slot, res.data.run_id, Date.now());
    return;
  }
  if (res.status === 400 && res.data?.errors) { setSlot(slot, { phase: "idle", fieldErrors: res.data.errors, message: "The application was not accepted. Nothing ran." }); return; }
  setSlot(slot, { phase: "error", message: `${problemText(res)} Nothing ran.` });
}
export const retryLaunch = (slot: Slot) => { const l = lastLaunch[slot]; if (l) launch(slot, l.application, l.posture); };

let adopted = false;
/** After a refresh or a new tab: re-read every stored run from the service (never trust a stored view). */
export async function adoptRuns() {
  if (adopted) return; adopted = true;
  await Promise.all(SLOTS.map(async (slot) => {
    const id = getMission().runs[slot]; if (!id) return;
    const res = await api<RunView>(`/api/missions/loan-desk/runs/${encodeURIComponent(id)}`);
    if (res.ok) {
      const running = res.data.status === "RUNNING";
      if (!running) updateMission((s) => ({ ...s, runDone: { ...s.runDone, [slot]: true } }));
      setSlot(slot, { view: res.data, phase: running ? "running" : "idle" });
      if (running) poll(slot, id, Date.now());
    } else if (res.status === 404) forget(slot, "That run no longer exists (the Attack Service or AcmeBank was restarted). Launch it again.");
  }));
}

/** Ask the host verifier to check a run, then poll until the status settles. The page never holds a Splunk credential. */
export async function verifyRun(slot: Slot) {
  const id = getMission().runs[slot];
  if (!id) { setVerify(slot, { text: "Launch the run first.", busy: false }); return; }
  setVerify(slot, { busy: true, text: "Requesting verification…" });
  const res = await post(`/api/missions/loan-desk/runs/${encodeURIComponent(id)}/verify`, {});
  if (res.status === 503) { setVerify(slot, { busy: false, text: "NOT VERIFIED. The verifier is not installed on this lab (no bridge key). Evidence stays local-only; use the Splunk searches." }); return; }
  if (res.status === 404) { setVerify(slot, { busy: false, text: "This run is no longer known to the Loan Desk. Launch it again." }); return; }
  if (res.status !== 202 && res.status !== 429) { setVerify(slot, { busy: false, text: problemText(res) }); return; }
  const t0 = Date.now();
  for (;;) {
    const r = await api<RunView>(`/api/missions/loan-desk/runs/${encodeURIComponent(id)}`);
    if (!r.ok) { setVerify(slot, { busy: false, text: `${problemText(r)} Press Verify to try again.` }); return; }
    setSlot(slot, { view: r.data });
    const st = r.data.evidence.indexed_status;
    setVerify(slot, { text: evidenceText(r.data) + (st === "PENDING" ? ` (${Math.round((Date.now() - t0) / 1000)} s)` : "") });
    if (st === "PENDING" && Date.now() - t0 < 160000) await new Promise((ok) => window.setTimeout(ok, 2000)); else break;
  }
  setVerify(slot, { busy: false });
}

export function resetRuns() {
  SLOTS.forEach((slot) => { stopped.add(slot); window.clearTimeout(timers[slot]); });
  store = {
    slots: { explore: { phase: "idle" }, attack: { phase: "idle" }, retest: { phase: "idle" } },
    verify: { explore: { text: "", busy: false }, attack: { text: "", busy: false }, retest: { text: "", busy: false } },
  };
  emit();
}
