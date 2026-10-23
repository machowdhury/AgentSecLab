import { useSyncExternalStore } from "react";
import type { Posture, Slot } from "./types";
import { STAGES, type StageId } from "./stages";

// The learner's mission state lives in this browser only (it never reaches the request payload and never counts as evidence).
// Run ids are real ids returned by the Loan Desk; their views are always re-fetched from the service, never stored.
const KEY = "agentsec.learn.v1";
const LEGACY_PROGRESS = "agentsec.academy.progress.v1"; // the classic Learning Path reads this marker
export const LAB_ID = "LAB-LOANDESK-001";

/** What the learner did in one notebook cell. Only facts returned by a real search are recorded here; nothing is composed for the learner. */
export interface NotebookRan { at: string; runs: string[]; spl: string; rows: number; preview: string[]; changed: string[]; truncated: boolean }
export interface NotebookEntry { params?: Record<string, string | number>; scratch?: string; note?: string; ran?: NotebookRan }

export interface MissionState {
  v: 1;
  seen: StageId[];
  prediction: { follow?: string; decision?: string; queue?: string; locked?: boolean };
  runs: Partial<Record<Slot, string>>;
  launched: Partial<Record<Slot, string>>;
  runDone: Partial<Record<Slot, boolean>>;
  posture: Posture;
  defenseApplied: boolean;
  attackNotes?: string;
  notebook?: Record<string, NotebookEntry>;
  foundationsRead?: string[];
  workbench?: Record<string, { prediction?: { decision?: string; llm?: string; classify?: string; handler?: string; locked?: boolean }; runs?: Partial<Record<"baseline" | "attack" | "retest", string>> }>;
  mcp?: { prediction?: string; locked?: boolean; attack?: string; retest?: string };
  mastery?: { mcq?: Record<string, string>; written?: Record<string, { text: string; revealed?: boolean; verdict?: "covered" | "partly" | "not_yet" }> };
  application?: Record<string, string>;
  completed: boolean;
}

const fresh = (): MissionState => ({ v: 1, seen: [], prediction: {}, runs: {}, launched: {}, runDone: {}, posture: "baseline", defenseApplied: false, completed: false });

function read(): MissionState {
  try {
    const raw = JSON.parse(window.localStorage.getItem(KEY) || "null");
    if (raw && raw.v === 1) return { ...fresh(), ...raw };
  } catch { /* storage unavailable or damaged: start fresh */ }
  return fresh();
}

let state = read();
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
window.addEventListener("storage", (e) => { if (e.key === KEY) { state = read(); emit(); } }); // another tab changed it

export const getMission = () => state;
export function updateMission(change: (s: MissionState) => MissionState): void {
  state = change(state);
  try { window.localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* convenience only */ }
  emit();
}
export function useMission(): MissionState {
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => { listeners.delete(cb); }; }, getMission, getMission);
}

export function resetMission(): void {
  updateMission(() => fresh());
  markProgress("not_started");
}

/** Mirror coarse progress into the marker the classic Learning Path reads ("in_progress" never downgrades "workflow_complete"). */
export function markProgress(value: "in_progress" | "workflow_complete" | "not_started"): void {
  try {
    const all = JSON.parse(window.localStorage.getItem(LEGACY_PROGRESS) || "null") || {};
    if (value === "not_started") delete all[LAB_ID];
    else if (!(all[LAB_ID]?.state === "workflow_complete" && value === "in_progress")) all[LAB_ID] = { state: value, updated: new Date().toISOString() };
    window.localStorage.setItem(LEGACY_PROGRESS, JSON.stringify(all));
  } catch { /* convenience only */ }
}

export function markSeen(stage: StageId): void {
  if (!state.seen.includes(stage)) updateMission((s) => ({ ...s, seen: [...s.seen, stage] }));
}

/** A stage is complete when the learner has produced its real result. */
export function stageComplete(stage: StageId, s: MissionState): boolean {
  switch (stage) {
    case "learn": return s.seen.includes("learn");
    case "prepare": return Boolean(s.prediction.locked);
    case "attack": return Boolean(s.runDone.attack);
    case "investigate": return Boolean(s.runDone.attack) && s.seen.includes("investigate");
    case "defend": return s.defenseApplied;
    case "retest": return Boolean(s.runDone.retest);
    case "explain": return s.completed;
  }
}

/** Why a stage is locked (empty string when open). Same rules as the original ten-step mission. */
export function gateReason(stage: StageId, s: MissionState): string {
  if (stage === "attack" && !s.prediction.locked) return "Lock your prediction on the Prepare stage first.";
  if ((stage === "investigate" || stage === "defend") && !s.runs.attack) return "Launch the attack first.";
  if (stage === "retest" && !s.defenseApplied) return "Apply the defense on the Defend stage first.";
  if (stage === "explain" && !(s.runDone.attack && s.runDone.retest)) return "Finish both the Attack and the Retest runs first.";
  return "";
}

export const firstOpenIncomplete = (s: MissionState): StageId =>
  (STAGES.map((x) => x.id).find((id) => !stageComplete(id, s) && !gateReason(id, s)) ?? "explain") as StageId;
