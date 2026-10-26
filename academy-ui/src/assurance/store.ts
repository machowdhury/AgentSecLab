import { useSyncExternalStore } from "react";
import type { StepId } from "./types";

// Workshop progress lives in this browser only. It records what the learner did, never evidence, and one button clears it.
const KEY = "agentsec.assurance.v1";
export interface Progress { v: 1; seen: StepId[]; practiceConfirmed: boolean; answers: Record<string, { picked: string[]; checked: boolean }> }
const fresh = (): Progress => ({ v: 1, seen: [], practiceConfirmed: false, answers: {} });

function read(): Progress {
  try {
    const raw = JSON.parse(window.localStorage.getItem(KEY) || "null");
    if (raw && raw.v === 1) return { ...fresh(), ...raw };
  } catch { /* storage unavailable or damaged: start fresh */ }
  return fresh();
}

let state = read();
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
window.addEventListener("storage", (e) => { if (e.key === KEY) { state = read(); emit(); } });

export function update(change: (p: Progress) => Progress): void {
  state = change(state);
  try { window.localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* convenience only */ }
  emit();
}
export const useProgress = () => useSyncExternalStore((cb) => { listeners.add(cb); return () => { listeners.delete(cb); }; }, () => state, () => state);
export const markSeen = (s: StepId) => update((p) => p.seen.includes(s) ? p : { ...p, seen: [...p.seen, s] });
export const resetWorkshop = () => update(() => fresh());
export const setAnswer = (id: string, a: { picked: string[]; checked: boolean }) => update((p) => ({ ...p, answers: { ...p.answers, [id]: a } }));
export const checked = (p: Progress, id: string) => Boolean(p.answers[id]?.checked);

/** A step is complete when its own work is done: reading steps once seen, exercise steps once every exercise is checked. */
export function complete(step: StepId, p: Progress, exerciseIds: string[]): boolean {
  if (step === "practice") return p.practiceConfirmed;
  if (step === "evaluate" || step === "risk" || step === "controls") return exerciseIds.length > 0 && exerciseIds.every((i) => checked(p, i));
  return p.seen.includes(step);
}
