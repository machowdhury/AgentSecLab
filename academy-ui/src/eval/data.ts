import { useEffect, useState } from "react";
import type { EvalIndex, Experiment } from "./types";

// Evaluation evidence is large, so every file is fetched only when its view opens; none of it is in the main bundle.
const FILES = import.meta.glob<{ default: unknown }>("../content/evals/*.json");
const cache = new Map<string, Promise<unknown>>();
const load = <T,>(name: string): Promise<T> => {
  const key = `../content/evals/${name}.json`;
  if (!cache.has(key)) { const l = FILES[key]; cache.set(key, l ? l().then((m) => m.default) : Promise.reject(new Error(`no ${name}`))); }
  return cache.get(key) as Promise<T>;
};
export type Loaded<T> = { data?: T; err?: boolean };
function useLoaded<T>(name: string | null): Loaded<T> {
  const [s, setS] = useState<Loaded<T>>({});
  useEffect(() => { let live = true; setS({}); if (name) load<T>(name).then((data) => live && setS({ data }), () => live && setS({ err: true })); return () => { live = false; }; }, [name]);
  return s;
}
export const useIndex = () => useLoaded<EvalIndex>("index");
export const useExperiment = (id: string | null) => useLoaded<Experiment>(id ? `exp-${id}` : null);
export const loadExperiment = (id: string) => load<Experiment>(`exp-${id}`);
