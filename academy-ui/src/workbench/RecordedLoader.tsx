import { useEffect, useState } from "react";
import type { RecordedFile } from "../curriculum";
import { RecordedPractice, RecordedProve } from "./RecordedWorkbench";
import { InvestigationPractice, InvestigationProve } from "./InvestigationWorkbench";

// Large recorded evidence lives in its own file and is fetched only when its lab page opens, so it stays out of the main bundle.
const FILES = import.meta.glob<{ default: RecordedFile }>("../content/recorded/*.json");
const cache = new Map<string, Promise<RecordedFile>>();
const load = (file: string) => {
  const key = `../content/recorded/${file}`;
  if (!cache.has(key)) { const l = FILES[key]; cache.set(key, l ? l().then((m) => m.default) : Promise.reject(new Error(`no recorded file ${file}`))); }
  return cache.get(key)!;
};

function useRecorded(file: string) {
  const [s, setS] = useState<{ data?: RecordedFile; err?: boolean }>({});
  useEffect(() => { let live = true; setS({}); load(file).then((data) => live && setS({ data }), () => live && setS({ err: true })); return () => { live = false; }; }, [file]);
  return s;
}

export function LazyRecorded({ file, part }: { file: string; part: "practice" | "prove" }) {
  const { data, err } = useRecorded(file);
  if (err) return <div className="m-sec" role="alert"><p>The recorded evidence for this lab could not be loaded. Reload the page to try again.</p></div>;
  if (!data) return <div className="m-sec" role="status"><p className="m-muted">Loading the recorded evidence…</p></div>;
  if (data.kind === "investigation") return part === "practice" ? <InvestigationPractice inv={data} /> : <InvestigationProve inv={data} />;
  return part === "practice" ? <RecordedPractice rec={data} /> : <RecordedProve rec={data} />;
}
