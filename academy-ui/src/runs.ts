import { useEffect, useState } from "react";
import { api } from "./api";
import type { RunView } from "./types";

/** Loads the real run view for each id from the service. null = the service no longer knows that run (for example after a restart). */
export function useRunViews(ids: string[]): Record<string, RunView | null> {
  const [views, setViews] = useState<Record<string, RunView | null>>({});
  const key = ids.join(",");
  useEffect(() => {
    let alive = true;
    ids.forEach((id) => {
      api<RunView>(`/api/missions/loan-desk/runs/${encodeURIComponent(id)}`).then((r) => { if (alive) setViews((v) => ({ ...v, [id]: r.ok ? r.data : null })); });
    });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return views;
}

export const reviewCall = (v: RunView) => v.timeline?.tool_calls.find((c) => c.tool === "submit_for_underwriter_review");
