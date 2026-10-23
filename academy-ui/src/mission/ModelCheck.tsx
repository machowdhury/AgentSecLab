import { useCallback, useEffect, useState } from "react";
import { api, problemText } from "../api";
import { Button } from "../ui";
import { Callout, CopyButton } from "./parts";

interface Readiness { model: string; ollama_reachable: boolean; model_installed: boolean; fix?: { note?: string; command?: string; where?: string } }
interface Status { available: boolean; model: string; reason?: string; proposal_source?: string; identity?: { digest?: string; parameter_size?: string; quantization?: string }; readiness?: Readiness }
type State = { phase: "checking" } | { phase: "unreachable"; text: string } | { phase: "ok"; status: Status };

/** First-run check: which real model drives the agent, and whether it is ready. It never downloads anything. */
export function useModelStatus() {
  const [state, setState] = useState<State>({ phase: "checking" });
  const check = useCallback(() => {
    setState({ phase: "checking" });
    api<Status>("/api/missions/loan-desk/status").then((r) => setState(r.ok ? { phase: "ok", status: r.data } : { phase: "unreachable", text: problemText(r) }));
  }, []);
  useEffect(check, [check]);
  return { state, check };
}

export function ModelCheck() {
  const { state, check } = useModelStatus();
  if (state.phase === "checking") return <p className="m-muted" role="status">Checking model…</p>;
  if (state.phase === "unreachable") return <>
    <Callout kind="warn" role="alert">{state.text}</Callout>
    <p>The Loan Desk is not reachable, so no run can start.</p>
    <Button variant="ghost" onClick={check}>Check again</Button>
  </>;
  const d = state.status; const id = d.identity ?? {}; const rd = d.readiness;
  return <div className="m-model">
    {d.available
      ? <p><strong>Model {d.model} via Ollama</strong>{id.digest ? `, digest ${id.digest.slice(0, 12)}` : ""}{id.parameter_size ? `, ${id.parameter_size} ${id.quantization ?? ""}` : ""}. Proposals come from real inference ({d.proposal_source}).</p>
      : <><Callout kind="warn" role="alert">Model unavailable: {d.reason ?? "unknown"} A run would fail visibly and no tool would run.</Callout><p>Model {d.model} is unavailable.</p></>}
    {rd && <div className="m-readiness">
      <h4>First-run check</h4>
      <ul>
        <li className={rd.ollama_reachable ? "is-ok" : "is-bad"}>Ollama reachable from AcmeBank: <strong>{rd.ollama_reachable ? "Ready" : "Not ready"}</strong></li>
        <li className={rd.model_installed ? "is-ok" : "is-bad"}>Model {rd.model} installed: <strong>{rd.model_installed ? "Ready" : "Not ready"}</strong></li>
      </ul>
      {rd.fix && <div>
        <p>{rd.fix.note}</p>
        <p>Run this yourself {rd.fix.where}:</p>
        <p><code>{rd.fix.command}</code> {rd.fix.command && <CopyButton text={rd.fix.command} label="Copy command" />}</p>
      </div>}
    </div>}
    {!d.available && <Button variant="ghost" onClick={check}>Check again</Button>}
  </div>;
}
