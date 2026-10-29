import { useEffect, useState } from "react";
import { Badge } from "../ui";
import { StageGuide } from "../StageGuide";
import { api } from "../api";
import { useConfig } from "../config";

interface Challenge { id: string; title: string; difficulty: string; points: number; technique: string; objective: string; learning_outcome: string; simulation: string; simulation_note: string; status: string; scored: boolean }
interface Listing { challenges: Challenge[]; total: number; labels: Record<string, string> }

/** The three Advanced CTF challenges, read from the CTF service itself. The page links to the CTF; scoring, receipts and the ledger stay server-side there. */
export function Challenges() {
  const { config, loaded } = useConfig();
  const ctf = config.urls.ctf ?? null;
  const [data, setData] = useState<Listing | null | undefined>(undefined);
  // Ask the CTF only where the server says it can answer this browser: behind the gateway the route does not exist unless the CTF overlay is on.
  useEffect(() => { if (!loaded) return; if (!ctf) { setData(null); return; } api<Listing>("/api/ctf/challenges").then((r) => setData(r.ok ? r.data : null)); }, [loaded, ctf]);
  return <div className="page">
    <header className="page-header"><div>
      <div className="eyebrow">Advanced · Capture the flag</div>
      <h1>CTF Challenges</h1>
      <p>Three scored, server-verified challenges built on the MCP, memory and delegation labs. Success is decided on the server from the events the engine recorded, never from text you type. One local participant; not multi-user, not public hosting.</p>
    </div></header>
    <StageGuide learning="Each challenge is a short attack you run against a scripted simulation, then a server-side verification that issues a receipt you redeem once."
      todo={ctf ? "Open a challenge, run the baseline posture, verify, then redeem the receipt. The hardened posture shows the defense; it is not scored." : "Turn the CTF on first (see below), then come back."}
      happened="The challenge list below is read live from the CTF service."
      next="After a challenge, compare it with the matching workshop: Note Smuggler with Loan Desk, Poisoned Catalog with Tool Catalog, Confused Deputy with Confused Deputy (MCP-006)." />
    {data === undefined && <p className="m-muted" role="status">Loading the challenge list…</p>}
    {data === null && <div className="m-notice" role="note"><div><strong>The CTF is not reachable from this page</strong>
      <p>{config.gateway ? "Behind the HTTPS gateway the CTF is off by default. Turn it on with gateway.ctf in the installer (or scripts/gateway.sh ctf-enable and up), then reload." : "The CTF answers loopback browsers only: open the Academy at http://localhost:5001/learn."}</p></div></div>}
    {data && <><p className="m-muted">Score {data.total}. {Object.values(data.labels).join(" · ")}</p>
      <div className="m-grid">{data.challenges.map((c) => <section key={c.id} className="m-card" aria-label={c.title}>
        <h2>{c.title}</h2>
        <p><Badge tone="info">{c.difficulty.toUpperCase()}</Badge> <Badge tone="muted">{c.points} POINTS</Badge> <Badge tone="simulated">{c.simulation}</Badge> <Badge tone={c.scored ? "good" : "neutral"}>{c.status}</Badge></p>
        <p><strong>Technique.</strong> {c.technique}</p>
        <p><strong>Objective.</strong> {c.objective}</p>
        <p><strong>What you should learn.</strong> {c.learning_outcome}</p>
        <p className="m-muted">{c.simulation_note}</p>
        {ctf && <p><a className="button button--primary" href={`${ctf}/${c.id}`}>Open this challenge</a></p>}
      </section>)}</div></>}
  </div>;
}
