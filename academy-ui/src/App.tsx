import { ConfigProvider } from "./config";
import { AppShell } from "./shell";
import { WorkshopFlow } from "./WorkshopFlow";
import { matchRoute, missionPath, navigate, usePath } from "./router";
import { Home } from "./pages/Home";
import { Mission } from "./pages/Mission";
import { Suspense, lazy, useEffect } from "react";
import { Foundations } from "./pages/Foundations";
import { Mastery } from "./pages/Mastery";
import { Mcp } from "./pages/Mcp";
import { Curriculum } from "./pages/Curriculum";
import { Challenges } from "./pages/Challenges";
import { LabPage } from "./pages/Lab";
import { labById } from "./curriculum";
import { Path } from "./pages/Path";
import { AssuranceHub, AssuranceJourney } from "./pages/Assurance";

// The EVAL Center is its own chunk: opening it is the only thing that downloads its code.
const EvalCenter = lazy(() => import("./pages/EvalCenter"));
const RiskCenter = lazy(() => import("./pages/RiskCenter"));
const Governance = lazy(() => import("./pages/Governance"));
import { STAGES } from "./stages";

function NotFound() {
  return <div className="page"><header className="page-header"><div><div className="eyebrow">Not found</div><h1>That page does not exist</h1><p>Use the sidebar, or <a href="/learn">return to the Academy home</a>.</p></div></header></div>;
}

export default function App() {
  const path = usePath();
  const route = matchRoute(path);
  useEffect(() => { if (route.name === "acmebank") navigate(missionPath("prepare"), { replace: true }); }, [route.name]);  // the standalone AcmeBank page is now the Prepare stage
  const crumbs = route.name === "governance" ? ["Governance Center"] : route.name === "risk" ? ["Risk Center"] : route.name === "evals" ? ["EVAL Center"] : route.name === "assurance" ? (route.step === "hub" ? ["Security Assurance"] : ["Security Assurance", "Workshop"]) : route.name === "home" ? ["Home"] : route.name === "path" ? ["Your Path"] : route.name === "foundations" ? ["AI & Agent Foundations"] : route.name === "mastery" ? ["Mastery"] : route.name === "mcp" ? ["MCP Tool Authorization"] : route.name === "curriculum" ? ["Curriculum Explorer"] : route.name === "lab" ? ["Curriculum Explorer", labById(route.id)?.title ?? route.id] : route.name === "acmebank" ? ["Loan Desk mission", "Prepare"] : route.name === "mission" ? ["Loan Desk mission", ...(route.stage ? [STAGES.find((s) => s.id === route.stage)!.label] : [])] : ["Not found"];
  return <ConfigProvider><AppShell path={path} crumbs={crumbs}>
    {["governance", "risk", "evals", "mission", "lab", "curriculum"].includes(route.name) && <WorkshopFlow path={path} />}
    {route.name === "home" && <Home />}
    {route.name === "path" && <Path />}
    {route.name === "foundations" && <Foundations />}
    {route.name === "mastery" && <Mastery />}
    {route.name === "mcp" && <Mcp />}
    {route.name === "curriculum" && <Curriculum />}
    {route.name === "challenges" && <Challenges />}
    {route.name === "lab" && <LabPage id={route.id} />}
    {route.name === "mission" && <Mission stage={route.stage} />}
    {route.name === "governance" && <Suspense fallback={<div className="page"><div className="m-sec" role="status"><p className="m-muted">Loading the Governance Center…</p></div></div>}><Governance view={route.view} /></Suspense>}
    {route.name === "risk" && <Suspense fallback={<div className="page"><div className="m-sec" role="status"><p className="m-muted">Loading the Risk Center…</p></div></div>}><RiskCenter route={route} /></Suspense>}
    {route.name === "evals" && <Suspense fallback={<div className="page"><div className="m-sec" role="status"><p className="m-muted">Loading the EVAL Center…</p></div></div>}><EvalCenter view={route.view} id={route.id} /></Suspense>}
    {route.name === "assurance" && (route.step === "hub" ? <AssuranceHub /> : <AssuranceJourney step={route.step} />)}
    {route.name === "missing" && <NotFound />}
  </AppShell></ConfigProvider>;
}
