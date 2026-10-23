import { ConfigProvider } from "./config";
import { AppShell } from "./shell";
import { matchRoute, missionPath, navigate, usePath } from "./router";
import { Home } from "./pages/Home";
import { Mission } from "./pages/Mission";
import { useEffect } from "react";
import { Foundations } from "./pages/Foundations";
import { Mastery } from "./pages/Mastery";
import { Mcp } from "./pages/Mcp";
import { Curriculum } from "./pages/Curriculum";
import { LabPage } from "./pages/Lab";
import { labById } from "./curriculum";
import { Path } from "./pages/Path";
import { STAGES } from "./stages";

function NotFound() {
  return <div className="page"><header className="page-header"><div><div className="eyebrow">Not found</div><h1>That page does not exist</h1><p>Use the sidebar, or <a href="/learn">return to the Academy home</a>.</p></div></header></div>;
}

export default function App() {
  const path = usePath();
  const route = matchRoute(path);
  useEffect(() => { if (route.name === "acmebank") navigate(missionPath("prepare"), { replace: true }); }, [route.name]);  // the standalone AcmeBank page is now the Prepare stage
  const crumbs = route.name === "home" ? ["Home"] : route.name === "path" ? ["Your Path"] : route.name === "foundations" ? ["AI & Agent Foundations"] : route.name === "mastery" ? ["Mastery"] : route.name === "mcp" ? ["MCP Tool Authorization"] : route.name === "curriculum" ? ["Curriculum Explorer"] : route.name === "lab" ? ["Curriculum Explorer", labById(route.id)?.title ?? route.id] : route.name === "acmebank" ? ["Loan Desk mission", "Prepare"] : route.name === "mission" ? ["Loan Desk mission", ...(route.stage ? [STAGES.find((s) => s.id === route.stage)!.label] : [])] : ["Not found"];
  return <ConfigProvider><AppShell path={path} crumbs={crumbs}>
    {route.name === "home" && <Home />}
    {route.name === "path" && <Path />}
    {route.name === "foundations" && <Foundations />}
    {route.name === "mastery" && <Mastery />}
    {route.name === "mcp" && <Mcp />}
    {route.name === "curriculum" && <Curriculum />}
    {route.name === "lab" && <LabPage id={route.id} />}
    {route.name === "mission" && <Mission stage={route.stage} />}
    {route.name === "missing" && <NotFound />}
  </AppShell></ConfigProvider>;
}
