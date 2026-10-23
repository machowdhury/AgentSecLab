import { ConfigProvider } from "./config";
import { AppShell } from "./shell";
import { matchRoute, usePath } from "./router";
import { Home } from "./pages/Home";
import { Mission } from "./pages/Mission";
import { AcmeBank } from "./pages/AcmeBank";
import { STAGES } from "./stages";

function NotFound() {
  return <div className="page"><header className="page-header"><div><div className="eyebrow">Not found</div><h1>That page does not exist</h1><p>Use the sidebar, or <a href="/learn">return to the Academy home</a>.</p></div></header></div>;
}

export default function App() {
  const path = usePath();
  const route = matchRoute(path);
  const crumbs = route.name === "home" ? ["Home"] : route.name === "acmebank" ? ["AcmeBank loan application"] : route.name === "mission" ? ["Loan Desk mission", ...(route.stage ? [STAGES.find((s) => s.id === route.stage)!.label] : [])] : ["Not found"];
  return <ConfigProvider><AppShell path={path} crumbs={crumbs}>
    {route.name === "home" && <Home />}
    {route.name === "acmebank" && <AcmeBank />}
    {route.name === "mission" && <Mission stage={route.stage} />}
    {route.name === "missing" && <NotFound />}
  </AppShell></ConfigProvider>;
}
