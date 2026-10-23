import { useEffect, useState, type ReactNode } from "react";
import { Badge, Icon, type IconName } from "./ui";
import { Link, missionPath, ACMEBANK_PATH, BASE } from "./router";
import { useConfig, useEnvironment } from "./config";

type Item = { label: string; icon: IconName; to?: string; href?: string; splunk?: string; tag?: string };
type Group = { label: string; items: Item[] };

// Sections follow the Figma navigation. Entries without a React screen yet open their existing, working page.
const groups: Group[] = [
  { label: "", items: [{ label: "Home", icon: "home", to: BASE }, { label: "Your Path", icon: "path", href: "/academy/path", tag: "Classic" }] },
  { label: "Learn", items: [
    { label: "AI & Agent Foundations", icon: "book", href: "/academy/foundations", tag: "Classic" },
    { label: "Loan Desk Mission", icon: "target", to: missionPath() },
    { label: "MCP Tool Authorization", icon: "shield", href: "/academy/labs/LAB-MCP-001", tag: "Classic" },
  ] },
  { label: "Practice", items: [
    { label: "AcmeBank Loan Application", icon: "home", to: ACMEBANK_PATH },
    { label: "Attack Workbench", icon: "terminal", to: missionPath("attack") },
  ] },
  { label: "Assess", items: [
    { label: "Mastery", icon: "chart", splunk: "/en-US/app/agentsec/ws_agentsec_mastery" },
    { label: "Arena", icon: "target", splunk: "/en-US/app/agentsec/ws_agentsec_arena" },
  ] },
  { label: "Investigate", items: [{ label: "Search", icon: "search", splunk: "/en-US/app/search/search" }] },
];

const activeFor = (item: Item, path: string) => Boolean(item.to) && item.label !== "Attack Workbench" && (item.to === BASE ? path.replace(/\/$/, "") === BASE : path.startsWith(item.to!));

function NavItem({ item, path, collapsed, splunkWeb }: { item: Item; path: string; collapsed: boolean; splunkWeb: string }) {
  const cls = `nav-item ${activeFor(item, path) ? "nav-item--active" : ""}`;
  const body = <><Icon name={item.icon} />{!collapsed && <span>{item.label}</span>}</>;
  if (item.to) return <Link to={item.to} className={cls} aria-label={item.label} title={collapsed ? item.label : item.tag ? `${item.label} (${item.tag.toLowerCase()} page)` : undefined} aria-current={activeFor(item, path) ? "page" : undefined}>{body}</Link>;
  if (item.splunk) return <a className={cls} aria-label={`${item.label} (opens Splunk in a new tab)`} href={`${splunkWeb}${item.splunk}`} target="_blank" rel="noopener" title={collapsed ? item.label : `${item.label} (opens Splunk in a new tab)`}>{body}{!collapsed && <span className="nav-ext" aria-hidden="true">↗</span>}</a>;
  return <a className={cls} aria-label={item.label} href={item.href} title={collapsed ? item.label : item.tag ? `${item.label} (opens the ${item.tag.toLowerCase()} Academy page)` : undefined}>{body}</a>;
}

export function Sidebar({ path, collapsed, setCollapsed, open }: { path: string; collapsed: boolean; setCollapsed: (v: boolean) => void; open: boolean }) {
  const { config } = useConfig();
  return <aside id="primary-nav" aria-label="Sidebar" className={`sidebar ${collapsed ? "sidebar--collapsed" : ""} ${open ? "sidebar--drawer" : ""}`}>
    <div className="brand">
      <div className="brand__mark"><span>A</span></div>
      {!collapsed && <div><strong>AgentSec</strong><small>Security Academy</small></div>}
      <button className="icon-button collapse" aria-label="Toggle sidebar" aria-expanded={!collapsed} onClick={() => setCollapsed(!collapsed)}><Icon name="menu" /></button>
    </div>
    <nav aria-label="Primary navigation">
      {groups.map((group, gi) => <div className="nav-group" key={gi}>
        {!collapsed && group.label && <div className="nav-label">{group.label}</div>}
        {group.items.map((item) => <NavItem key={item.label} item={item} path={path} collapsed={collapsed} splunkWeb={config.urls.splunk_web} />)}
      </div>)}
    </nav>
    <div className="sidebar__footer">
      <a className="nav-item" aria-label="System Status" href="/academy/status" title="System Status (opens the classic Academy page)"><Icon name="status" />{!collapsed && <span>System Status</span>}</a>
    </div>
  </aside>;
}

export function Topbar({ crumbs, menuOpen, toggleMenu }: { crumbs: ReactNode[]; menuOpen: boolean; toggleMenu: () => void }) {
  const env = useEnvironment();
  return <header className="topbar">
    <button type="button" className="icon-button menu-toggle" aria-label="Open navigation menu" aria-expanded={menuOpen} aria-controls="primary-nav" onClick={toggleMenu}><Icon name="menu" /></button>
    <nav className="breadcrumb" aria-label="Breadcrumb">
      <Link to={BASE}>Academy</Link>
      {crumbs.map((c, i) => <span className="breadcrumb__part" key={i}><Icon name="chevron" size={15} />{i === crumbs.length - 1 ? <strong aria-current="page">{c}</strong> : c}</span>)}
    </nav>
    <div className="topbar__actions">
      {env.level === "ready" && <Badge tone="live"><span className="pulse" /> LIVE ENVIRONMENT</Badge>}
      {env.level === "attention" && <Badge tone="warning">CHECK ENVIRONMENT</Badge>}
      {env.level === "checking" && <Badge tone="muted">CHECKING…</Badge>}
      <span className="visually-hidden" role="status">{env.detail}</span>
      <a className="icon-button" href="/academy/status" aria-label="Environment status and help" title={env.detail}><Icon name="help" /></a>
    </div>
  </header>;
}

export function AppShell({ path, crumbs, children }: { path: string; crumbs: ReactNode[]; children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => { setMenuOpen(false); }, [path]); // navigating closes the drawer
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);
  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to main content</a>
    <Sidebar path={path} collapsed={collapsed} setCollapsed={setCollapsed} open={menuOpen} />
    {menuOpen && <div className="drawer-backdrop" onClick={() => setMenuOpen(false)} aria-hidden="true" />}
    <div className="app-main"><Topbar crumbs={crumbs} menuOpen={menuOpen} toggleMenu={() => setMenuOpen((v) => !v)} /><main id="main" tabIndex={-1}>{children}</main></div>
  </div>;
}
