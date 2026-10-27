import type { ReactNode } from "react";
import { Link } from "./router";

// Shared building blocks copied verbatim from the supplied Figma export (src/App.tsx), so the look matches.

export type IconName = "home" | "path" | "book" | "shield" | "search" | "target" | "chart" | "status" | "help" | "menu" | "arrow" | "check" | "clock" | "copy" | "play" | "terminal" | "chevron";

const icons: Record<IconName, ReactNode> = {
  home: <><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9v11h14V9M9 20v-6h6v6"/></>,
  path: <><circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 18h2a4 4 0 0 0 4-4v-4a4 4 0 0 1 4-4"/></>,
  book: <><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H11v16H6.5A2.5 2.5 0 0 0 4 21.5z"/><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H13v16h4.5a2.5 2.5 0 0 1 2.5 2.5z"/></>,
  shield: <path d="M12 3 4.5 6v5.5c0 4.7 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.8 7.5-9.5V6z"/>,
  search: <><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/></>,
  target: <><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3m9 6h-3m-6 9v-3M3 12h3"/></>,
  chart: <><path d="M4 20V10m6 10V4m6 16v-7m5 7H2"/></>,
  status: <><circle cx="12" cy="12" r="9"/><path d="M8 12h2l1.5-4 2.5 8 1.5-4H18"/></>,
  help: <><circle cx="12" cy="12" r="9"/><path d="M9.7 9a2.5 2.5 0 1 1 3.5 2.3c-.8.4-1.2.9-1.2 1.7m0 4h.01"/></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16"/></>,
  arrow: <><path d="M5 12h14m-5-5 5 5-5 5"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  copy: <><rect x="8" y="8" width="11" height="11" rx="1"/><path d="M16 8V5H5v11h3"/></>,
  play: <path d="m8 5 11 7-11 7z"/>,
  terminal: <><path d="m5 7 4 4-4 4m7 1h7"/></>,
  chevron: <path d="m9 6 6 6-6 6"/>,
};

export function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  return <svg aria-hidden="true" className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{icons[name]}</svg>;
}

export function Button({ children, onClick, variant = "primary", icon, disabled = false }: { children: ReactNode; onClick?: () => void; variant?: "primary" | "secondary" | "ghost"; icon?: IconName; disabled?: boolean }) {
  return <button className={`button button--${variant}`} onClick={onClick} disabled={disabled}>{children}{icon && <Icon name={icon} size={17}/>}</button>;
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "live" | "replay" | "recorded" | "replayed" | "simulated" | "unverified" | "allow" | "deny" | "observed" | "muted" | "indexed" | "good" | "low" | "medium" | "high" | "critical" | "warning" | "neutral" }) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function ProgressBar({ value }: { value: number }) {
  return <div className="progress" role="progressbar" aria-label="Mission progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value}><span style={{ width: `${value}%` }}/></div>;
}

export function LinkButton({ href, children, variant = "primary", icon, external = false, internal = false }: { href: string; children: ReactNode; variant?: "primary" | "secondary" | "ghost"; icon?: IconName; external?: boolean; internal?: boolean }) {
  const cls = `button button--${variant}`;
  const inner = <>{children}{icon && <Icon name={icon} size={17}/>}</>;
  if (internal) return <Link to={href} className={cls}>{inner}</Link>;
  return <a className={cls} href={href} {...(external ? { target: "_blank", rel: "noopener" } : {})}>{inner}</a>;
}

export function FactCard({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: "allow" | "observed" | "deny" | "muted" }) {
  return <div className={`fact-card fact-card--${tone}`}><span>{label}</span><div><Badge tone={tone}>{value}</Badge></div><p>{detail}</p></div>;
}
