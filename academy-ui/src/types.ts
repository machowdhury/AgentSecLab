export type Posture = "baseline" | "hardened";
export type RunStatus = "RUNNING" | "COMPLETED" | "INCOMPLETE" | "FAILED";
export type Slot = "explore" | "attack" | "retest";

export interface ToolCall { step: number; tool: string; decision: "ALLOW" | "DENY"; reason: string; executed: boolean }
export interface RunStep {
  step: number; kind: string;
  proposal?: { tool: string; source: string; arguments?: Record<string, unknown> };
  decision?: { decision: string; reason: string };
  recommendation?: string; summary?: string;
}
export interface Ticket { ticket_id: string; applicant_id: string; note: string }
export interface Blocked { step: number; tool: string; reason: string; executed: boolean }
export interface Outcomes {
  security: { outcome: string; blocked: Blocked[]; rejected_malformed?: Blocked[] };
  business: { outcome: string; reason: string | null };
  operations: { proposed: number; authorized: number; denied: number; executed: number; denied_but_executed: number; policy_denied?: number; rejected_malformed?: number };
}
export interface Evidence {
  run_id: string; event_count: number; indexed_status: string; splunk_search: string;
  splunk?: { status?: string; detail?: string; checked_at?: string; indexed_events?: number; local_events?: number; problems?: string[] };
}
export interface RunView {
  run_id: string; applicant_id: string; posture: Posture; status: RunStatus; stop_reason: string | null; error: string | null;
  application: Record<string, string>;
  model: { name: string; provider: string; proposal_source: string; identity?: { digest?: string; parameter_size?: string; quantization?: string } };
  steps: RunStep[]; tickets: Ticket[]; queue_harm: { tickets_with_applicant_text: string[] };
  outcomes?: Outcomes; timeline?: { tool_calls: ToolCall[]; events?: unknown[] };
  evidence: Evidence;
  advisory?: { summary: string; unsupported_figures?: string[] } | null;
}
