// Mirrors scripts/eval_model.py. An experiment holds recorded test cases; a finding is derived from a case by a stated rule; nothing here is a rate or a score.
import type { EvidenceClass, Mapping, Quote, Source } from "../assurance/types";
export type CapStatus = "AVAILABLE_WITH_EVIDENCE" | "DOCUMENTED_ONLY" | "NOT_IMPLEMENTED";
export interface Verification { status: "NOT_VERIFIED" | "VERIFIED"; receipt: string | null }
export interface Decision { sequence: number; control: string; decision: string; reason: string; tool: string | null; requested_scope: string | null; requested_resource: string | null; agent: string | null }
export interface SplunkCopy { indexed: boolean; indexed_rows?: number; distinct_raw?: number; exact_raw_bytes?: number; pack_events?: number; identical?: boolean; note?: string }
export interface Case {
  id: string; role: string; title: string; evidence_class: EvidenceClass; kind: string; statement: string; facts: Record<string, any>; conditions: Record<string, unknown>; // eslint-disable-line @typescript-eslint/no-explicit-any
  expected: { documented: boolean; quote?: Quote }; sources: Source[]; verification: Verification; splunk_copy: SplunkCopy; limitations: string[]; timeline: Record<string, unknown>[];
}
export interface Comparison {
  kind: "attack_retest" | "scanner_vs_runtime"; reading?: string; limits: string[]; method?: string;
  roles?: string[]; rows: any[]; controlled_pair?: boolean; same_request_fields?: Record<string, boolean>; signature_has_value?: boolean; // eslint-disable-line @typescript-eslint/no-explicit-any
  same_request_check?: { control: string; nth_decision: number; attack: Record<string, unknown>; retest: Record<string, unknown>; fields_absent_in_both: string[] };
  also_reported?: Record<string, { attack: unknown; retest: unknown; equal: boolean }>; runtime_experiment?: string;
}
export interface Experiment {
  id: string; kind: string; category: string; lab_id: string; title: string; evidence_class: EvidenceClass; status: string; method: string;
  target: { description: string; agents: string[]; controls: string[] }; cases: Case[]; comparison: Comparison | null; comparison_unavailable?: string;
  mappings: Mapping[]; threat: { id: string; category: string; question: string; gap: string; residual_risk: string }; documentation: Source; limitations: string[]; findings: string[];
}
export interface Finding {
  id: string; rule: string; experiment: string; title: string; target: Record<string, unknown>; conditions: Record<string, unknown>; observed: string; expected: { documented: boolean; quote?: Quote };
  matches_documented: boolean | null; match_basis: string; evidence: string[]; sources: Source[]; verification: Verification; limitations: string[]; threat: string;
  severity: string; likelihood: string; impact: string; owner: string; remediation_status: string;
}
export interface Metric { id: string; label: string; numerator: number; denominator: number; unit: string; scope: string; derivation: string }
export interface Capability { id: string; title: string; status: CapStatus; experiments?: string[]; quote?: Quote; note?: string }
export interface Category { id: string; title: string; summary: string; capabilities: Capability[]; experiments: string[]; status: CapStatus; status_basis: string }
export interface ExpSummary { id: string; title: string; category: string; kind: string; evidence_class: EvidenceClass; status: string; lab_id: string; cases: number; case_roles: string[]; verified: number; findings: string[]; comparison: string | null; controlled_pair: boolean | null }
export interface EvalIndex {
  title: string; scope: string; categories: Category[]; experiments: ExpSummary[]; metrics: Metric[]; decisions_by_role: Record<string, Record<string, number>>;
  systems: { agents: { name: string; experiments: string[] }[]; controls: { id: string; experiments: string[] }[]; models: { name: string; experiments: string[] }[]; scanners: { name: string; version: string; experiments: string[] }[] };
  methods: { id: string; title: string; experiments: string[] }[]; findings: Finding[];
  gaps: { not_implemented: { category: string; capability: string; quote?: Quote; note?: string }[]; documented_only: { category: string; capability: string; quote: Quote }[]; no_verifier_receipt: { cases: number; statement: string };
          no_comparison: { experiment: string; reason: string }[]; no_framework_relationships: string[]; evidence_exists_but_not_included: string[]; unmatched_findings: string[] };
  demo: { experiment: string; steps: { title: string; text: string; to: string }[] };
}
export const STATUS_LABEL: Record<CapStatus, string> = { AVAILABLE_WITH_EVIDENCE: "AVAILABLE WITH EVIDENCE", DOCUMENTED_ONLY: "DOCUMENTED ONLY", NOT_IMPLEMENTED: "NOT IMPLEMENTED" };
export const RULES: Record<string, string> = {
  fail_open_allow_then_execution: "An ATTACK run in the vulnerable profile has a fail-open ALLOW decision followed by an executed handler or a started model call.",
  scanner_native_finding: "The scanner reported a native finding for the scanned artifact.",
};
