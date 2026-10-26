// Mirrors scripts/assurance_model.py. Observations, assessments, framework mappings and compliance assertions are separate lists and are never merged into a score.
export type EvidenceClass = "LIVE" | "RECORDED" | "SIMULATED" | "DOCUMENTED";
export type Status = "SUPPORTED" | "PARTLY_SUPPORTED" | "NOT_SUPPORTED" | "NOT_ASSESSED";
export type StepId = "learn" | "practice" | "evaluate" | "risk" | "controls" | "prove";
export const STEP_IDS: StepId[] = ["learn", "practice", "evaluate", "risk", "controls", "prove"];

export interface Source { file: string; sha256: string; locator: string }
export interface Quote { file: string; text: string }
export interface Observation {
  id: string; kind: "runtime_decision" | "provenance_check" | "evaluation_result"; evidence_class: EvidenceClass; title: string; statement: string;
  facts: Record<string, unknown>; sources: Source[]; verification: { status: "NOT_VERIFIED" | "VERIFIED"; receipt: string | null }; limitations: string[];
}
export interface Assessment { id: string; statement: string; status: Status; about: string[]; basis: string; limitations: string[] }
export interface Asset { id: string; category: string; name: string; reason: string }
export interface Risk {
  id: string; statement: string; authored: boolean; assets: Asset[]; threat: { id: string; category: string; question: string }; controls: { id: string; class: string; placement: string }[];
  observed_in: string[]; impact: { status: Status; reason: string }; likelihood: { status: Status; reason: string }; gap: string; residual_risk: string; owner: string;
}
export interface Control { id: string; class: string; placement: string; code_reference: string; observed_in_recorded_runs: { run: string; decision: string; reason: string }[]; note: string }
export interface Mapping {
  framework: string; id: string; name: string; verification_status: string; relationship: "PROPOSED" | "RELATED"; rationale: string; limits: string; version_or_date: string; source_url: string; claims_compliance: false;
}
export interface Remediation { id: string; action: string; basis_quote: Quote; owner: string; status: string; authored: boolean }
export interface Journey {
  schema: string; id: string; title: string; lab_id: string;
  learn: { question: Quote; lines: Quote[] };
  steps: { id: StepId; title: string; instruction: string; next_action: string }[];
  observations: Observation[]; assessments: Assessment[]; risks: Risk[]; controls: Control[]; mappings: Mapping[];
  coverage: { notion: string; statement: string; source?: string; quote?: Quote }[]; coverage_note: string;
  mapping_meaning: { question: string; options: string[]; answer: string[]; quote: Quote };
  upstream_tags: { note: string; tags: string[] };
  compliance_assertions: never[]; compliance_statement: string; remediation: Remediation[]; limitations: string[];
}
