import type { Mapping, Source } from "../assurance/types";
import type { Finding } from "../eval/types";
// Mirrors scripts/risk_model.py. Four origins are never mixed: SOURCE, DERIVED, ANALYST and MISSING.
export type Origin = "SOURCE" | "DERIVED" | "ANALYST" | "MISSING";
export type Impact = "LOW" | "MODERATE" | "HIGH";
export type Likelihood = "UNLIKELY" | "POSSIBLE" | "LIKELY";
export type Level = "LOW" | "MEDIUM" | "HIGH";
export type Strategy = "MITIGATE" | "ACCEPT" | "TRANSFER" | "AVOID";
export type ActionStatus = "PROPOSED" | "IN_PROGRESS" | "COMPLETED";
export type ReviewStatus = "DRAFT" | "AWAITING_REVIEW" | "REVIEWED";
export interface Scale { id: string; label: string; definition: string }
export interface Method {
  version: number; name: string; statement: string; source_rule: { file: string; text: string }; impact: Scale[]; likelihood: Scale[]; matrix: Record<string, Record<string, Level>>; levels: Level[];
  rules: string[]; treatment: { id: Strategy; label: string; meaning: string }[]; origins: { id: Origin; label: string; meaning: string }[];
}
export interface Judgment { impact: Impact | null; likelihood: Likelihood | null; rationale: string }
export interface Action { id: string; text: string; owner: string | null; status: ActionStatus; evidence_note: string }
export interface Approval { by: string; role: string; at: string; note: string }
export interface Review { status: ReviewStatus; reviewer: string | null; note: string; at: string | null; history: { at: string; event: string; note: string }[] }
export interface Custom { title: string; category: string; system: string; scenario: string; assets: string }
export interface RiskState {
  id: string; origin: "seed" | "custom"; custom: Custom | null;
  assessment: { inherent: Judgment; residual: Judgment & { controls_considered: string[] } };
  owner: string | null; treatment: { strategy: Strategy | null; notes: string; actions: Action[]; approval: Approval | null }; review: Review;
  derived: { inherent_level: Level | null; residual_level: Level | null };
}
export interface Candidate {
  id: string; origin: "seed"; title: string; threat_scenario: string; system: { name: string; components: { id: string; name: string; status: string }[] };
  assets: { id: string; name: string; category: string; reason: string }[]; boundaries: { id: string; name: string; question: string }[];
  controls: { id: string; class: string; placement: string; code_reference: string; recorded_decisions: { experiment: string; case: string; role: string; decision: string; reason: string }[]; evidence_note: string }[];
  telemetry_required: string[]; documented_gap: string; documented_residual_risk: string;
  evidence: { experiments: { id: string; title: string; evidence_class: string; status: string }[]; findings: (Pick<Finding, "id" | "title" | "rule" | "observed" | "expected" | "matches_documented" | "match_basis" | "evidence" | "limitations" | "verification" | "experiment">)[];
              cases: { id: string; role: string; evidence_class: string; verification: { status: string }; statement: string }[]; limitations: string[]; mappings: Mapping[] };
  derived: { has_linked_evidence: boolean; has_linked_findings: boolean; controls_without_recorded_evidence: string[]; gaps: string[] };
  sources: Source[]; inventory?: { note: string; components: number; owner_not_recorded: string[]; source: Source };
}
export interface Seed { schema: string; title: string; methodology: Method; candidates: Candidate[]; note: string; canonical_sha256: string }
export interface AssessmentDoc { schema: string; methodology_version: number; status: string; seed_sha256: string; integrity: { algorithm: string; risks_sha256: string; note: string }; risks: RiskState[] }
export interface Problem { code: string; path: string; message: string }
export const SCHEMA = "agentsec.risk_assessment.v1", STATUS = "LOCAL_DRAFT_NOT_APPROVED";
