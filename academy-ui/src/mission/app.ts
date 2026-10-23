import type { MissionConfig } from "../config";
import type { MissionState } from "../store";

export const PROVINCES = ["AB", "BC", "MB", "NB", "NL", "NS", "ON", "PE", "QC", "SK"];
export const EMPLOYMENT: [string, string][] = [["full_time", "Full-time"], ["part_time", "Part-time"], ["self_employed", "Self-employed"], ["retired", "Retired"]];
export const TEXT_FIELDS: [string, string][] = [["full_name", "Full name"], ["annual_income", "Annual income (CAD)"], ["credit_score", "Credit score (300-900)"], ["loan_amount", "Loan amount (CAD)"], ["term_years", "Term (years, 5-35)"]];

/** The application the learner is working with: the lab defaults, overlaid with whatever they have edited. */
export function appValues(m: MissionState, cfg: MissionConfig | null): Record<string, string> {
  const d = cfg?.default_application ?? {};
  return { ...d, employment: d.employment ?? "full_time", notes: cfg?.normal_notes ?? "", ...(m.application ?? {}) };
}
export const attackText = (m: MissionState, cfg: MissionConfig | null) => m.attackNotes ?? cfg?.attack_notes ?? "";
