import { useSyncExternalStore } from "react";
import { risksSha256 } from "./sha256";
import { derive, validateAssessment } from "./validate";
import { SCHEMA, STATUS, type Action, type AssessmentDoc, type Custom, type Judgment, type Method, type Problem, type RiskState, type Seed, type Strategy } from "./types";

// The assessment is a LOCAL DRAFT: it lives in this browser only, is not shared, and is never approved by being saved. One button resets it to the source-backed seed.
const KEY = "agentsec.risk.v1";
export interface Draft { risks: RiskState[]; notice: string; saved: "saved" | "memory" | "none"; savedAt: string | null }
const now = () => new Date().toISOString();

export const blankRisk = (id: string, custom: Custom | null = null): RiskState => ({
  id, origin: custom ? "custom" : "seed", custom,
  assessment: { inherent: { impact: null, likelihood: null, rationale: "" }, residual: { impact: null, likelihood: null, rationale: "", controls_considered: [] } },
  owner: null, treatment: { strategy: null, notes: "", actions: [], approval: null }, review: { status: "DRAFT", reviewer: null, note: "", at: null, history: [] }, derived: { inherent_level: null, residual_level: null },
});

let seed: Seed | null = null;
let draft: Draft = { risks: [], notice: "", saved: "none", savedAt: null };
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function persist(risks: RiskState[], notice = ""): void {
  let saved: Draft["saved"] = "saved";
  try { window.localStorage.setItem(KEY, JSON.stringify({ v: 1, risks })); } catch { saved = "memory"; }
  draft = { risks, notice: saved === "memory" ? "This browser would not store the draft, so this change is kept in memory only and will be lost on reload." : notice, saved, savedAt: now() };
  emit();
}
export const getDraft = () => draft;
const withDerived = (m: Method, r: RiskState): RiskState => ({ ...r, derived: derive(m, r) });
const log = (r: RiskState, event: string, note = ""): RiskState => ({ ...r, review: { ...r.review, history: [...r.review.history, { at: now(), event, note }].slice(-100) } });

/** Load the seed once, then restore the saved draft if it is valid; otherwise start from the seed and say so. */
export function init(s: Seed): void {
  if (seed && seed.canonical_sha256 === s.canonical_sha256 && draft.risks.length) return;
  seed = s;
  const ids = new Set(s.candidates.map((c) => c.id));
  let risks = s.candidates.map((c) => blankRisk(c.id)), notice = "";
  try {
    const raw = window.localStorage.getItem(KEY);
    if (raw) {
      const j = JSON.parse(raw);
      const doc: AssessmentDoc = { schema: SCHEMA, methodology_version: s.methodology.version, status: STATUS, seed_sha256: s.canonical_sha256, integrity: { algorithm: "sha256", risks_sha256: risksSha256(j.risks), note: "" }, risks: j.risks };
      const bad = j.v !== 1 || !Array.isArray(j.risks) ? [{ code: "TYPE", path: "$", message: "unreadable" }] : validateAssessment(doc, ids, s.methodology);
      if (bad.length) notice = "Your saved draft could not be read, so it was replaced by the source-backed starting point.";
      else {
        const have = new Set((j.risks as RiskState[]).map((r) => r.id));
        risks = [...(j.risks as RiskState[]), ...s.candidates.filter((c) => !have.has(c.id)).map((c) => blankRisk(c.id))];
        // keep seed risks in the source order, custom risks after them
        risks = [...s.candidates.map((c) => risks.find((r) => r.id === c.id)!), ...risks.filter((r) => r.origin === "custom")];
      }
    }
  } catch { notice = "Saved drafts are not available in this browser, so work is kept in memory only."; }
  draft = { risks, notice, saved: notice.startsWith("Saved drafts") ? "memory" : "none", savedAt: null };
  emit();
}
export const useDraft = () => useSyncExternalStore((cb) => { listeners.add(cb); return () => { listeners.delete(cb); }; }, () => draft, () => draft);
const method = () => seed!.methodology;
const edit = (id: string, f: (r: RiskState) => RiskState, notice = "") => persist(draft.risks.map((r) => (r.id === id ? withDerived(method(), f(r)) : r)), notice);

export function saveInherent(id: string, j: Judgment) {
  edit(id, (r) => log({ ...r, assessment: { ...r.assessment, inherent: { ...j, rationale: j.rationale.trim() } } }, "Inherent assessment saved", `${j.impact} impact, ${j.likelihood} likelihood`), "Inherent assessment saved to this browser.");
}
export function saveResidual(id: string, j: Judgment, controls: string[]) {
  edit(id, (r) => log({ ...r, assessment: { ...r.assessment, residual: { ...j, rationale: j.rationale.trim(), controls_considered: controls } } }, "Residual assessment saved", `${j.impact} impact, ${j.likelihood} likelihood, ${controls.length} control(s) considered`), "Residual assessment saved to this browser.");
}
export function clearAssessment(id: string, which: "inherent" | "residual") {
  edit(id, (r) => log({ ...r, assessment: { ...r.assessment, [which]: which === "inherent" ? { impact: null, likelihood: null, rationale: "" } : { impact: null, likelihood: null, rationale: "", controls_considered: [] } } }, `${which === "inherent" ? "Inherent" : "Residual"} assessment cleared`), `${which === "inherent" ? "Inherent" : "Residual"} assessment cleared.`);
}
export function saveTreatment(id: string, strategy: Strategy | null, notes: string, owner: string | null) {
  edit(id, (r) => log({ ...r, owner: owner && owner.trim() ? owner.trim() : null, treatment: { ...r.treatment, strategy, notes: notes.trim(), approval: strategy === "ACCEPT" ? r.treatment.approval : null } }, "Treatment saved", strategy ?? "no strategy"), "Treatment saved to this browser.");
}
export function saveApproval(id: string, a: { by: string; role: string; note: string }) {
  edit(id, (r) => log({ ...r, treatment: { ...r.treatment, approval: { by: a.by.trim(), role: a.role.trim(), at: now(), note: a.note.trim() } } }, "Acceptance approval recorded", `${a.by.trim()}, ${a.role.trim()} (entered locally, not verified)`), "Approval record saved. It was entered locally and is not verified.");
}
export function clearApproval(id: string) { edit(id, (r) => log({ ...r, treatment: { ...r.treatment, approval: null } }, "Acceptance approval removed"), "Approval record removed."); }
export function saveAction(id: string, a: Omit<Action, "id"> & { id?: string }) {
  edit(id, (r) => {
    const acts = a.id ? r.treatment.actions.map((x) => (x.id === a.id ? { ...x, ...a, id: x.id } as Action : x)) : [...r.treatment.actions, { ...a, id: `A${r.treatment.actions.reduce((n, x) => Math.max(n, Number(x.id.slice(1)) || 0), 0) + 1}` } as Action];
    return log({ ...r, treatment: { ...r.treatment, actions: acts } }, a.id ? "Action updated" : "Action added", `${a.status}: ${a.text}`);
  }, a.id ? "Action saved." : "Action added.");
}
export function removeAction(id: string, actionId: string) { edit(id, (r) => log({ ...r, treatment: { ...r.treatment, actions: r.treatment.actions.filter((x) => x.id !== actionId) } }, "Action removed", actionId), "Action removed."); }
export function setReview(id: string, status: "DRAFT" | "AWAITING_REVIEW" | "REVIEWED", reviewer: string | null, note: string) {
  edit(id, (r) => log({ ...r, review: { ...r.review, status, reviewer: status === "REVIEWED" ? reviewer!.trim() : null, note: status === "REVIEWED" ? note.trim() : "", at: status === "REVIEWED" ? now() : null } },
    status === "REVIEWED" ? "Review recorded" : status === "AWAITING_REVIEW" ? "Marked awaiting review" : "Returned to draft", status === "REVIEWED" ? `${reviewer!.trim()}: ${note.trim()} (entered locally, not verified)` : ""),
    status === "REVIEWED" ? "Review recorded. It was entered locally and is not verified." : status === "AWAITING_REVIEW" ? "Marked as awaiting review." : "Returned to draft.");
}
export function addCustom(c: Custom): string {
  const n = draft.risks.filter((r) => r.origin === "custom").reduce((k, r) => Math.max(k, Number(r.id.replace("custom-", "")) || 0), 0) + 1, id = `custom-${n}`;
  persist([...draft.risks, log(blankRisk(id, { ...c, title: c.title.trim() }), "Custom risk created")], `Custom risk ${id} created.`);
  return id;
}
export function deleteCustom(id: string) { persist(draft.risks.filter((r) => r.id !== id), `Custom risk ${id} deleted.`); }
export function resetDraft() {
  try { window.localStorage.removeItem(KEY); } catch { /* nothing saved */ }
  draft = { risks: seed!.candidates.map((c) => blankRisk(c.id)), notice: "The draft was reset to the source-backed starting point. Every judgment is NOT ASSESSED.", saved: "none", savedAt: null };
  emit();
}

export function exportDoc(): AssessmentDoc {
  return { schema: SCHEMA, methodology_version: method().version, status: STATUS, seed_sha256: seed!.canonical_sha256, integrity: { algorithm: "sha256", risks_sha256: risksSha256(draft.risks), note: "A checksum that detects edits to this file. It is not a signature and does not show who made the assessment." }, risks: draft.risks };
}
export function importText(textJson: string): { ok: true; summary: string; warning: string } | { ok: false; problems: Problem[] } {
  let doc: unknown;
  try { doc = JSON.parse(textJson); } catch { return { ok: false, problems: [{ code: "JSON", path: "$", message: "is not valid JSON" }] }; }
  const ids = new Set(seed!.candidates.map((c) => c.id));
  const problems = validateAssessment(doc, ids, method());
  if (problems.length) return { ok: false, problems };
  const d = doc as AssessmentDoc;
  const have = new Set(d.risks.map((r) => r.id));
  const risks = [...seed!.candidates.map((c) => d.risks.find((r) => r.id === c.id) ?? blankRisk(c.id)), ...d.risks.filter((r) => r.origin === "custom")];
  persist(risks, "");
  const warning = d.seed_sha256 !== seed!.canonical_sha256 ? "The source evidence changed after this file was exported. Source facts shown on each risk are the current ones; your judgments were kept as written." : "";
  return { ok: true, summary: `Imported ${d.risks.length} risks (${d.risks.filter((r) => r.origin === "seed").length} source-backed, ${d.risks.filter((r) => r.origin === "custom").length} custom). Your local draft was replaced. ${seed!.candidates.filter((c) => !have.has(c.id)).length} source-backed risk(s) absent from the file were added unassessed.`, warning };
}
