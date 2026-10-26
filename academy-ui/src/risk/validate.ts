import { risksSha256 } from "./sha256";
import { SCHEMA, STATUS, type Level, type Method, type Problem, type RiskState } from "./types";

// A port of validate_assessment in scripts/risk_model.py. The two return the same error codes for the same document, which the tests check on a shared set of cases.
export const LIMITS = { risks: 200, text: 2000, short: 200, actions: 50, history: 100, controls: 50 };
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/, RESERVED = new Set(["register", "method", "new"]), ACTION = ["PROPOSED", "IN_PROGRESS", "COMPLETED"], REVIEW = ["DRAFT", "AWAITING_REVIEW", "REVIEWED"];
const isObj = (o: unknown): o is Record<string, any> => !!o && typeof o === "object" && !Array.isArray(o); // eslint-disable-line @typescript-eslint/no-explicit-any
const blank = (v: unknown) => !(typeof v === "string" && v.trim());

export const level = (m: Method, impact: unknown, likelihood: unknown): Level | null =>
  m.impact.some((x) => x.id === impact) && m.likelihood.some((x) => x.id === likelihood) ? m.matrix[impact as string][likelihood as string] : null;
export const derive = (m: Method, r: Pick<RiskState, "assessment">) => ({ inherent_level: level(m, r.assessment.inherent.impact, r.assessment.inherent.likelihood), residual_level: level(m, r.assessment.residual.impact, r.assessment.residual.likelihood) });

export function validateAssessment(doc: unknown, seedIds: Set<string>, m: Method): Problem[] {
  const errs: Problem[] = [], add = (code: string, path: string, message: string) => errs.push({ code, path, message });
  const keys = (o: unknown, allowed: string[], path: string): o is Record<string, any> => { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (!isObj(o)) { add("TYPE", path, "must be an object"); return false; }
    Object.keys(o).forEach((k) => { if (!allowed.includes(k)) add("UNKNOWN_KEY", `${path}.${k}`, "is not a field of the schema"); });
    allowed.forEach((k) => { if (!(k in o)) add("MISSING_KEY", `${path}.${k}`, "is missing"); });
    return true;
  };
  const text = (v: unknown, path: string, limit = LIMITS.text, nullable = false) => { if ((v === null || v === undefined) && nullable) return; if (typeof v !== "string") add("TYPE", path, "must be text"); else if (v.length > limit) add("LIMIT", path, `is longer than ${limit} characters`); };
  if (!keys(doc, ["schema", "methodology_version", "status", "seed_sha256", "integrity", "risks"], "$")) return errs;
  if (doc.schema !== SCHEMA) add("SCHEMA", "$.schema", `must be ${SCHEMA}`);
  if (doc.methodology_version !== m.version) add("METHOD_VERSION", "$.methodology_version", `must be ${m.version}`);
  if (doc.status !== STATUS) add("STATUS", "$.status", `must be ${STATUS}: a local draft is never approved`);
  if (typeof doc.seed_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(doc.seed_sha256)) add("TYPE", "$.seed_sha256", "must be a SHA-256");
  keys(doc.integrity, ["algorithm", "risks_sha256", "note"], "$.integrity");
  const risks = doc.risks;
  if (!Array.isArray(risks)) { add("TYPE", "$.risks", "must be a list"); return errs; }
  if (risks.length > LIMITS.risks) add("LIMIT", "$.risks", `has more than ${LIMITS.risks} risks`);
  if (isObj(doc.integrity) && doc.integrity.algorithm === "sha256" && doc.integrity.risks_sha256 !== risksSha256(risks)) add("INTEGRITY", "$.integrity.risks_sha256", "does not match the risks: the file was edited after it was exported");
  else if (isObj(doc.integrity) && doc.integrity.algorithm !== "sha256") add("INTEGRITY", "$.integrity.algorithm", "must be sha256");
  const seen = new Set<string>();
  risks.forEach((r: unknown, i: number) => {
    const p = `$.risks[${i}]`;
    if (!keys(r, ["id", "origin", "custom", "assessment", "owner", "treatment", "review", "derived"], p)) return;
    const rid = r.id;
    if (typeof rid !== "string" || !ID_RE.test(rid) || RESERVED.has(rid.toLowerCase())) add("ID", `${p}.id`, "is not a valid risk id");
    else if (seen.has(rid)) add("DUPLICATE", `${p}.id`, "appears twice");
    seen.add(String(rid));
    if (r.origin !== "seed" && r.origin !== "custom") add("ORIGIN", `${p}.origin`, "must be seed or custom");
    if (r.origin === "seed") {
      if (!seedIds.has(rid)) add("UNKNOWN_SEED", `${p}.id`, "is not a source-backed risk in the current evidence");
      if (r.custom != null) add("ORIGIN", `${p}.custom`, "a source-backed risk carries no analyst-defined facts");
    }
    if (r.origin === "custom") {
      const c = r.custom;
      if (keys(c, ["title", "category", "system", "scenario", "assets"], `${p}.custom`)) {
        ["title", "category", "system", "scenario", "assets"].forEach((f) => text(c[f], `${p}.custom.${f}`, f !== "scenario" ? LIMITS.short : LIMITS.text));
        if (typeof c.title === "string" && !c.title.trim()) add("TITLE", `${p}.custom.title`, "a custom risk needs a title");
      }
    }
    const a = r.assessment;
    if (keys(a, ["inherent", "residual"], `${p}.assessment`)) {
      (["inherent", "residual"] as const).forEach((which) => {
        const s = a[which], sp = `${p}.assessment.${which}`;
        if (!keys(s, ["impact", "likelihood", "rationale", ...(which === "residual" ? ["controls_considered"] : [])], sp)) return;
        if (s.impact != null && !m.impact.some((x) => x.id === s.impact)) add("SCALE", `${sp}.impact`, "must be a scale value or null");
        if (s.likelihood != null && !m.likelihood.some((x) => x.id === s.likelihood)) add("SCALE", `${sp}.likelihood`, "must be a scale value or null");
        text(s.rationale, `${sp}.rationale`);
        if ((s.impact == null) !== (s.likelihood == null)) add("PAIR", sp, "impact and likelihood must be entered together");
        if (s.impact != null && s.likelihood != null && blank(s.rationale)) add("RATIONALE", `${sp}.rationale`, "a judgment needs a written rationale");
        if (which === "residual") { const cc = s.controls_considered; if (!Array.isArray(cc) || !cc.every((x) => typeof x === "string" && x.length <= LIMITS.short) || cc.length > LIMITS.controls) add("TYPE", `${sp}.controls_considered`, "must be a list of control ids"); }
      });
      const ih = isObj(a.inherent) ? a.inherent : {}, rs = isObj(a.residual) ? a.residual : {};
      if (rs.impact != null && ih.impact == null) add("RESIDUAL_NEEDS_INHERENT", `${p}.assessment.residual`, "residual risk cannot be judged before inherent risk");
    }
    if (r.owner != null) text(r.owner, `${p}.owner`, LIMITS.short);
    const t = r.treatment;
    if (keys(t, ["strategy", "notes", "actions", "approval"], `${p}.treatment`)) {
      if (t.strategy != null && !m.treatment.some((x) => x.id === t.strategy)) add("STRATEGY", `${p}.treatment.strategy`, "must be a treatment option or null");
      text(t.notes, `${p}.treatment.notes`);
      const ap = t.approval;
      if (ap != null) {
        if (t.strategy !== "ACCEPT") add("APPROVAL", `${p}.treatment.approval`, "only an ACCEPT treatment carries an approval record");
        if (keys(ap, ["by", "role", "at", "note"], `${p}.treatment.approval`)) ["by", "role", "at", "note"].forEach((f) => { text(ap[f], `${p}.treatment.approval.${f}`, LIMITS.short); if (typeof ap[f] === "string" && !ap[f].trim()) add("APPROVAL", `${p}.treatment.approval.${f}`, "an approval record needs who, role, when and a note"); });
      }
      const acts = t.actions;
      if (!Array.isArray(acts) || acts.length > LIMITS.actions) add("TYPE", `${p}.treatment.actions`, "must be a short list");
      else {
        const ids = new Set<unknown>();
        acts.forEach((x: unknown, j: number) => {
          const xp = `${p}.treatment.actions[${j}]`;
          if (!keys(x, ["id", "text", "owner", "status", "evidence_note"], xp)) return;
          if (ids.has(x.id)) add("DUPLICATE", `${xp}.id`, "appears twice");
          ids.add(x.id);
          text(x.text, `${xp}.text`, LIMITS.short); text(x.owner, `${xp}.owner`, LIMITS.short, true); text(x.evidence_note, `${xp}.evidence_note`);
          if (!ACTION.includes(x.status)) add("ACTION_STATUS", `${xp}.status`, "must be a known action status");
          if (x.status === "COMPLETED" && blank(x.evidence_note)) add("ACTION_EVIDENCE", `${xp}.evidence_note`, "a completed action needs the evidence it rests on");
        });
      }
    }
    const rv = r.review;
    if (keys(rv, ["status", "reviewer", "note", "at", "history"], `${p}.review`)) {
      if (!REVIEW.includes(rv.status)) add("REVIEW_STATUS", `${p}.review.status`, "must be a known review status: nothing is shown as approved");
      text(rv.reviewer, `${p}.review.reviewer`, LIMITS.short, true); text(rv.note, `${p}.review.note`); text(rv.at, `${p}.review.at`, LIMITS.short, true);
      if (rv.status === "REVIEWED" && !(["reviewer", "note", "at"] as const).every((f) => typeof rv[f] === "string" && rv[f].trim())) add("REVIEW_FIELDS", `${p}.review`, "a recorded review needs the reviewer, a note and a date");
      const h = rv.history;
      if (!Array.isArray(h) || h.length > LIMITS.history) add("TYPE", `${p}.review.history`, "must be a short list");
      else h.forEach((x: unknown, j: number) => { if (keys(x, ["at", "event", "note"], `${p}.review.history[${j}]`)) ["at", "event", "note"].forEach((f) => text(x[f], `${p}.review.history[${j}].${f}`, f !== "note" ? LIMITS.short : LIMITS.text)); });
    }
    const d = r.derived;
    if (keys(d, ["inherent_level", "residual_level"], `${p}.derived`) && isObj(r.assessment)) {
      try { const want = derive(m, r as RiskState); if (d.inherent_level !== want.inherent_level || d.residual_level !== want.residual_level) add("DERIVED", `${p}.derived`, "does not follow from the entries by the method"); } catch { /* shape errors were reported above */ }
    }
  });
  return errs;
}
