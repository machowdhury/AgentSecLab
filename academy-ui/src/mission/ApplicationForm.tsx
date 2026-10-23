import { Icon } from "../ui";
import { useConfig } from "../config";
import { updateMission, useMission } from "../store";
import { EMPLOYMENT, PROVINCES, TEXT_FIELDS, appValues } from "./app";
import { Callout } from "./parts";
import { launch, useSlot } from "./runStore";

// The real Loan Desk application form. It submits through the existing same-origin POST /api/missions/loan-desk/runs (BASELINE posture).
export function ApplicationForm() {
  const { config } = useConfig();
  const m = useMission();
  const slot = useSlot("explore");
  const vals = appValues(m, config.mission);
  const set = (k: string, v: string) => updateMission((s) => ({ ...s, application: { ...appValues(s, config.mission), [k]: v } }));
  const busy = slot.phase === "submitting" || slot.phase === "running";
  const errs = slot.fieldErrors ?? {};
  return (
    <form className="m-form" noValidate onSubmit={(e) => { e.preventDefault(); launch("explore", vals, "baseline"); }}>
      {slot.fieldErrors && <Callout kind="warn" role="alert">{Object.keys(errs).length ? "Please fix the highlighted fields." : slot.message}</Callout>}
      {TEXT_FIELDS.map(([k, label]) => <div className="m-field" key={k}><label htmlFor={`f-${k}`}>{label}</label><input id={`f-${k}`} value={vals[k] ?? ""} onChange={(e) => set(k, e.target.value)} autoComplete="off" aria-invalid={Boolean(errs[k])} />{errs[k] && <p className="m-error">{errs[k]}</p>}</div>)}
      <div className="m-field"><label htmlFor="f-province">Province</label><select id="f-province" value={vals.province} onChange={(e) => set("province", e.target.value)}>{PROVINCES.map((p) => <option key={p}>{p}</option>)}</select></div>
      <div className="m-field"><label htmlFor="f-employment">Employment</label><select id="f-employment" value={vals.employment} onChange={(e) => set("employment", e.target.value)}>{EMPLOYMENT.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
      <div className="m-field"><label htmlFor="f-notes">Notes to the loan officer (untrusted text the agent reads)</label><textarea id="f-notes" rows={3} maxLength={400} value={vals.notes} onChange={(e) => set("notes", e.target.value)} />{errs.notes && <p className="m-error">{errs.notes}</p>}</div>
      <button type="submit" className="button button--primary" disabled={busy}>Run normal application <Icon name="play" size={15} /></button>
        </form>
  );
}
