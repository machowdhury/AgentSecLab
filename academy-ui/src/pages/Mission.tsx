import { useEffect, useRef, useState, type ComponentType } from "react";
import { Badge, Icon } from "../ui";
import { Link, missionPath, navigate } from "../router";
import { STAGES, stageIndex, unifiedNumber, unifiedStages, type StageId, type UnifiedStageId } from "../stages";
import { UnifiedRail } from "../UnifiedWorkshop";
import { firstOpenIncomplete, gateReason, markSeen, stageComplete, useMission } from "../store";
import { adoptRuns } from "../mission/runStore";
import { Learn } from "../mission/stages/Learn";
import { Prepare } from "../mission/stages/Prepare";
import { Attack } from "../mission/stages/Attack";
import { Investigate } from "../mission/stages/Investigate";
import { Defend } from "../mission/stages/Defend";
import { Retest } from "../mission/stages/Retest";
import { Explain } from "../mission/stages/Explain";

const SECURITY_QUESTION = "Can a valid, in-scope tool call still carry attacker-written content into a human work queue, and does argument-level authorization stop it without breaking the business task?";
// The Loan Desk keeps its seven mission stages; each maps onto the unified sequence (Prepare covers Predict and Baseline).
const UNIFIED_OF: Record<StageId, UnifiedStageId[]> = { learn: ["learn"], prepare: ["predict", "baseline"], attack: ["attack"], investigate: ["investigate"], defend: ["defend"], retest: ["retest"], explain: ["explain"] };
const MISSION_OF: Record<UnifiedStageId, StageId> = { learn: "learn", predict: "prepare", baseline: "prepare", attack: "attack", investigate: "investigate", defend: "defend", retest: "retest", explain: "explain" };
const VIEW: Record<StageId, ComponentType> = { learn: Learn, prepare: Prepare, attack: Attack, investigate: Investigate, defend: Defend, retest: Retest, explain: Explain };

export function Mission({ stage }: { stage: StageId | null }) {
  const m = useMission();
  const [gateMsg, setGateMsg] = useState("");
  const pending = useRef("");
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => { adoptRuns(); }, []);

  useEffect(() => {
    if (stage === null) { navigate(missionPath(m.seen.length ? firstOpenIncomplete(m) : "learn"), { replace: true }); return; }
    const why = gateReason(stage, m);
    if (why) {
      pending.current = `${STAGES.find((s) => s.id === stage)!.label} is locked. ${why}`;
      navigate(missionPath(firstOpenIncomplete(m)), { replace: true });
      return;
    }
    setGateMsg(pending.current); pending.current = "";
    markSeen(stage);
    heading.current?.focus({ preventScroll: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage, m.prediction.locked, m.runs.attack, m.defenseApplied, m.runDone.attack, m.runDone.retest]);

  if (stage === null || gateReason(stage, m)) return <div className="page"><p className="m-muted" role="status">Opening your mission…</p></div>;
  const Stage = VIEW[stage];
  const idx = stageIndex(stage);
  const info = STAGES[idx];
  return <div className="page workshop">
    <header className="lab-header">
      <div className="badge-row"><Badge>L1</Badge><Badge tone="live">LIVE LAB</Badge><span>Mission · AcmeBank Loan Desk · live agent</span></div>
      <h1 ref={heading} tabIndex={-1}>Loan Desk: when the agent writes for the underwriter</h1>
      <p>{SECURITY_QUESTION}</p>
    </header>
    <div className="lab-facts"><div><span>LAB</span><strong>LAB-LOANDESK-001</strong></div><div><span>STAGE</span><strong>{UNIFIED_OF[stage].map((u) => unifiedNumber(u)).join("–")} of {unifiedStages.length} · {info.label}</strong></div><div><span>QUESTION</span><strong>{info.blurb}</strong></div><div><span>CONTROL UNDER TEST</span><strong>CTRL-LOANDESK-001</strong></div></div>
    <UnifiedRail lab="LAB-LOANDESK-001" current={UNIFIED_OF[stage]} lockedReason={(u) => gateReason(MISSION_OF[u], m)}
      onSelect={(u) => { const to = MISSION_OF[u], why = gateReason(to, m); if (why) setGateMsg(`${STAGES.find((x) => x.id === to)!.label} is locked. ${why}`); else navigate(missionPath(to)); }} />
    <p className="visually-hidden" role="status" aria-live="polite">Stage {UNIFIED_OF[stage].map((u) => unifiedNumber(u)).join(" and ")} of {unifiedStages.length}: {info.label}</p>
    {gateMsg && <div className="m-callout m-callout--warn" role="alert"><Icon name="clock" size={16} /> {gateMsg}</div>}
    <Stage />
  </div>;
}
