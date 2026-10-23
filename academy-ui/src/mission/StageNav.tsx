import { Link, missionPath } from "../router";
import type { StageId } from "../stages";
import { Icon } from "../ui";
import { gateReason, useMission } from "../store";

export function StageNav({ back, next, nextLabel }: { back?: StageId; next?: StageId; nextLabel?: string }) {
  const m = useMission();
  const locked = next ? gateReason(next, m) : "";
  return <div className="lesson-actions m-stagenav">
    {back ? <Link className="button button--ghost" to={missionPath(back)}>Back</Link> : <span />}
    {next && (locked
      ? <span className="m-locked" role="note"><Icon name="clock" size={15} /> {nextLabel ?? "Continue"} unlocks when: {locked.replace(/\.$/, "").replace(/^(\w)/, (c) => c.toLowerCase())}.</span>
      : <Link className="button button--primary" to={missionPath(next)}>{nextLabel ?? "Continue"} <Icon name="arrow" size={17} /></Link>)}
  </div>;
}
