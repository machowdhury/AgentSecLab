import { Icon, type IconName } from "./ui";
import type { PathNode } from "./curriculum";

const KIND: Record<PathNode["kind"], { label: string; icon: IconName }> = {
  attacker: { label: "Attacker input", icon: "terminal" }, entry: { label: "Entry point", icon: "arrow" }, boundary: { label: "Trust boundary", icon: "shield" },
  control: { label: "Security control", icon: "shield" }, operation: { label: "Dangerous operation", icon: "play" }, evidence: { label: "Evidence", icon: "search" },
};

/** A reusable, text-first attack path. Every node carries a fact quoted from the lab's own files and its source; nothing here is an observed result. */
export function AttackPath({ nodes, title }: { nodes: PathNode[]; title: string }) {
  return <figure className="m-path">
    <figcaption>{title}</figcaption>
    <ol aria-label={title}>
      {nodes.map((n) => <li key={n.id} className={`m-path__node m-path__node--${n.kind}`}>
        <span className="m-path__icon" aria-hidden="true"><Icon name={KIND[n.kind].icon} size={16} /></span>
        <div className="m-path__body">
          <span className="m-path__kind">{KIND[n.kind].label}</span>
          <strong>{n.label}</strong>
          <p>{n.detail}</p>
          {n.outcomes && <ul className="m-path__branches" aria-label={`Possible outcomes of ${n.label}`}>
            {n.outcomes.map((o) => <li key={o.label}><strong>{o.label}</strong><span>{o.detail}</span></li>)}
          </ul>}
          <small className="m-src">Source: <code>{n.source}</code></small>
        </div>
      </li>)}
    </ol>
    <p className="m-muted">This is the path described in the lab's files. It shows what can happen, not what happened in a run.</p>
  </figure>;
}
