export function TaskPanel({ task, steps, active }: { task: string; steps: string[]; active: number }) {
  return <div className="task-panel" role="region" aria-label="Your task for this stage">
    <div><div className="eyebrow">Your task</div><strong>{task}</strong></div>
    <ol>{steps.map((s, i) => <li key={s} className={i === active ? "active" : ""} aria-current={i === active ? "step" : undefined}><span>{i + 1}</span>{s}</li>)}</ol>
  </div>;
}
