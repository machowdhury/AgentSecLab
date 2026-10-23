import type { ReactNode } from "react";

/** The four things every learner screen must show: what you are learning, what to do, what happened, what comes next. */
export function StageGuide({ learning, todo, happened, next }: { learning: ReactNode; todo: ReactNode; happened: ReactNode; next: ReactNode }) {
  const cells: [string, ReactNode][] = [["What you are learning", learning], ["What to do", todo], ["What happened", happened], ["What comes next", next]];
  return <section className="m-guide" aria-label="Guide to this page">
    {cells.map(([label, body]) => <div key={label}><span>{label}</span><p>{body}</p></div>)}
  </section>;
}
