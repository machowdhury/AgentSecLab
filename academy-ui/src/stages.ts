// Seven learner-facing stages over the original ten mission steps (the step content and gating are unchanged).
export const STEP_ORDER = ["understand", "explore", "predict", "attack", "observe", "investigate", "defend", "retest", "compare", "explain"] as const;
export type StepId = (typeof STEP_ORDER)[number];

export const STAGES = [
  { id: "learn", label: "Learn", blurb: "How the Loan Desk is built and what is real", steps: ["understand"] },
  { id: "prepare", label: "Prepare", blurb: "Run a normal application, then predict", steps: ["explore", "predict"] },
  { id: "attack", label: "Attack", blurb: "Launch the planted application and observe", steps: ["attack", "observe"] },
  { id: "investigate", label: "Investigate", blurb: "Prove it from recorded evidence in Splunk", steps: ["investigate"] },
  { id: "defend", label: "Defend", blurb: "Change one control", steps: ["defend"] },
  { id: "retest", label: "Retest", blurb: "Same attack, new posture, then compare", steps: ["retest", "compare"] },
  { id: "explain", label: "Explain", blurb: "Say it in your own words", steps: ["explain"] },
] as const satisfies readonly { id: string; label: string; blurb: string; steps: readonly StepId[] }[];

export type StageId = (typeof STAGES)[number]["id"];
export const STAGE_IDS = STAGES.map((s) => s.id) as StageId[];
export const stageIndex = (id: StageId) => STAGE_IDS.indexOf(id);
export const isStage = (v: string): v is StageId => (STAGE_IDS as string[]).includes(v);
export const stepNumber = (s: StepId) => STEP_ORDER.indexOf(s) + 1;
