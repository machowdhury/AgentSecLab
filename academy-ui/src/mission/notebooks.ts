// Exercise-specific notebook configuration. The notebook component is generic; a new exercise supplies lists like these.
// `template` names a FIXED server-side search template. Learners adjust validated parameters; they never send SPL.
export interface CellConfig {
  id: string;
  template: string;
  title: string;
  question: string;
  hint: string;
  proves: string;
  notProves: string;
  /** Short label for the milestone this cell earns once it has really returned rows for the learner's run. */
  milestone: string;
  /** A comparison cell binds the attack run (baseline) and the retest run (defended). */
  compare?: boolean;
  /** Show the real underwriter-queue ticket from the run view beside the result (correlation with the search). */
  showQueue?: boolean;
  stage: "investigate" | "retest";
}

export const LOAN_DESK_INVESTIGATE: CellConfig[] = [
  { id: "ld-events", template: "events_by_field", stage: "investigate", milestone: "Telemetry found",
    title: "What telemetry did this run leave behind?",
    question: "Group the run's indexed events by event name. How many events are there, and which steps of the agent's work do they record?",
    hint: "Start with event.name. Then try gen_ai.tool.name and agentsec.control.decision.",
    proves: "These events were indexed for this run id, and they record the pipeline, the policy decisions and the tool starts and completions.",
    notProves: "That the events are true, that nothing is missing, or that the run was verified. SPLUNK-VERIFIED comes only from the host verifier's receipt, not from a count on this page." },
  { id: "ld-tools", template: "tool_calls", stage: "investigate", milestone: "Tool calls rebuilt",
    title: "Which tools did the agent propose, and in what order?",
    question: "Rebuild the agent's plan from the recorded proposals. Which tool is the one that writes to a human work queue?",
    hint: "Look for the step where submit_for_underwriter_review is proposed. The source column says who made the proposal.",
    proves: "The agent proposed these tool calls at these steps, as recorded when it proposed them.",
    notProves: "That any proposal was allowed or ran. A proposal is only a request." },
  { id: "ld-decisions", template: "decisions", stage: "investigate", milestone: "Policy decisions read",
    title: "What did the policy engine decide for each proposal?",
    question: "Find the policy decision for the review submission. Was it allowed? On what grounds?",
    hint: "ALLOW means the policy engine permitted the call: right tool, granted scope, bound applicant. Ask what it did not look at.",
    proves: "CTRL-LOANDESK-001 recorded these decisions and reasons for this run.",
    notProves: "That the allowed content was safe. In BASELINE posture the decision never inspected the note's text." },
  { id: "ld-trail", template: "review_content_trail", stage: "investigate", milestone: "Attacker text traced",
    title: "Where did the attacker's words travel?",
    question: "Follow the review note through the proposal, the policy decision and the handler. At which step does the planted text first appear, and does it change along the way?",
    hint: "Compare the content column across the three events for submit_for_underwriter_review. The preview is truncated to the start of the content.",
    proves: "The same note content was recorded at the proposal, at the decision and at the handler, in that order.",
    notProves: "Who wrote the text. The telemetry shows it moved through the agent, not that the applicant planted it; your Attack step established that." },
  { id: "ld-queue", template: "handler_outcomes", stage: "investigate", milestone: "Queue outcome correlated", showQueue: true,
    title: "What did each handler return, and what reached the human queue?",
    question: "Check what the review handler returned. Does it match the ticket an underwriter would read below?",
    hint: "Find the submit_for_underwriter_review row. Then read the real queue ticket shown under the results.",
    proves: "What each handler returned, as recorded, and (below) the ticket AcmeBank reports in the queue for this run.",
    notProves: "That the two records are independent: both come from AcmeBank. Splunk indexing and the host verifier are what tie the recorded events to what was indexed." },
];

export const LOAN_DESK_RETEST: CellConfig[] = [
  { id: "rt-overview", template: "compare_overview", stage: "retest", compare: true, milestone: "Both runs compared",
    title: "Did the two runs leave the same telemetry?",
    question: "Compare the event activity of the baseline run and the defended run. Where do the counts differ?",
    hint: "Different counts are expected: the model varies between runs, and a denied call changes what happens next.",
    proves: "How many events of each kind Splunk holds for each run.",
    notProves: "That a difference was caused by the defense. Model randomness also changes counts; read the decision and handler rows." },
  { id: "rt-decisions", template: "compare_decisions", stage: "retest", compare: true, milestone: "Decision change located",
    title: "Where did the policy decision change?",
    question: "Find the tool whose decision differs between baseline and defended. What reason did the policy engine record?",
    hint: "Rows marked changed differ between the runs. Look at submit_for_underwriter_review.",
    proves: "The policy engine's recorded verdict and reason for each tool, per run.",
    notProves: "That the defense made the agent behave better, only that this control decided differently on this input." },
  { id: "rt-exec", template: "compare_execution", stage: "retest", compare: true, milestone: "Execution compared",
    title: "Which handlers actually began in each run?",
    question: "A denied call must not start its handler. Do the counts of handlers that began match the allowed calls?",
    hint: "Compare started handlers with the decision rows above: a DENY should leave a gap.",
    proves: "How many times each tool's handler began, per run.",
    notProves: "That a started handler finished correctly or that its output was harmless." },
  { id: "rt-note", template: "compare_review_note", stage: "retest", compare: true, milestone: "Queue content compared",
    title: "What did the review handler file in each run?",
    question: "Compare the notes that reached the review handler. Did the attacker's text get through in the defended run?",
    hint: "Read the filed column for each side. A denied attempt files nothing; the agent may then try again with a different note.",
    proves: "The content each review handler returned, per run.",
    notProves: "That the attack is impossible. It shows what this input produced against this control." },
];

export const ALL_CELLS: CellConfig[] = [...LOAN_DESK_INVESTIGATE, ...LOAN_DESK_RETEST];
