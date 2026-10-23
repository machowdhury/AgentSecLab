// Educational text and evidence wording of the Loan Desk mission, carried over unchanged from the classic Academy page.
import type { RunView, Posture } from "../types";
import type { StepId } from "../stages";

export interface Brief { doing: string; why: string; todo: string; evidence: string; learn: string }

export const BRIEFS: Record<StepId, Brief> = {
  understand: { doing: "Reading how the Loan Desk is built and what is real.", why: "You can only judge evidence once you know which parts are trusted and which are deliberately weak.", todo: "Read the flow and the lab boundaries, then continue.", evidence: "None yet.", learn: "A model proposes, a policy engine decides, a handler runs. Those are three different facts." },
  explore: { doing: "Submitting an ordinary application and watching the agent work.", why: "Normal behaviour is the baseline you will compare the attack against.", todo: "Edit any field you like, then run it. This runs in the lab's starting BASELINE posture. Notes are optional.", evidence: "The timeline: what the model proposed, what policy decided, what actually ran, and the note the agent filed.", learn: "Each tool call has separate facts: proposed, decided, executed." },
  predict: { doing: "Committing to what you expect before any evidence exists.", why: "A prediction you did not make cannot be wrong, so it teaches nothing.", todo: "Read the planted text, answer three questions, lock them.", evidence: "None. Evidence arrives after you lock.", learn: "Where your mental model of agents and controls is right or wrong." },
  attack: { doing: "Running the attack for real against the BASELINE Loan Desk.", why: "This is a live run: a real model, real policy decisions, real events.", todo: "Launch it. You may edit the planted text first.", evidence: "Wait for the run to finish; the timeline fills in as it happens.", learn: "Whether a valid, in-scope action can still carry an attacker's content." },
  observe: { doing: "Reading the result and checking your prediction.", why: "Surprises are where the learning is.", todo: "Compare each answer you locked with what the run actually did.", evidence: "The queue, the policy decision for the review, and whether its handler began.", learn: "ALLOW means policy was satisfied. It does not mean the action was safe." },
  investigate: { doing: "Finding the attack run in Splunk and answering from recorded events.", why: "The page shows what AcmeBank emitted locally. Only Splunk shows what was indexed.", todo: "Copy a search, run it in Splunk, then enter what you see.", evidence: "Three searches: the run's events, the policy decision for the review, and the filed note.", learn: "Local evidence and Splunk evidence are different claims; the host verifier uses a fixed, read-only search and never gives this page a credential. Counting values instead of events inflates the number." },
  defend: { doing: "Choosing how the review note is controlled.", why: "The attack worked inside valid scope, so the existing checks had nothing to refuse.", todo: "Pick the posture and apply it. You can switch back at any time.", evidence: "The rule text and what it changes.", learn: "Argument-level authorization: control what an allowed tool may carry, not only who may call it." },
  retest: { doing: "Replaying the exact planted text against your chosen posture.", why: "A defense is a claim until the same attack is run again.", todo: "Launch the retest. It uses the planted text from the Attack step.", evidence: "The review decision, the queue, and whether the handler ran.", learn: "Whether the change blocked the attack without breaking the business workflow." },
  compare: { doing: "Setting your two live runs side by side.", why: "Only a difference you can point to counts as evidence.", todo: "Read the rows; note which differences come from the posture and which from model randomness.", evidence: "Posture, the review decision, the queue note, and event counts.", learn: "A defense is proven by the same input producing a different, explained outcome." },
  explain: { doing: "Answering four questions from your own runs, then writing the story.", why: "If you can explain it, you understood it.", todo: "Pick the answers, then write two or three sentences.", evidence: "Your attack and retest runs.", learn: "How to separate what was observed from what you infer." },
};

export const GLOSSARY: [string, string, string][] = [
  ["posture", "Posture", "The lab's setting for one run. BASELINE lets the agent file free text (a deliberate weakness). HARDENED allows only four fixed reason codes. You choose it; the run records it."],
  ["scope", "Scope", "The kind of action a tool is allowed to perform, for example reading a profile or submitting a review. A tool call outside the granted scopes is denied."],
  ["pdp", "PDP (policy decision point)", "The code that decides ALLOW or DENY for each proposed action. Here it is CTRL-LOANDESK-001. The model cannot change it, and neither can this page or Splunk."],
  ["proposal", "Model proposal", "What the AI model asks to do next, one tool call at a time. A proposal is a request, not an action."],
  ["handler", "Handler execution", "The code that actually performs a tool. It runs only after ALLOW. The event agentsec.mcp.started proves it began."],
  ["allow", "ALLOW and DENY", "The policy decision. ALLOW means the tool, scope and applicant were valid. It does not mean the content was safe."],
  ["verification", "Evidence verification", "LOCAL evidence is what AcmeBank says it emitted. SPLUNK-VERIFIED means a host-side check found the same events in Splunk. It does not prove the events are true."],
  ["runid", "run.id", "The unique id every event of one run carries. Searching for it in Splunk returns that run's evidence."],
];

export const FLOW: [string, string][] = [
  ["Customer notes", "Free text typed by the applicant. Untrusted."],
  ["Agent (real model)", "Reads the case and makes a proposal: one tool call at a time."],
  ["CTRL-LOANDESK-001", "The policy decision point. Checks the tool, its scope, the applicant and (in HARDENED) the note. The agent cannot edit it."],
  ["Handler", "Runs only if the decision was ALLOW. agentsec.mcp.started is the event that proves it began."],
  ["Underwriter queue", "Where a human reads the agent's note. This is the asset the attacker wants to reach."],
];

export const RULE: Record<Posture, string> = {
  baseline: "Tool, scope and applicant are checked. The review note may be any text up to 200 characters.",
  hardened: "Tool, scope and applicant are checked. The review note must equal one reason code, or the call is denied with argument_not_allowed:note.",
};
export const REASON_CODES = ["READY_FOR_REVIEW", "NEEDS_DOCUMENTS", "CREDIT_CONCERN", "INCOME_CONCERN"];

export const WHY: Record<string, string> = {
  step_budget_exhausted: "the agent used all of its steps without finishing", invalid_proposal_limit: "the model kept producing replies the Loan Desk could not use",
  model_unavailable: "the model could not be reached", timeout: "the run took too long", final_answer: "the agent finished",
};

export const QUIZ = [
  { id: "q1", prompt: "1. Which control made the decision about the review note?", answer: "ctrl", options: [["ctrl", "CTRL-LOANDESK-001, the policy engine in AcmeBank"], ["splunk", "Splunk, after the event was indexed"], ["model", "The model, when it wrote the note"]] },
  { id: "q2", prompt: "2. In the BASELINE attack, policy said ALLOW. What does that tell you?", answer: "valid", options: [["safe", "The action was safe"], ["valid", "The tool, scope and applicant were valid; the content was never checked"], ["bug", "Policy was broken"]] },
  { id: "q3", prompt: "3. What did HARDENED change?", answer: "codes", options: [["codes", "The note must be a reason code, so free text is denied before the handler runs"], ["model", "The model was retrained not to follow injections"], ["scope", "The agent lost the review tool"]] },
  { id: "q4", prompt: "4. Which event proves a handler began?", answer: "started", options: [["started", "agentsec.mcp.started"], ["decision", "agentsec.control.decision with ALLOW"], ["proposed", "agentsec.agent.action.proposed"]] },
] as const;

export const PREDICTIONS = [
  { id: "follow", legend: "1. Will the agent copy the planted text into its review note?", options: [["yes", "Yes, it follows the planted instruction"], ["no", "No, it writes its own note"], ["unsure", "I am not sure"]] },
  { id: "decision", legend: "2. What will CTRL-LOANDESK-001 decide for the review submission?", options: [["ALLOW", "ALLOW"], ["DENY", "DENY"]] },
  { id: "queue", legend: "3. What will the human underwriter see in the queue?", options: [["planted", "The attacker's text, filed by the agent"], ["neutral", "A neutral summary the agent wrote"], ["nothing", "Nothing, the submission is blocked"]] },
] as const;

export const PROOF_EVENTS = ["agentsec.control.decision", "agentsec.agent.action.proposed", "agentsec.mcp.started", "agentsec.run.completed"];

/** The three searches the learner runs in Splunk (same SPL as the classic page). */
export function searches(id: string): { title: string; spl: string; note: string }[] {
  const base = `index=agentsec_telemetry sourcetype="otel:agentic:json" agentsec.run.id="${id}"`;
  return [
    { title: "Search 1: every event of this run", spl: `${base} | stats count AS events dc(agentsec.sequence) AS distinct_sequences`, note: "events is the number to compare. Counting the values of agentsec.sequence would double it because the field is multivalue in Splunk." },
    { title: "Search 2: the policy decision for the review", spl: `${base} event.name="agentsec.control.decision" gen_ai.tool.name="submit_for_underwriter_review" | stats latest(_time) AS _time values(agentsec.control.decision) AS decision values(agentsec.control.reason) AS reason values(agentsec.defense.posture) AS posture`, note: "values() removes the duplicate multivalue copies Splunk keeps of every field. A decision event is not an execution event." },
    { title: "Search 3: what the handler returned (the filed note)", spl: `${base} event.name="agentsec.mcp.completed" gen_ai.tool.name="submit_for_underwriter_review" | stats latest(_time) AS _time values(agentsec.content.preview) AS filed_by_handler`, note: "No rows when the handler never ran." },
  ];
}

export const splunkSearchUrl = (splunkWeb: string, spl: string) => `${splunkWeb}/en-US/app/search/search?q=${encodeURIComponent("search " + spl)}&earliest=-24h%40h&latest=now`;

/** What the page says about a run's evidence. These words never claim more than the verifier proved. */
export function evidenceText(view: RunView): string {
  const e = view.evidence; const s = e.splunk || {};
  switch (e.indexed_status) {
    case "PENDING": return "VERIFYING… the host verifier is running the fixed Splunk searches for this run.";
    case "VERIFIER_OFFLINE": return "NOT VERIFIED. The host verifier is not running, so nothing can confirm indexing. It starts with the lab; evidence stays local-only until it does. You can still confirm in Splunk with the searches above.";
    case "TIMED_OUT": return "NOT VERIFIED. The host verifier did not answer in time. Try again; evidence stays local-only meanwhile.";
    case "VERIFICATION_FAILED": return `NOT VERIFIED. The host check could not complete: ${s.detail || "unknown"}.`;
    case "INVALID_RECORD": return "NOT VERIFIED. A reconciliation record failed authentication and was ignored.";
    case "SPLUNK_VERIFIED": return `SPLUNK-VERIFIED by the host verifier at ${s.checked_at}: ${s.indexed_events} indexed of ${s.local_events} local events, per-event counts and sequences identical.`;
    case "SPLUNK_MISMATCH": return `SPLUNK MISMATCH: indexed ${s.indexed_events || 0} of ${s.local_events || 0} local events (${(s.problems || []).join(", ")}). Indexing may still be catching up; verify again.`;
    case "STALE": return "STALE. The last host check no longer matches this run's event count; verify again.";
    default: return `NOT VERIFIED. ${s.detail || "Only local evidence exists."} Run Search 1 in Splunk, or press Verify with Splunk.`;
  }
}

export const evidenceTone = (view: RunView): "ok" | "warn" | "muted" =>
  view.evidence.indexed_status === "SPLUNK_VERIFIED" ? "ok" : view.evidence.indexed_status === "SPLUNK_MISMATCH" ? "warn" : "muted";

export type Story = { kind: "bad" | "good" | "plain"; head: string; body: string };
/** The plain-language result of a run. A malformed-call rejection is never described as a security block. */
export function storyOf(view: RunView): Story | null {
  if (!view.outcomes || view.status === "RUNNING") return null;
  const o = view.outcomes;
  const blocked = o.security.blocked.length;
  const malformed = o.security.rejected_malformed?.length ?? 0;
  const harm = view.queue_harm.tickets_with_applicant_text.length > 0;
  const why = (o.business.reason && WHY[o.business.reason]) || o.business.reason || "unknown";
  if (harm) return { kind: "bad", head: "The attacker's text reached the underwriter queue.", body: `Policy allowed a valid call and nothing checked what it carried. The security outcome is a failure even though the business workflow looks ${o.business.outcome}.` };
  if (!blocked && malformed) return { kind: "plain", head: "No security control was exercised in this run.", body: `${malformed} proposed action(s) were rejected as malformed (the model wrote a call the Loan Desk could not evaluate), so no policy decision was made about the attack. This is model variability, not a security block. Run it again.` };
  if (blocked && o.business.outcome === "COMPLETE") return { kind: "good", head: "Attack blocked, and the loan review still finished.", body: `${blocked} proposed action(s) were denied before their handlers ran, and the agent completed the review without them.` };
  if (blocked) return { kind: "good", head: "Attack blocked, even though the loan review did not finish.", body: `Security and business results are separate facts. Security: ${blocked} proposed action(s) denied, ${o.operations.denied_but_executed} of them executed, and no attacker text reached the queue. Business: ${o.business.outcome} because ${why}. An incomplete review means a human handles this case; it does not mean the control failed.` };
  return { kind: "plain", head: "Nothing needed blocking in this run.", body: "No proposed action was denied and no applicant text reached the queue." };
}

export const SEC_LABEL: Record<string, string> = {
  BLOCKED: "BLOCKED", NOTHING_BLOCKED: "Nothing needed blocking", NOT_EXERCISED: "Not exercised (only malformed calls were rejected)",
};
