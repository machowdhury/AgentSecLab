import raw from "./content/curriculum.json";

// The 12-domain curriculum and the 32 registered labs, exported from the repository's own sources by scripts/export_curriculum.py.
// Availability is the registry's tier. Registry membership is NOT verified execution; see the availability descriptions below.
export type Availability = "guided" | "workbench" | "replay" | "content_only";
export interface Entry { text: string; source: string }
export interface PathNode { id: string; kind: "attacker" | "entry" | "boundary" | "control" | "operation" | "evidence"; label: string; detail: string; source: string; fact: string; outcomes?: { label: string; detail: string; source: string; fact: string }[] }
export type RecEvent = Record<string, string | number | boolean | string[] | null | undefined>;
export interface RecRun {
  role: string; run_id: string; pack: string; sha256: string; decisive: number; documented_as: { text: string; source: string };
  meta: { attack_id: string; mode: string; profile: string; schema_version: string; execution_mode: string; fidelity: string; trace_id: string; principal: string; workflow_entry: string; started: string; ended: string; event_count: number };
  events: RecEvent[];
}
export interface Spl { name: string; source: string; text: string }
export interface Recorded { options: string[]; runs: RecRun[]; spl: Spl[] }
export type Ref =
  | { src: "event"; scenario: string; stage: string; where?: { control?: string; event?: string; nth?: "first" | "last" }; field: string; json?: string }
  | { src: "external"; scan: string; path: string[] }
  | { src: "run"; scenario: string; stage: string };
export type Eval = { kind: "value"; ref: Ref } | { kind: "equal"; a: Ref; b: Ref } | { kind: "handler"; scenario: string; stage: string; tool: string };
export interface Question { id: string; prompt: string; choices: string[]; eval: Eval; quote: { file: string; text: string }; teach: string }
export interface InvRun { stage: string; run_id: string; pack: string; sha256: string; meta: RecRun["meta"]; events: RecEvent[] }
export interface Scenario { id: string; label: string; documented_in: string; runs: InvRun[] }
export interface External { scan_id: string; pack: string; sha256: string; documented_in: string; records: Record<string, unknown>[] }
export interface Block { group: "hints" | "prove" | "limits" | "rules" | "assess"; title: string; source: string; items: string[] }
export interface Investigation {
  kind: "investigation"; brief: { paragraphs: string[]; source: string }; scenarios: Scenario[]; external: External[]; questions: Question[];
  graph?: { scope: string; allowed_edge_semantics: string[]; forbidden_unless_established: string[]; nodes: { id: string; kind: string; label: string; state: string }[]; edges: { from: string; to: string; semantic: string; basis: string }[]; source: string };
  control_analysis?: { states: string[]; controls: Record<string, string>[]; source: string };
  blocks: Block[]; spl: Spl[];
}
export type Derived =
  | { kind: "within"; at: string; window: { packet_path?: string; from: string; to: string; lookup?: { list: string; key: string; by: string } }; inside: string; outside: string }
  | { kind: "equals"; a: string; b_packet: string };
export interface Prediction { id: string; question: string; field: string; options: string[]; match?: "equals" | "startswith"; reason_field?: string; derived?: Derived }
export interface Labelled { label: string; field: string }
export interface Pathed { label: string; path: string }
export interface InvQuestion { id: string; prompt: string; where: { field: string; equals?: string; not_equals?: string; contains?: string }; quote: { file: string; text: string } }
export interface CheckpointSpec {
  kind?: "inventory"; order?: string[]; context?: Pathed[]; setup?: Labelled[]; predictions?: Prediction[]; outcome?: Labelled[]; diff?: Labelled[]; decisive?: Labelled[];
  packet_facts: Pathed[]; tables?: { title: string; path: string; columns: [string, string][] }[]; lists?: { title: string; path: string }[];
  items_path?: string; name_field?: string; columns?: [string, string][]; questions?: InvQuestion[];
}
export interface Checkpoint { kind: "checkpoint"; packet_file: string; sha256: string; packet: Record<string, any>; spec: CheckpointSpec; spl: Spl[] } // eslint-disable-line @typescript-eslint/no-explicit-any
export type RecordedFile = (Recorded & { kind: "decision" }) | Investigation | Checkpoint;
export interface Explainer {
  status: "full" | "partial"; authored: { on: string; note: string };
  summary?: { text: string; grounds: string[]; facts: string[] };
  glance?: { id: string; label: string; text: string; grounds: string[]; facts: string[] }[];
  path?: PathNode[]; terms?: { term: string; text: string; source: string; fact: string }[];
  known?: { text: string; grounds: string[]; facts: string[] }[];
  practice?: { predict?: { label: string; source: string; text: string }[]; defender?: { text: string; grounds: string[]; facts: string[] } };
  recorded_table?: { title: string; caption: string; source: string; columns: string[]; rows: string[][] };
  workbench?: { kind: string; specimens: Record<string, string>; resolved: Record<string, { text: string; source: string }> };
  spl?: { name: string; source: string; text: string }[];
  identifiers?: { label: string; value: string; source: string }[];
  cannot_claim?: { source: string; items: string[] };
  recorded?: Recorded;
  recorded_ref?: { kind: "decision" | "investigation"; file: string };
}
export interface Lab {
  id: string; title: string; level: string | null; primary_domain: string; secondary_domain: string | null; domain_confidence: string;
  tier: string; availability: Availability; launchable: boolean; native: string | null; integrated: boolean;
  registry_quote: { file: string; quote: string } | null;
  sections: { learn: ({ items: string[]; source: string } | Entry) | null; idea: Entry | null; problem: Entry | null; why: Entry | null; controls: Entry | null; boundary: Entry | null; how: Entry | null; predict: Entry | null; defend: Entry | null; conclude: Entry | null };
  rules: string[]; explainer: Explainer | null; limitations: { items: string[]; source: string } | null;
  assets: { specimens: string[]; hunts: string[]; dashboard: string | null; evidence_docs: string[] };
  checks: { q: string; a: string | null }[]; checks_source: string | null;
}
export interface Domain { id: string; name: string; taxonomy_title: string; source: string }
export const CURRICULUM = raw as unknown as { inventory_date: string; domains: Domain[]; labs: Lab[]; sources: string[] };

export const AVAIL: Record<Availability, { label: string; blurb: string }> = {
  guided: { label: "Guided", blurb: "A complete guided exercise in this Academy: a live attack and retest with recorded evidence." },
  workbench: { label: "Workbench", blurb: "Registered as a live attack and retest lab on the Attack Service. It is not integrated in this Academy yet." },
  replay: { label: "Replay", blurb: "Recorded evidence only. There is no live run for this lab." },
  content_only: { label: "Content only", blurb: "Reading material and any knowledge checks the lab defines. No execution exists for this lab." },
};
export const AVAIL_ORDER: Availability[] = ["guided", "workbench", "replay", "content_only"];
export const REGISTRY_NOTE = "Registry membership is not verified execution. An availability label says what the registry records for a lab, not that it has been run or validated.";
export const labsOf = (domainId: string) => CURRICULUM.labs.filter((l) => l.primary_domain === domainId);
export const labById = (id: string) => CURRICULUM.labs.find((l) => l.id === id);
export const domainName = (id: string | null) => CURRICULUM.domains.find((d) => d.id === id)?.name ?? id ?? "";
