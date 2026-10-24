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
export interface Recorded { options: string[]; runs: RecRun[]; spl: { name: string; source: string; text: string }[] }
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
