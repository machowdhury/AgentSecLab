// MAESTRO threat-modeling workbench types. The content (layers, AcmeBank elements, example, rubric) is learning/level_1/LAB-THREAT-MODELING-001/maestro.json,
// exported to src/content/maestro.json by scripts/export_curriculum.py. Nothing here authorizes, denies or detects anything.
export type Impact = "LOW" | "MODERATE" | "HIGH";
export type Likelihood = "UNLIKELY" | "POSSIBLE" | "LIKELY";
export type Level = "LOW" | "MEDIUM" | "HIGH";
export type Evidence = "DEMONSTRATED" | "DOCUMENTED" | "ASSUMED";
export interface Judgment { impact: Impact | null; likelihood: Likelihood | null; rationale: string }
export interface Threat {
  id: string; layer: number; label: string; custom: boolean; kind: "traditional" | "agentic"; description: string; elements: string[]; evidence: Evidence | "";
  scenarios: string[]; controls: string[]; inherent: Judgment; mitigation: string; residual: Judgment;
}
export interface PathStep { layer: number; threat: string; note: string }
export interface Path { id: string; name: string; narrative: string; steps: PathStep[] }
export interface BoundaryAnswer { found: boolean; layers: [number, number] }
export interface Model { scope: string; placements: Record<string, number>; boundaries: Record<string, BoundaryAnswer>; threats: Threat[]; paths: Path[] }

export interface Layer { n: number; name: string; description: string; vertical: boolean; official_threats: string[] }
export interface Element { id: string; name: string; layer: number; also: number[]; kind: string; evidence: string[]; note: string }
export interface Boundary { id: string; name: string; layers: [number, number]; source: string; note: string }
export interface Interaction { id: string; from: string; to: string; layers: [number, number]; data: string; trust: string }
export interface Control { id: string; name: string; class: string; layer: number }
export interface Scenario { lab_id: string; family: string; layers: number[]; labels: string[]; what: string }
export interface Criterion { id: string; title: string; check: string; text: string }
export interface Data {
  framework: { name: string; expansion: string; author: string; published: string; sources: { id: string; title: string; url: string; role: string }[]; layers: Layer[]; cross_layer_threats: string[];
    method: { n: number; name: string; does: string }[]; notes: string[]; mitigation_categories: { cross_layer: string[]; ai_specific: string[] } };
  analyzer: { name: string; repository: string; licence: string; provenance_note: string; status_here: string; compare: string[] };
  risk: { impact: { id: Impact; label: string; definition: string }[]; likelihood: { id: Likelihood; label: string; definition: string }[]; matrix: Record<string, Record<string, Level>> };
  risk_method: { why: string };
  acmebank: { scenario: string; elements: Element[]; boundaries: Boundary[]; interactions: Interaction[]; controls: Control[]; scenarios: Scenario[] };
  example: { scope: string; register: (Omit<Threat, "elements"> & { elements: string[] })[]; paths: (Path & { scenarios: string[]; demonstrated: string })[] };
  rubric: { criteria: Criterion[]; pass: string; thresholds: Record<string, number> };
  families: string[];
  status: string;
}
export interface Result { id: string; title: string; state: "MET" | "PARTIAL" | "NOT MET"; detail: string }
export interface Assessment { results: Result[]; applied: boolean }
