// Runs the Academy's MAESTRO logic (academy-ui/src/maestro, pure TypeScript) in Node and prints JSON. Input on stdin: {data, cases:{name: model|"example"|"empty"}}.
import { assess, exampleModel, emptyModel, prioritize } from "../academy-ui/src/maestro/assess.ts";
import { markdown, exportDoc, cell } from "../academy-ui/src/maestro/report.ts";
let raw = ""; for await (const c of process.stdin) raw += c;
const { data, cases } = JSON.parse(raw);
const fake = (t) => "h" + t.length;
const out = {};
for (const [name, spec] of Object.entries(cases)) {
  const m = spec === "example" ? exampleModel(data) : spec === "empty" ? emptyModel() : spec;
  out[name] = { assess: assess(m, data), rank: prioritize(m, data).map((t) => t.id), md: markdown(m, data, fake, "2026-01-01T00:00:00Z"), doc: exportDoc(m, data, fake) };
}
out.__cell = [cell("a|b\nc<script>"), cell("")];
console.log(JSON.stringify(out));
