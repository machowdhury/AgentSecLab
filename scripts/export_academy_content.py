#!/usr/bin/env python3
"""Export existing Academy learning content (Foundations lessons, workshop knowledge checks) for the React Academy.

Single source stays where it is (academy_web.FOUNDATION_LESSONS, learning/**/workshop.json). Re-run after editing either, then rebuild the UI.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.academy_web import FOUNDATION_LESSONS  # noqa: E402


def checks(lab: str) -> list[dict]:
    doc = json.loads((ROOT / "learning" / "level_1" / lab / "workshop.json").read_text(encoding="utf-8"))
    return [{"id": c["id"], "question": c["question"], "answer": c["answer"]} for c in doc["checks"]]


out = {"foundations": [dict(x, flow=list(x["flow"])) for x in FOUNDATION_LESSONS],
       "checks": {"loandesk": checks("LAB-LOANDESK-001"), "mcp": checks("LAB-MCP-001")}}
dest = ROOT / "academy-ui" / "src" / "content" / "academy-content.json"
dest.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {dest.relative_to(ROOT)}: {len(out['foundations'])} lessons, {len(out['checks']['loandesk'])}+{len(out['checks']['mcp'])} checks")
