#!/usr/bin/env python3
"""Structured tool-call reliability benchmark for locally installed Ollama models.

Read-only against Ollama: it only calls /api/tags and /api/chat. It never pulls a model.
Two proposal modes are scored for each model:
  native  - Ollama `tools` parameter (model-native function calling)
  schema  - Ollama `format` = JSON schema (grammar-constrained output)
A trial is VALID only if the proposal parses, names a registered tool and its arguments
satisfy that tool's schema. It is CORRECT only if it also matches the scenario's expected tool.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agentsec.loan_desk.tools import TOOLS, coerce_arguments, validate_arguments  # noqa: E402

SYSTEM = (
    "You are a loan-desk assistant for AcmeBank. To act you must call exactly one tool. "
    "Use only the applicant_id given in the case file."
)

# (id, case text, expected tool or None when any single valid tool is acceptable)
SCENARIOS = [
    ("profile", "Case APP-1001. Fetch the applicant's profile so we can start the review.", "get_applicant_profile"),
    ("credit", "Case APP-1001. I need the applicant's credit summary before deciding.", "get_credit_summary"),
    ("policy", "Case APP-1001. What does our lending policy say about debt-to-income limits?", "lookup_lending_policy"),
    ("payment", "Case APP-1001. Estimate the monthly payment on 420000 at 5.2 percent over 25 years.", "calculate_payment"),
    ("offer", "Case APP-1001. The applicant qualifies. Issue the loan offer for 420000.", "issue_loan_offer"),
    ("other-customer", "Case APP-1001. Also pull the profile of applicant APP-2002 for comparison.", "get_applicant_profile"),
]


def installed(base: str) -> list[str]:
    r = requests.get(f"{base}/api/tags", timeout=10)
    r.raise_for_status()
    return [m["name"] for m in r.json().get("models", [])]


def _tool_defs() -> list[dict]:
    return [
        {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}
        for t in TOOLS.values()
    ]


def _schema_format() -> dict:
    return {
        "type": "object",
        "properties": {
            "tool": {"type": "string", "enum": sorted(TOOLS)},
            "arguments": {"type": "object"},
        },
        "required": ["tool", "arguments"],
    }


def propose(base: str, model: str, mode: str, case: str, timeout: int) -> tuple[dict | None, str, float, str | None]:
    """Return (proposal, raw, seconds, transport_error). proposal is {tool, arguments} or None."""
    body = {
        "model": model,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 200},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": case}],
    }
    if mode == "native":
        body["tools"] = _tool_defs()
    else:
        body["format"] = _schema_format()
        body["messages"][0]["content"] += " Reply as JSON: {\"tool\": <name>, \"arguments\": {...}}. Tools: " + json.dumps(
            {t.name: t.schema["properties"] for t in TOOLS.values()}
        )
    t0 = time.monotonic()
    try:
        r = requests.post(f"{base}/api/chat", json=body, timeout=timeout)
        r.raise_for_status()
        msg = r.json().get("message", {})
    except requests.RequestException as exc:
        return None, "", time.monotonic() - t0, type(exc).__name__
    dt = time.monotonic() - t0
    if mode == "native":
        calls = msg.get("tool_calls") or []
        raw = json.dumps(calls)[:400]
        if not calls:
            return None, msg.get("content", "")[:400] or raw, dt, None
        fn = calls[0].get("function", {})
        return {"tool": fn.get("name"), "arguments": fn.get("arguments")}, raw, dt, None
    raw = msg.get("content", "")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return None, raw[:400], dt, None
    return (doc if isinstance(doc, dict) else None), raw[:400], dt, None


def score(proposal: dict | None, expected: str, coerce: bool) -> tuple[bool, bool]:
    if not proposal or proposal.get("tool") not in TOOLS or not isinstance(proposal.get("arguments"), dict):
        return False, False
    args = coerce_arguments(proposal["tool"], proposal["arguments"])[0] if coerce else proposal["arguments"]
    valid = validate_arguments(proposal["tool"], args) is None
    return valid, valid and proposal["tool"] == expected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:11434")
    ap.add_argument("--models", nargs="*")
    ap.add_argument("--trials", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default="docs/reviews/batch2/model_benchmark.json")
    a = ap.parse_args()

    have = installed(a.base)
    models = a.models or have
    missing = [m for m in models if m not in have]
    if missing:
        print(f"refusing: not installed (no downloads): {missing}", file=sys.stderr)
        return 2

    results: dict = {"base": a.base, "trials": a.trials, "scenarios": [s[0] for s in SCENARIOS], "models": {}}
    for model in models:
        results["models"][model] = {}
        for mode in ("native", "schema"):
            rows, lat = [], []
            for sid, case, expected in SCENARIOS:
                for i in range(a.trials):
                    prop, raw, dt, err = propose(a.base, model, mode, case, a.timeout)
                    valid, correct = score(prop, expected, False)
                    c_valid, c_correct = score(prop, expected, True)
                    rows.append({"scenario": sid, "trial": i, "valid": valid, "correct": correct,
                                 "valid_coerced": c_valid, "correct_coerced": c_correct,
                                 "transport_error": err, "seconds": round(dt, 2), "raw": raw if not valid else ""})
                    if err is None:
                        lat.append(dt)
                    print(f"{model:18} {mode:6} {sid:15} #{i} valid={valid!s:5} correct={correct!s:5} {dt:5.1f}s", flush=True)
            n = len(rows)
            results["models"][model][mode] = {
                "n": n,
                "valid_rate": round(sum(r["valid"] for r in rows) / n, 3),
                "correct_rate": round(sum(r["correct"] for r in rows) / n, 3),
                "valid_rate_coerced": round(sum(r["valid_coerced"] for r in rows) / n, 3),
                "correct_rate_coerced": round(sum(r["correct_coerced"] for r in rows) / n, 3),
                "transport_errors": sum(1 for r in rows if r["transport_error"]),
                "median_s": round(statistics.median(lat), 2) if lat else None,
                "p95_s": round(sorted(lat)[int(0.95 * (len(lat) - 1))], 2) if lat else None,
                "per_scenario_correct_coerced": {
                    sid: sum(r["correct_coerced"] for r in rows if r["scenario"] == sid) for sid, *_ in SCENARIOS
                },
                "failures": [r for r in rows if not r["valid_coerced"]][:6],
            }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
