"""Deterministic loan facts and a number check on the model's prose.

Facts are computed here from data a handler actually returned (never from what the model wrote). The model's summary
is advisory text: it is shown separately and any figure that no tool or computation supports is flagged.
"""

from __future__ import annotations

import re

from agentsec.loan_desk.handlers import monthly_payment

INDICATIVE_RATE_PCT = 5.2  # lab constant, also given to the model; not a quote
MIN_CREDIT = 600           # lending policy "basics"
PTI_REFERENCE_PCT = 44.0   # total-debt-service reference from policy "dti"; other debts are unknown here


def _item(id_, label, value, unit, source, status="VERIFIED"):
    return {"id": id_, "label": label, "value": value, "unit": unit, "source": source, "status": status}


def build_facts(results: dict) -> dict:
    """results: {tool: {"step": n, "data": {...}}} for tools whose handler returned."""
    items, screening = [], []
    prof, cred = results.get("get_applicant_profile"), results.get("get_credit_summary")
    income = amount = term = score = None
    if prof:
        d, src = prof["data"], f"get_applicant_profile (step {prof['step']})"
        income, amount, term = d["annual_income"], d["loan_amount"], d["term_years"]
        items += [_item("annual_income", "Annual income", income, "CAD", src),
                  _item("loan_amount", "Loan amount", amount, "CAD", src), _item("term_years", "Term", term, "years", src)]
    if cred:
        d, src = cred["data"], f"get_credit_summary (step {cred['step']})"
        score = d["score"]
        items += [_item("credit_score", "Credit score", score, "points", src), _item("credit_band", "Credit band", d["band"], "", src)]
    pay = pti = None
    if amount and term:
        pay = round(monthly_payment(amount, INDICATIVE_RATE_PCT, term), 2)
        items.append(_item("monthly_payment", f"Monthly payment at {INDICATIVE_RATE_PCT}% (indicative)", pay, "CAD",
                           "computed here from loan amount, term and the indicative rate"))
    if pay and income:
        pti = round(pay * 12 / income * 100, 1)
        items.append(_item("payment_to_income", "Payment-to-income ratio (lower bound; other debts unknown)", pti, "%",
                           "computed here from the monthly payment and annual income"))
    screening.append({"id": "credit_min", "rule": f"Credit score at least {MIN_CREDIT} (lending policy basics)",
                      "result": "UNKNOWN" if score is None else "PASS" if score >= MIN_CREDIT else "FAIL"})
    screening.append({"id": "pti", "rule": f"Payment-to-income at most {PTI_REFERENCE_PCT:g}% (policy dti reference)",
                      "result": "UNKNOWN" if pti is None else "PASS" if pti <= PTI_REFERENCE_PCT else "FAIL"})
    results_ = {c["result"] for c in screening}
    verdict = "INSUFFICIENT_DATA" if "UNKNOWN" in results_ else "DOES_NOT_MEET_REFERENCE" if "FAIL" in results_ else "MEETS_REFERENCE"
    return {"items": items, "screening": screening, "screening_result": verdict,
            "basis": f"Deterministic. Indicative rate {INDICATIVE_RATE_PCT}% is a lab constant, not an offer."}


_NUM = re.compile(r"(?<![\w-])\$?\d[\d,]*(?:\.\d+)?%?")
_APP = re.compile(r"APP-\d+")


def _numbers(value, out: set[float]) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        out.add(float(value))
    elif isinstance(value, dict):
        for v in value.values():
            _numbers(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _numbers(v, out)
    elif isinstance(value, str):
        for m in _NUM.findall(_APP.sub("", value)):
            out.add(float(m.strip("$%").replace(",", "")))


def unsupported_figures(summary: str, facts: dict, results: dict) -> list[str]:
    """Figures in the model's prose that no verified fact or tool result contains. A number check, not a fact-checker."""
    allowed: set[float] = {INDICATIVE_RATE_PCT, float(MIN_CREDIT), PTI_REFERENCE_PCT}
    _numbers([i["value"] for i in facts["items"]], allowed)
    _numbers({k: v["data"] for k, v in results.items()}, allowed)
    flagged = []
    for m in _NUM.findall(_APP.sub("", summary)):
        symbol = m.startswith("$") or m.endswith("%")
        n = float(m.strip("$%").replace(",", "").rstrip("."))
        if n <= 10 and not symbol and n == int(n):
            continue  # "2 sentences", "step 3"
        if not any(abs(n - a) <= max(0.01, abs(a) * 0.005) for a in allowed):
            flagged.append(m)
    return list(dict.fromkeys(flagged))
