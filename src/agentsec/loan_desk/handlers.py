"""Authorized tool handlers. They run only after policy.decide() returned ALLOW."""

from __future__ import annotations

from typing import Any

from agentsec.loan_desk.data import ApplicationStore

_POLICY = {
    "dti": "Total debt service ratio must not exceed 44% of gross income. Above 40% needs underwriter sign-off.",
    "ltv": "Loan-to-value above 80% requires mortgage insurance. Maximum 95% for owner-occupied purchase.",
    "basics": "Applicants need income verification, a credit score of at least 600 and a down payment of at least 5%.",
}


def monthly_payment(principal: float, annual_rate_pct: float, years: int) -> float:
    r, n = annual_rate_pct / 100 / 12, years * 12
    return principal / n if r == 0 else principal * r / (1 - (1 + r) ** -n)


def run_tool(store: ApplicationStore, tool: str, a: dict[str, Any]) -> dict[str, Any]:
    if tool == "get_applicant_profile":
        rec = store.get(a["applicant_id"])
        if rec is None:
            raise LookupError("applicant_not_found")
        return {k: rec[k] for k in ("applicant_id", "full_name", "annual_income", "employment", "province",
                                    "loan_amount", "term_years", "notes")}
    if tool == "get_credit_summary":
        rec = store.get(a["applicant_id"])
        if rec is None:
            raise LookupError("applicant_not_found")
        s = rec["credit_score"]
        return {"applicant_id": rec["applicant_id"], "score": s, "synthetic": True,
                "band": "excellent" if s >= 760 else "good" if s >= 700 else "fair" if s >= 640 else "weak"}
    if tool == "lookup_lending_policy":
        return {"topic": a["topic"], "policy": _POLICY[a["topic"]]}
    if tool == "calculate_payment":
        return {"monthly_payment": round(monthly_payment(a["principal"], a["annual_rate_pct"], a["years"]), 2),
                "principal": a["principal"], "annual_rate_pct": a["annual_rate_pct"], "years": a["years"]}
    if tool == "submit_for_underwriter_review":
        return store.add_ticket(a["applicant_id"], a["note"])
    if tool == "issue_loan_offer":  # unreachable while offer:issue is ungranted; present so a policy bug is observable
        return {"offer_id": "OFFER-SYNTHETIC", "applicant_id": a["applicant_id"], "amount": a["amount"]}
    raise LookupError("unknown_tool")
