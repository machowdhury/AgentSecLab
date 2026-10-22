"""Test doubles for the Loan Desk. They are labelled test_double, so no run they drive is ever shown as model-driven."""

from __future__ import annotations

import json

from agentsec.loan_desk.model import ModelReply


class ScriptedModel:
    name, source = "scripted-test-double", "test_double"

    def __init__(self, replies: list) -> None:
        self.replies, self.calls = list(replies), 0

    def chat(self, messages):
        self.calls += 1
        item = self.replies.pop(0) if self.replies else self.replies_last
        self.replies_last = item
        text = item if isinstance(item, str) else json.dumps(item)
        return ModelReply(text=text, tokens_in=10, tokens_out=5, model=self.name, latency_ms=1)


class UnavailableModel:
    name, source = "scripted-test-double", "test_double"

    def __init__(self, error_type="connection_error", message="ConnectionError") -> None:
        self.error_type, self.message = error_type, message

    def chat(self, messages):
        return ModelReply("", error_type=self.error_type, error_message=self.message)


def tool(name, **arguments):
    return {"action": "tool", "tool": name, "arguments": arguments}


FINAL = {"action": "final", "summary": "Income and credit profile are consistent with lending policy for this request.", "recommendation": "PROCEED_TO_UNDERWRITER"}
GOOD_FORM = {"full_name": "Priya Chen", "annual_income": 118000, "credit_score": 740, "loan_amount": 420000,
             "term_years": 25, "province": "ON", "employment": "full_time", "notes": "First-time buyer."}
