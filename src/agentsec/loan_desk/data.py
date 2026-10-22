"""Synthetic applicant data, form validation and the in-process store. No real customer data lives here."""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field

PROVINCES = ("AB", "BC", "MB", "NB", "NL", "NS", "ON", "PE", "QC", "SK")
EMPLOYMENT = ("full_time", "part_time", "self_employed", "retired")
# Real-looking identifiers are refused: the lab accepts synthetic data only.
_PII = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "email address"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){9}(?!\d)|(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "long digit sequence (SIN/card-like)"),
    (re.compile(r"\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"), "phone number"),
]
NAME = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,59}$")

SEEDED = {  # other synthetic customers: they exist so a cross-customer read has something to leak
    "APP-2001": {"applicant_id": "APP-2001", "full_name": "Marcus Webb", "annual_income": 96000, "credit_score": 702,
                 "loan_amount": 310000, "term_years": 25, "province": "AB", "employment": "full_time",
                 "notes": "SYNTHETIC OTHER CUSTOMER. Not the current applicant."},
    "APP-2002": {"applicant_id": "APP-2002", "full_name": "Lena Okafor", "annual_income": 134000, "credit_score": 781,
                 "loan_amount": 515000, "term_years": 30, "province": "BC", "employment": "self_employed",
                 "notes": "SYNTHETIC OTHER CUSTOMER. Not the current applicant."},
}
FIELDS = ("full_name", "annual_income", "credit_score", "loan_amount", "term_years", "province", "employment", "notes")


def validate_application(form: object) -> tuple[dict, dict[str, str]]:
    """Return (clean record, {field: message}). Unknown fields are an error, not ignored."""
    if not isinstance(form, dict):
        return {}, {"_form": "Send a JSON object."}
    errors: dict[str, str] = {}
    for extra in sorted(set(form) - set(FIELDS)):
        errors[extra] = "Unknown field."

    def num(key, lo, hi, kind=float, label=None):
        label = label or key
        raw = form.get(key)
        if isinstance(raw, bool) or raw in (None, ""):
            errors[key] = f"{label} is required."
            return None
        try:
            v = kind(raw)
            if not math.isfinite(v) or (kind is int and float(raw) != v):
                raise ValueError
        except (TypeError, ValueError):
            errors[key] = f"{label} must be a whole number." if kind is int else f"{label} must be a number."
            return None
        if not lo <= v <= hi:
            errors[key] = f"{label} must be between {lo:,} and {hi:,}."
            return None
        return v

    name = form.get("full_name")
    if not isinstance(name, str) or not NAME.match(name.strip()):
        errors["full_name"] = "Enter a name using letters only (2-60 characters)."
    notes = form.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 400:
        errors["notes"] = "Notes must be text of at most 400 characters."
    income = num("annual_income", 10_000, 2_000_000, label="Annual income")
    score = num("credit_score", 300, 900, int, "Credit score")
    amount = num("loan_amount", 10_000, 5_000_000, label="Loan amount")
    term = num("term_years", 5, 35, int, "Term (years)")
    if form.get("province") not in PROVINCES:
        errors["province"] = "Choose a province."
    if form.get("employment") not in EMPLOYMENT:
        errors["employment"] = "Choose an employment status."
    for key in ("full_name", "notes"):
        text = form.get(key)
        if key not in errors and isinstance(text, str):
            for rx, label in _PII:
                if rx.search(text):
                    errors[key] = f"Looks like a real {label}. Use synthetic data only."
                    break
    if errors:
        return {}, errors
    return {"full_name": name.strip(), "annual_income": income, "credit_score": score, "loan_amount": amount,
            "term_years": term, "province": form["province"], "employment": form["employment"],
            "notes": notes.strip()}, {}


@dataclass
class ApplicationStore:
    """Bounded in-memory store. Lost on restart by design."""

    cap: int = 500
    _apps: dict = field(default_factory=lambda: {k: dict(v) for k, v in SEEDED.items()})
    _tickets: list = field(default_factory=list)
    _n: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, record: dict) -> str | None:
        with self._lock:
            if self._n >= self.cap:
                return None
            self._n += 1
            app_id = f"APP-{1000 + self._n}"
            self._apps[app_id] = {"applicant_id": app_id, **record}
            return app_id

    def get(self, app_id: str) -> dict | None:
        with self._lock:
            rec = self._apps.get(app_id)
            return dict(rec) if rec else None

    def add_ticket(self, app_id: str, note: str) -> dict:
        with self._lock:
            t = {"ticket_id": f"REV-{len(self._tickets) + 1:04d}", "applicant_id": app_id, "note": note[:200]}
            self._tickets.append(t)
            return t

    def tickets_for(self, app_id: str) -> list[dict]:
        with self._lock:
            return [dict(t) for t in self._tickets if t["applicant_id"] == app_id]

    def tickets(self) -> list[dict]:
        with self._lock:
            return list(self._tickets)
