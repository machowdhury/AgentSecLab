"""Constrained read-only SPL policy for searches the APPLICATION builds and sends to Splunk.

This is an allowlist for a small, fixed dialect, NOT a sanitizer for arbitrary SPL. Arbitrary SPL cannot be made safe by pattern matching: macros,
subsearches, comments, aliases and app-defined commands all change what Splunk executes. So the policy does not try to understand SPL; it accepts
only text that cannot contain any of those constructs and whose every pipeline stage starts with a command the application actually uses:

- ASCII printable text only, at most MAX_CHARS characters and MAX_STAGES pipeline stages.
- No backtick (macros and comments) and no square brackets (subsearches), anywhere, even inside quotes.
- EVERY `|` starts a new stage, even one that looks quoted: Splunk and this check may disagree about quoting, and treating each pipe as a stage
  boundary means a stage Splunk could see is always a stage this check sees. A literal pipe inside a string is therefore refused.
- The first stage is a plain search (optionally starting with the word `search`), or the query starts with `| makeresults`.
- Every later stage must start with one of ALLOWED_COMMANDS. `index=` may appear only in the first stage.

The credential is still the real control: the token should be search-only on one index (Splunk enforces that). This policy narrows what the
application itself can ever ask for, and is applied on every backend (REST token and the bundled admin path). Splunk's own audit log (_audit)
records the searches that run under the token. This module also writes a hash-only audit line (never the SPL text or any secret).
"""
from __future__ import annotations

import hashlib
import logging
import re

MAX_CHARS = 8192
MAX_STAGES = 16
ALLOWED_COMMANDS = frozenset({"eval", "fillnull", "head", "rename", "sort", "stats", "table", "where"})
GENERATING_COMMANDS = frozenset({"makeresults"})
# Only to give a clearer message; the allowlist, not this list, is what protects.
KNOWN_MUTATING = frozenset({"delete", "outputlookup", "outputcsv", "collect", "mcollect", "meventcollect", "sendemail", "script", "run", "dbxquery", "rest",
                            "tscollect", "sendalert", "map", "loadjob", "savedsearch", "crawl", "input", "audit", "diag", "outputtelemetry", "webhook",
                            "runshellscript", "summaryindex", "sichart", "ldapsearch", "ldapfetch", "ldapgroup", "ldapfilter", "curl"})
_WORD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])")
_INDEX = re.compile(r"\bindex\s*=", re.IGNORECASE)
audit = logging.getLogger("agentsec.splunk.audit")


class SplPolicyViolation(ValueError):
    """code is fixed and safe to show; the message never echoes the search text."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fingerprint(spl: object) -> str:
    return hashlib.sha256(spl.encode("utf-8", "replace") if isinstance(spl, str) else b"").hexdigest()[:16]


def check(spl: object) -> str:
    """Returns the whitespace-normalised search, or raises SplPolicyViolation. Nothing is sent anywhere by this function."""
    if not isinstance(spl, str) or not spl.strip():
        raise SplPolicyViolation("empty", "empty search")
    if len(spl) > MAX_CHARS:
        raise SplPolicyViolation("oversized", "oversized search")
    text = " ".join(spl.split())
    if any(not 0x20 <= ord(c) < 0x7F for c in text):
        raise SplPolicyViolation("disallowed_character", "only printable ASCII is accepted")
    if "`" in text or "[" in text or "]" in text:
        raise SplPolicyViolation("subsearch_or_macro", "macros, comments and subsearches are not accepted")
    stages = [s.strip() for s in text.split("|")]
    if len(stages) > MAX_STAGES:
        raise SplPolicyViolation("too_many_stages", "too many pipeline stages")
    first, rest = stages[0], stages[1:]
    if first == "":                                        # a generating query: | makeresults ...
        if not rest or not _is(rest[0], GENERATING_COMMANDS):
            raise SplPolicyViolation("command_not_allowed", f"generating command '{_name(rest[0]) if rest else ''}' is not accepted")
        rest = rest[1:]
    elif first.split(None, 1)[0].lower() == "search" and len(first.split(None, 1)) == 1:
        raise SplPolicyViolation("empty", "empty search")
    for stage in rest:
        name = _name(stage)
        if name not in ALLOWED_COMMANDS:
            raise SplPolicyViolation("command_not_allowed", f"command '{name or '?'}' is not allowed" + (" (mutating or external)" if name in KNOWN_MUTATING else ""))
        if _INDEX.search(stage):
            raise SplPolicyViolation("index_outside_base_search", "index= may appear only in the base search")
    return text


def _name(stage: str) -> str:
    m = _WORD.match(stage.strip())
    return m.group(1).lower() if m else ""


def _is(stage: str, names: frozenset) -> bool:
    return _name(stage) in names


def checked(spl: object, *, backend: str) -> str:
    """check() plus the audit line. Raises SplPolicyViolation after logging a hash-only refusal."""
    try:
        text = check(spl)
    except SplPolicyViolation as exc:
        audit.warning("splunk_search REFUSED backend=%s code=%s sha256=%s", backend, exc.code, fingerprint(spl))
        raise
    audit.info("splunk_search ACCEPTED backend=%s sha256=%s chars=%d stages=%d", backend, fingerprint(text), len(text), text.count("|") + 1)
    return text
