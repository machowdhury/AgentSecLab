"""Model names: the roles, the validation and the normalisation rule. Standard library only, so the installer can use it without the application's dependencies.
See model_identity.py for how a requested name is resolved against what Ollama has installed."""
from __future__ import annotations

import os
import re

#: role -> (environment variable that names the model, default). The variable names are the long-standing ones: nothing configured changes.
ROLES: dict[str, tuple[str, str]] = {
    "pipeline": ("OLLAMA_MODEL", "llama3.2:1b"),       # AcmeBank pipeline labs (LAB-PI-001, MCP, RAG, memory, goal, identity ...)
    "loan_desk": ("LOANDESK_MODEL", "llama3.2:latest"),  # the interactive Loan Desk mission
}
NAME_RE = re.compile(r"^(?!.*\.\.)(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?/)?[A-Za-z0-9][A-Za-z0-9._/-]{0,127}(:[A-Za-z0-9][A-Za-z0-9._-]{0,63})?$")



class ModelConfigError(ValueError):
    """The configured model name is not a valid Ollama model name. Raised at start-up so a typo is never silently run."""


def normalize(name: str) -> str:
    """Ollama's own rule: a name without a tag means `:latest`. Case and spelling are otherwise kept exactly."""
    n = (name or "").strip()
    if not NAME_RE.match(n) or "//" in n or "/:" in n or n.split(":")[0].endswith("/"):
        raise ModelConfigError(f"{n[:60]!r} is not a valid Ollama model name (expected name or name:tag)")
    return n if ":" in n.rsplit("/", 1)[-1] else n + ":latest"      # a registry port (host:5000/name) is not a tag


def default_for(role: str) -> str:
    return ROLES[role][1]


def requested(role: str, env: dict | None = None) -> str:
    """The configured model for a role: the role's variable if set, otherwise the role's default. Validated; returned as configured (not tag-normalised)."""
    var, default = ROLES[role]
    raw = ((os.environ if env is None else env).get(var) or "").strip() or default
    normalize(raw)  # raises ModelConfigError on a malformed name
    return raw


def requested_or_raw(role: str, env: dict | None = None) -> tuple[str, str | None]:
    """(name, problem). A malformed name is returned as configured with the problem text instead of raising, so a typo cannot stop the whole application
    (the Academy and REPLAY need no model); every live call with such a name is refused by resolve() (fail closed)."""
    var, default = ROLES[role]
    raw = ((os.environ if env is None else env).get(var) or "").strip() or default
    try:
        normalize(raw)
        return raw, None
    except ModelConfigError as exc:
        return raw[:200], str(exc)
