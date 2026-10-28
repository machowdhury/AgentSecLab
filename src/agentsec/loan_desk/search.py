"""Fixed-template Splunk search gateway for the Academy notebook.

Learners never send SPL. They send a template id and a few validated parameters; the SPL is built HERE (by the host verifier,
which re-validates everything) with the index, sourcetype, time bound and run-id constraint always present. The execution
backend is a small interface so a least-privilege Splunk REST backend can replace the docker-exec one without touching callers or the UI.
"""

from __future__ import annotations

import csv
import io
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BASE = 'index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-24h "agentsec.run.id"="{run}"'
BASE2 = 'index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-24h ("agentsec.run.id"="{run}" OR "agentsec.run.id"="{other}")'
MAX_ROWS = 50          # rows returned to the browser, whatever the template asks for
MAX_COLS = 12
MAX_CELL = 400         # characters per value; event data is untrusted and may be huge
SEARCH_TIMEOUT_S = 30


class SearchError(ValueError):
    """A request that must be refused (unknown template, bad parameter, bad run id). The message is safe to show."""


@dataclass(frozen=True)
class Param:
    name: str
    kind: str                      # "int" | "enum"
    default: object
    label: str
    lo: int = 1
    hi: int = 50
    choices: tuple[str, ...] = ()

    def clean(self, value: object) -> object:
        if value is None:
            return self.default
        if self.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not self.lo <= value <= self.hi:
                raise SearchError(f"{self.label} must be a whole number from {self.lo} to {self.hi}.")
            return value
        if not isinstance(value, str) or value not in self.choices:
            raise SearchError(f"{self.label} must be one of: {', '.join(self.choices)}.")
        return value

    def public(self) -> dict:
        d = {"name": self.name, "kind": self.kind, "default": self.default, "label": self.label}
        return {**d, "lo": self.lo, "hi": self.hi} if self.kind == "int" else {**d, "choices": list(self.choices)}


@dataclass(frozen=True)
class Template:
    id: str
    title: str
    params: tuple[Param, ...]
    body: str                      # str.format template; only validated values are ever substituted
    chart: str | None = None       # "bar" when the first column is a label and the second a count
    runs: int = 1                  # 2 = a comparison: {run} is the baseline run and {other} the defended (retest) run

    def build(self, run_id: str, raw: object, compare_run: object = None) -> tuple[str, dict]:
        if not isinstance(run_id, str) or not UUID.match(run_id):
            raise SearchError("run id must be a lowercase UUID.")
        if self.runs == 2:
            if not isinstance(compare_run, str) or not UUID.match(compare_run) or compare_run == run_id:
                raise SearchError("A comparison needs two different run ids.")
            scope = BASE2.format(run=run_id, other=compare_run)
        elif compare_run is not None:
            raise SearchError("This search takes one run.")
        else:
            scope = BASE.format(run=run_id)
        raw = {} if raw is None else raw
        if not isinstance(raw, dict) or set(raw) - {p.name for p in self.params}:
            raise SearchError("Unknown parameter.")
        clean = {p.name: p.clean(raw.get(p.name)) for p in self.params}
        spl = " ".join((scope + " " + self.body.format(run=run_id, other=compare_run, **clean)).split())
        return spl, clean

    def public(self) -> dict:
        return {"id": self.id, "title": self.title, "params": [p.public() for p in self.params], "chart": self.chart, "runs": self.runs}


GROUP_FIELDS = ("event.name", "gen_ai.tool.name", "agentsec.control.decision")
LIMIT = Param("limit", "int", 20, "Rows", 1, 50)
# Splunk keeps duplicate multivalue copies of every field; mvindex(mvdedup(...),0) takes one value per event so counts stay honest.
_SIDE = ('eval side=if(mvindex(mvdedup(\'agentsec.run.id\'),0)="{run}","baseline","defended")')
_TOOL_EVENTS = 'gen_ai.tool.name="submit_for_underwriter_review" (event.name="agentsec.agent.action.proposed" OR event.name="agentsec.control.decision" OR event.name="agentsec.mcp.completed")'

TEMPLATES: dict[str, Template] = {t.id: t for t in (
    Template("events_by_field", "Count this run's events by a field",
             (Param("field", "enum", "event.name", "Group by", choices=GROUP_FIELDS), LIMIT),
             "| eval grp=mvindex(mvdedup('{field}'),0) | fillnull value=\"(none)\" grp | stats count AS events by grp "
             "| rename grp AS \"{field}\" | sort 0 - events | head {limit}", chart="bar"),
    Template("tool_calls", "The tool calls the agent proposed", (LIMIT,),
             'event.name="agentsec.agent.action.proposed" | eval step=mvindex(mvdedup(\'agentsec.agent.step\'),0), tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0), '
             'source=mvindex(mvdedup(\'agentsec.agent.proposal.source\'),0) | table step tool source | sort 0 num(step) | head {limit}'),
    Template("decisions", "What the policy engine decided", (LIMIT,),
             'event.name="agentsec.control.decision" | eval step=mvindex(mvdedup(\'agentsec.agent.step\'),0), tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0), '
             'decision=mvindex(mvdedup(\'agentsec.control.decision\'),0), reason=mvindex(mvdedup(\'agentsec.control.reason\'),0) '
             '| table step tool decision reason | sort 0 num(step) | head {limit}'),
    Template("review_content_trail", "Follow the review note from proposal to handler", (LIMIT,),
             _TOOL_EVENTS + ' | eval seq=mvindex(mvdedup(\'agentsec.sequence\'),0), ev=mvindex(mvdedup(\'event.name\'),0), '
             'step=mvindex(mvdedup(\'agentsec.agent.step\'),0), content=mvindex(mvdedup(\'agentsec.content.preview\'),0) '
             '| table seq step ev content | sort 0 num(seq) | head {limit}'),
    Template("handler_outcomes", "What each handler returned", (LIMIT,),
             'event.name="agentsec.mcp.completed" | eval step=mvindex(mvdedup(\'agentsec.agent.step\'),0), tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0), '
             'trust=mvindex(mvdedup(\'agentsec.mcp.result.trust\'),0), returned=mvindex(mvdedup(\'agentsec.content.preview\'),0) '
             '| table step tool trust returned | sort 0 num(step) | head {limit}'),
    # ---- comparisons: baseline run vs defended (retest) run, side by side ----
    Template("compare_overview", "Event activity, baseline vs defended", (LIMIT,),
             '| ' + _SIDE + ' | eval ev=mvindex(mvdedup(\'event.name\'),0) | stats count(eval(side="baseline")) AS baseline count(eval(side="defended")) AS defended by ev '
             '| rename ev AS "event.name" | sort 0 "event.name" | head {limit}', runs=2),
    Template("compare_decisions", "Policy decisions, baseline vs defended", (LIMIT,),
             '| ' + _SIDE + ' | eval event_name=mvindex(mvdedup(\'event.name\'),0) | where event_name="agentsec.control.decision" '
             '| eval tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0), verdict=mvindex(mvdedup(\'agentsec.control.decision\'),0)." / ".mvindex(mvdedup(\'agentsec.control.reason\'),0) '
             '| stats count(eval(side="baseline")) AS baseline count(eval(side="defended")) AS defended by tool verdict | sort 0 tool verdict | head {limit}', runs=2),
    Template("compare_execution", "Handlers that began, baseline vs defended", (LIMIT,),
             '| ' + _SIDE + ' | eval event_name=mvindex(mvdedup(\'event.name\'),0) | where event_name="agentsec.mcp.started" '
             '| eval tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0) | stats count(eval(side="baseline")) AS baseline count(eval(side="defended")) AS defended by tool | sort 0 tool | head {limit}', runs=2),
    Template("compare_review_note", "What the review handler filed, baseline vs defended", (LIMIT,),
             '| ' + _SIDE + ' | eval event_name=mvindex(mvdedup(\'event.name\'),0), tool=mvindex(mvdedup(\'gen_ai.tool.name\'),0) '
             '| where event_name="agentsec.mcp.completed" AND tool="submit_for_underwriter_review" '
             '| eval step=mvindex(mvdedup(\'agentsec.agent.step\'),0), filed=mvindex(mvdedup(\'agentsec.content.preview\'),0) | table side step filed | sort 0 side num(step) | head {limit}', runs=2),
)}


def get_template(template_id: object) -> Template:
    if not isinstance(template_id, str) or template_id not in TEMPLATES:
        raise SearchError("Unknown search template.")
    return TEMPLATES[template_id]


# ----------------------------------------------------------------------------- execution backends

@dataclass
class Outcome:
    ok: bool
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None       # fixed codes: timeout | search_failed | backend_unavailable
    duration_ms: int = 0


class Backend(Protocol):
    name: str

    def run(self, spl: str, *, timeout_s: int, max_rows: int) -> Outcome: ...


def shape_csv(text: str, max_rows: int = MAX_ROWS) -> tuple[list[str], list[list[str]], bool]:
    """CSV from Splunk to bounded plain strings. Nothing here interprets the data; the UI renders it as text."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith(("WARNING:", "INFO:"))]
    if not lines:
        return [], [], False
    reader = csv.reader(io.StringIO("\n".join(lines)))
    head = next(reader, [])[:MAX_COLS]
    rows, truncated = [], False
    for rec in reader:
        if len(rows) >= max_rows:
            truncated = True
            break
        rows.append([c[:MAX_CELL] for c in rec[:MAX_COLS]])
    return [h[:MAX_CELL] for h in head], rows, truncated


class DockerExecBackend:
    """Today's backend: `splunk search` inside the Splunk container, as the same host-side mechanism the verifier already uses.

    The SPL reaches the container as an ENVIRONMENT VARIABLE through an argument list (no host shell), and the in-container
    script is a constant that expands it as one quoted word. The admin password stays inside the container.
    """
    name = "docker-exec"

    def __init__(self, container: str | None = None, runner: Callable | None = None):
        from agentsec.loan_desk.reconcile import SPLUNK_CONTAINER
        self.container, self.runner = container or SPLUNK_CONTAINER, runner or subprocess.run

    def run(self, spl: str, *, timeout_s: int = SEARCH_TIMEOUT_S, max_rows: int = MAX_ROWS) -> Outcome:
        from agentsec import spl_policy
        try:
            spl = spl_policy.checked(spl, backend="docker-exec")      # this path runs with the container's admin credential: same read-only policy as REST
        except spl_policy.SplPolicyViolation:
            return Outcome(False, error="search_failed")
        t0 = time.monotonic()
        script = f'exec /opt/splunk/bin/splunk search "$AGENTSEC_SPL" -auth "admin:${{SPLUNK_PASSWORD}}" -output csv -maxout {int(max_rows) + 1} -max_time {int(timeout_s)}'
        argv = ["docker", "exec", "-u", "splunk", "-e", f"AGENTSEC_SPL={spl}", self.container, "bash", "-c", script]
        try:
            proc = self.runner(argv, capture_output=True, text=True, check=False, timeout=timeout_s + 5)
        except subprocess.TimeoutExpired:
            return Outcome(False, error="timeout", duration_ms=int((time.monotonic() - t0) * 1000))
        except OSError:
            return Outcome(False, error="backend_unavailable")
        ms = int((time.monotonic() - t0) * 1000)
        if proc.returncode != 0:
            return Outcome(False, error="search_failed", duration_ms=ms)
        cols, rows, trunc = shape_csv(proc.stdout or "", max_rows)
        return Outcome(True, cols, rows, trunc, None, ms)


class RestBackend:
    """External Splunk (EXTERNAL_ENTERPRISE or CLOUD): the shared strict-TLS REST client. No docker, no admin password; a least-privilege token.
    Errors map onto the fixed Outcome codes; the stage/code detail (never a secret) goes to the log only."""
    name = "rest"

    def __init__(self, client):
        self.client = client

    def run(self, spl: str, *, timeout_s: int = SEARCH_TIMEOUT_S, max_rows: int = MAX_ROWS) -> Outcome:
        from agentsec.splunk_client import SplunkError
        t0 = time.monotonic()
        try:
            text = self.client.export_csv(spl, timeout_s=timeout_s)
        except SplunkError as exc:
            import logging
            logging.getLogger(__name__).info("splunk rest search failed: %s/%s", exc.stage, exc.code)
            ms = int((time.monotonic() - t0) * 1000)
            error = "timeout" if exc.code == "timeout" else ("backend_unavailable" if exc.stage == "connectivity" else "search_failed")
            return Outcome(False, error=error, duration_ms=ms)
        cols, rows, trunc = shape_csv(text, max_rows)
        return Outcome(True, cols, rows, trunc, None, int((time.monotonic() - t0) * 1000))


class UnavailableBackend:
    """Used when an external Splunk mode is selected but misconfigured: fail closed, never fall back to docker."""
    name = "unavailable"

    def run(self, spl: str, *, timeout_s: int = SEARCH_TIMEOUT_S, max_rows: int = MAX_ROWS) -> Outcome:
        return Outcome(False, error="backend_unavailable")


def default_backend(env=None) -> Backend:
    """BUNDLED (default): the existing docker backend, unchanged. External modes: the REST backend, or UnavailableBackend if misconfigured."""
    from agentsec.splunk_client import SplunkError, client_for_mode
    try:
        client = client_for_mode(env)
    except SplunkError:
        return UnavailableBackend()
    return DockerExecBackend() if client is None else RestBackend(client)
