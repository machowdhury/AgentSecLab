"""AgentSec Academy: the learner-facing web experience (P1.4).

Pages are server-rendered Jinja with one static script and one stylesheet, so
the Academy can run under a strict Content-Security-Policy with no inline
script. The Academy adds read-only routes only. Launching still goes through
the existing ``POST /api/launch`` contract, and CTRL-MCP-001 inside the runtime
remains the only policy decision point; nothing here can grant or deny a tool.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from agentsec import academy_evidence as evidence
from agentsec.academy import load_curriculum
from agentsec.experiment_context import LAB_MCP, LAB_PI, lookup_experiment
from agentsec.mcp.policy import coded_policy
from agentsec.search_handoff import browser_splunk_web, workshop_url

ACADEMY_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)

#: Statements the MCP workshop must keep visible (lab boundaries, P1.3 guard).
LAB_BOUNDARIES = (
    "This is a learning lab with a deliberately vulnerable configuration. It is not a production control.",
    "CTRL-MCP-001 inside the runtime is the only policy decision point. Splunk does not ALLOW or DENY a tool.",
    "This page cannot authorize anything. Your prediction and answers stay in this browser and are never sent.",
    "DET-MCP-001 is packaged disabled. This workshop does not enable it. Not a notable-event pack.",
    "Recorded examples are REPLAY: real historical runs, not runs you just launched.",
    "Missing evidence is NOT MEASURED or NOT OBSERVED. It is never SAFE.",
)

#: LIVE labs that have an existing Attack Service page outside the Academy.
_LIVE_PAGES = {
    LAB_PI: "/",
}

FOUNDATION_LESSONS = (
    {
        "id": "llm",
        "title": "How an LLM works",
        "question": "When an AI gives a confident answer, does it actually understand what it is saying?",
        "concept": (
            "A large language model predicts the next likely piece of text from patterns it learned and from the "
            "context it is given. It does not look facts up unless a system connects it to a data source."
        ),
        "flow": ("Your prompt", "Tokens", "Model prediction", "Generated text"),
        "risk": "Fluent text can still be wrong, manipulated, or built on untrusted context.",
    },
    {
        "id": "agent",
        "title": "From model to agent",
        "question": "What makes an AI agent different from a chatbot?",
        "concept": (
            "An agent combines a model with instructions, tools and data. The model proposes an action; application "
            "code and security controls decide what may actually run."
        ),
        "flow": ("Goal", "Model proposes", "Tool request", "Control decides", "Execution"),
        "risk": "Tools raise the stakes. A bad proposal matters more when it can trigger a real action.",
    },
    {
        "id": "tools",
        "title": "Tools and MCP",
        "question": "Who decides whether an agent may use a tool?",
        "concept": (
            "The Model Context Protocol (MCP) is a standard way for an agent to call tools. A tool call is a "
            "request. A separate authorization control compares it with what the agent was granted."
        ),
        "flow": ("Agent", "tools/call request", "Authorization control", "Tool handler"),
        "risk": "A request is not authorization, and an authorization decision is not proof the tool ran.",
    },
    {
        "id": "evidence",
        "title": "Telemetry and evidence",
        "question": "How do you prove what an agent actually did?",
        "concept": (
            "Systems record events as they work: a control decision, a tool starting, a pipeline stopping. "
            "Investigators answer questions from those events, citing which event supports each claim."
        ),
        "flow": ("Runtime events", "Event record", "Splunk index", "Investigation"),
        "risk": "Never infer execution from a decision, or safety from missing events.",
    },
)


def _no_store(response):
    response.headers["Content-Security-Policy"] = ACADEMY_CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


def _curriculum_levels() -> list[dict]:
    levels = []
    for level in load_curriculum()["levels"]:
        labs = []
        for row in level.get("labs") or []:
            lab_id = row["lab_id"]
            if lab_id == LAB_MCP:
                href, surface = "/academy/labs/LAB-MCP-001", "ACADEMY"
            elif row.get("mode") == "LIVE":
                href, surface = _LIVE_PAGES.get(lab_id, f"/labs/{lab_id}"), "ATTACK SERVICE"
            else:
                href, surface = f"/en-US/app/agentsec/{row['view']}", "SPLUNK"
            labs.append(
                {
                    "lab_id": lab_id,
                    "title": row.get("title") or lab_id,
                    "mode": row.get("mode") or "REPLAY",
                    "href": href,
                    "surface": surface,
                }
            )
        levels.append({"id": level["id"], "title": level["title"], "labs": labs})
    return levels


def register_academy(app: Flask, *, launcher, client, artifacts_dir: Path, version: str) -> None:
    """Attach the Academy routes to the Attack Service app."""

    def render(template: str, page: str, **context):
        response = app.make_response(
            render_template(template, page=page, version=version, nav_page=page, **context)
        )
        return _no_store(response)

    def splunk_web() -> str:
        # Per request; never mutates shared launcher state.
        return browser_splunk_web(request.host, request.scheme)

    def live_ids_for(run_id: str) -> frozenset[str]:
        record = launcher.get_record(run_id) if evidence.is_run_id(run_id) else None
        if record is not None and record.lab_id == LAB_MCP and record.body:
            return frozenset({run_id})
        return frozenset()

    def load(run_id: str) -> tuple[evidence.RunRecord, dict | None]:
        record = evidence.load_run(run_id, artifacts_dir=artifacts_dir, live_run_ids=live_ids_for(run_id))
        body = None
        if record.provenance == evidence.LIVE:
            launch_record = launcher.get_record(run_id)
            body = launch_record.body if launch_record is not None else None
        return record, body

    def error(exc: evidence.EvidenceError):
        response = jsonify(
            {"error": exc.code, "error_class": "ERROR", "evidence_state": "ERROR", "detail": exc.detail}
        )
        response.status_code = exc.status
        return _no_store(response)

    @app.get("/academy")
    def academy_home():
        levels = _curriculum_levels()
        other_live = [
            {**lab, "level_title": level["title"]}
            for level in levels
            for lab in level["labs"]
            if lab["mode"] == "LIVE" and lab["lab_id"] != LAB_MCP
        ][:2]
        return render("academy/home.html", "home", levels=levels, other_live=other_live)

    @app.get("/academy/foundations")
    def academy_foundations():
        return render("academy/foundations.html", "foundations", lessons=FOUNDATION_LESSONS)

    @app.get("/academy/path")
    def academy_path():
        return render("academy/path.html", "path", levels=_curriculum_levels())

    @app.get("/academy/status")
    def academy_status():
        return render("academy/status.html", "status")

    @app.get("/academy/labs/<lab_id>")
    def academy_lab(lab_id: str):
        if lab_id != LAB_MCP:
            abort(404)
        attack = lookup_experiment(f"{LAB_MCP}:ATTACK")
        retest = lookup_experiment(f"{LAB_MCP}:RETEST")
        baseline = lookup_experiment(f"{LAB_MCP}:BASELINE")
        policy = coded_policy()
        return render(
            "academy/workshop_mcp.html",
            "workshop",
            boundaries=LAB_BOUNDARIES,
            attack=attack,
            retest=retest,
            baseline=baseline,
            policy={
                "agent_id": policy.agent_id,
                "allowed_tools": ", ".join(sorted(policy.allowed_tools)),
                "allowed_scopes": ", ".join(sorted(policy.allowed_scopes)),
            },
            replay=evidence.REPLAY_ROLES,
            studio_base=workshop_url(LAB_MCP) or "",
        )

    @app.get("/api/academy/evidence/<run_id>")
    def academy_evidence(run_id: str):
        try:
            record, body = load(run_id)
        except evidence.EvidenceError as exc:
            return error(exc)
        return _no_store(jsonify(evidence.evidence_document(record, splunk_web=splunk_web(), launch_body=body)))

    @app.get("/api/academy/compare")
    def academy_compare():
        if set(request.args) - {"attack", "retest"}:
            return error(evidence.EvidenceError("unknown_fields", 400, "Only attack and retest are accepted."))
        try:
            attack_record, _ = load(request.args.get("attack", ""))
            retest_record, _ = load(request.args.get("retest", ""))
            document = evidence.compare_document(attack_record, retest_record, splunk_web=splunk_web())
        except evidence.EvidenceError as exc:
            return error(exc)
        return _no_store(jsonify(document))

    @app.get("/api/academy/status")
    def academy_status_api():
        checks = []
        checks.append(
            {
                "name": "Attack Service",
                "state": "AVAILABLE",
                "detail": "This page was served by it.",
                "evidence": "MEASURED",
            }
        )
        status, body = client.health()
        healthy = status == 200 and body.get("status") == "healthy"
        checks.append(
            {
                "name": "AcmeBank runtime",
                "state": "AVAILABLE" if healthy else "UNAVAILABLE",
                "detail": (
                    f"Security profile {body.get('security.profile', 'NOT MEASURED')}; model label "
                    f"{body.get('ollama_model', 'NOT MEASURED')}. Health is reachability, not model quality."
                    if healthy
                    else "The runtime health check failed. LIVE launches will return an ERROR, not a decision."
                ),
                "evidence": "MEASURED",
            }
        )
        packs = evidence.replay_pack_inventory()
        present = sum(1 for row in packs if row["present"])
        checks.append(
            {
                "name": "REPLAY evidence packs (LAB-MCP-001)",
                "state": "AVAILABLE" if present == len(packs) else "INCOMPLETE",
                "detail": f"{present} of {len(packs)} committed packs readable by this service.",
                "evidence": "MEASURED",
                "packs": packs,
            }
        )
        artifacts_ok = artifacts_dir.is_dir()
        checks.append(
            {
                "name": "LIVE runtime event records",
                "state": "AVAILABLE" if artifacts_ok else "UNAVAILABLE",
                "detail": (
                    "The shared artifacts directory is readable, so LIVE runs launched here can be shown."
                    if artifacts_ok
                    else "The artifacts directory is not mounted; LIVE evidence cannot be shown in the notebook."
                ),
                "evidence": "MEASURED",
            }
        )
        checks.append(
            {
                "name": "Splunk indexing",
                "state": "NOT CHECKED",
                "detail": (
                    "This page does not query Splunk. Indexed evidence is confirmed in Splunk with the run's search "
                    "link. Reachability would not prove indexing anyway."
                ),
                "evidence": "UNTESTED",
                "href": splunk_web().rstrip("/") + "/en-US/app/search/search",
            }
        )
        return _no_store(jsonify({"checks": checks, "not_authorization": True}))
