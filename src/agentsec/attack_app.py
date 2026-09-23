"""Attack Service — untrusted HTTP client. It never calls Ollama or skips controls."""

from __future__ import annotations

import logging
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request

from agentsec.academy import lab_row, next_lab
from agentsec.attacks import ATK_002
from agentsec.experiment_context import LAB_CAPSTONE, LAB_GOAL, LAB_IDENTITY, LAB_MCP, LAB_MEMORY, LAB_PI, LAB_RAG, lookup_experiment
from agentsec.lab_manifest import load_lab_manifest, prediction_for
from agentsec.launch_catalog import RETEST_SUPPORT, allowlist_public_rows, known_lab_ids
from agentsec.launch_contract import parse_launch_json
from agentsec.launch_service import LaunchService, error_body
from agentsec.mcp.policy import coded_policy
from agentsec.memory.fixtures import (
    CLOSED_FOLLOW_ON_SCOPE as MEMORY_FOLLOW_ON_SCOPE,
    CLOSED_FOLLOW_ON_TOOL as MEMORY_FOLLOW_ON_TOOL,
    MEMORY_ID_MALICIOUS,
    MEMORY_TRUST_LABEL,
    PROVENANCE as MEMORY_PROVENANCE,
)
from agentsec.rag.fixtures import (
    CLOSED_FOLLOW_ON_SCOPE as RAG_FOLLOW_ON_SCOPE,
    CLOSED_FOLLOW_ON_TOOL as RAG_FOLLOW_ON_TOOL,
    CONTEXT_TRUST_LABEL,
    DOCUMENT_ID_MALICIOUS,
    PROVENANCE as RAG_PROVENANCE,
)
from agentsec.settings import get_settings

logger = logging.getLogger("agentsec.attack")

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


class AcmeBankClient:
    def __init__(self, base_url: str, post_fn=None, get_fn=None) -> None:
        self.base_url = base_url.rstrip("/")
        self._post_fn = post_fn
        self._get_fn = get_fn

    def health(self) -> tuple[int, dict]:
        if self._get_fn is not None:
            return self._get_fn("/health")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def process(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/process", payload)
        try:
            response = requests.post(
                f"{self.base_url}/process",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def mcp_invoke(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/mcp/invoke", payload)
        try:
            response = requests.post(
                f"{self.base_url}/mcp/invoke",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def rag_retrieve(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/rag/retrieve", payload)
        try:
            response = requests.post(
                f"{self.base_url}/rag/retrieve",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def memory_write(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/memory/write", payload)
        try:
            response = requests.post(
                f"{self.base_url}/memory/write",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def memory_recall(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/memory/recall", payload)
        try:
            response = requests.post(
                f"{self.base_url}/memory/recall",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def goal_evaluate(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/goal/evaluate", payload)
        try:
            response = requests.post(
                f"{self.base_url}/goal/evaluate",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}

    def identity_delegate(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/identity/delegate", payload)
        try:
            response = requests.post(
                f"{self.base_url}/identity/delegate",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data if isinstance(data, dict) else {"error": "non_json"}
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}


def create_app(client: AcmeBankClient | None = None, *, launch_kwargs: dict | None = None) -> Flask:
    settings = get_settings()
    client = client or AcmeBankClient(settings.acmebank_url)
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
        static_url_path="/static",
    )
    app.config["SECRET_KEY"] = settings.flask_secret_key
    app.config["AGENTSEC_ATTACK_CLIENT"] = client
    launcher = LaunchService(client, settings, **(launch_kwargs or {}))
    app.config["AGENTSEC_LAUNCH_SERVICE"] = launcher

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "healthy",
                "service": "attack-service",
                "version": settings.version,
                "acmebank_url": client.base_url,
                "bind_model": "LOCAL EDUCATIONAL SERVICE",
                "authentication": "NOT PRODUCTION AUTHENTICATION",
                "tenancy": "NOT MULTI-TENANT",
                "exposure": "NOT INTERNET-FACING",
                "schema_version": "1.9.0",
                "retest_support": RETEST_SUPPORT,
            }
        )

    @app.get("/favicon.ico")
    def favicon():
        # The workbench has no product icon yet; avoid a noisy browser 4xx.
        return "", 204

    @app.get("/")
    def index():
        return _lab_page("LAB-PI-001")

    @app.get("/labs/<lab_id>")
    def lab_page(lab_id: str):
        if lab_id not in known_lab_ids():
            status, body = error_body("unknown_lab")
            return jsonify(body), status
        return _lab_page(lab_id)

    def _lab_page(lab_id: str):
        try:
            manifest = load_lab_manifest(lab_id)
        except FileNotFoundError:
            manifest = {"lab_id": lab_id, "title": lab_id, "limitations": []}
        browser_health_url = client.base_url
        if "acmebank" in client.base_url and "127.0.0.1" not in client.base_url:
            browser_health_url = "http://127.0.0.1:5000"
        attack_ctx = lookup_experiment(f"{lab_id}:ATTACK")
        baseline_ctx = lookup_experiment(f"{lab_id}:BASELINE")
        retest_ctx = lookup_experiment(f"{lab_id}:RETEST")
        payload_preview = ATK_002.payload
        technique_name = ATK_002.name
        technique_id = ATK_002.technique_id
        specimen_label = "ATK-002 catalog payload (not learner-supplied)"
        expected_defended = ATK_002.expected_defended
        if lab_id == LAB_MCP and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Unauthorized tool request"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned MCP request (not learner-supplied)"
            expected_defended = (
                "CTRL-MCP-001 DENY tool_not_granted. Runtime handler count 0 is "
                "authoritative. Indexed mcp.started absence corroborates a complete copy."
            )
        if lab_id == LAB_RAG and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Retrieved-context-derived authority"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned malicious RAG fixture (not learner-supplied)"
            expected_defended = (
                "CTRL-RAG-CONTEXT-001 OBSERVE. Same follow-on REQUEST. "
                "CTRL-MCP-001 DENY tool_not_granted. Handler count 0."
            )
        if lab_id == LAB_MEMORY and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Memory-derived authority across WRITE then RECALL"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned malicious memory fixture (not learner-supplied)"
            expected_defended = (
                "WRITE persists untrusted_data. RECALL CTRL-MEMORY-CONTEXT-001 OBSERVE. "
                "Same follow-on REQUEST. CTRL-MCP-001 DENY tool_not_granted. Handler count 0."
            )
        if lab_id == LAB_GOAL and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Untrusted-instruction task expansion"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned malicious instruction fixture (not learner-supplied)"
            expected_defended = (
                "CTRL-GOAL-INTEGRITY-001 DENY unauthorized_task_expansion. "
                "Effective summarize_lending_policy. CTRL-MCP-001 ALLOW tool_granted. "
                "Wrong-goal handler 0. In-task handler 1."
            )
        if lab_id == LAB_IDENTITY and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Caller/delegation claim as authority"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned adversarial delegation fixture (not learner-supplied)"
            expected_defended = (
                "CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant. "
                "Same privileged request. CTRL-MCP-001 DENY tool_not_granted. "
                "lookup_customer_tier runtime handler count 0 is authoritative. "
                "Indexed mcp.started absence corroborates a complete copy. "
                "WHO AUTHENTICATED = NOT PROVEN / NOT MODELED."
            )
        if lab_id == LAB_CAPSTONE and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Unexpected customer-tier access in a policy workflow"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned closed capstone specimen (not learner-supplied)"
            expected_defended = (
                "Retrieved and recalled content remain data (OBSERVE). "
                "CTRL-MCP-001 DENY tool_not_granted on the later recall. "
                "lookup_customer_tier runtime handler count 0 is authoritative. "
                "Indexed mcp.started absence corroborates a complete copy."
            )
        if lab_id == LAB_MCP:
            hunt_hint = "Reuse Q-MCP-WHO / Q-MCP-AUTHZ (do not create a detector)."
        elif lab_id == LAB_RAG:
            hunt_hint = "Reuse Q-RAG-CONTEXT-AUTHORITY and Q-MCP-AUTHZ (do not create DET-RAG)."
        elif lab_id == LAB_MEMORY:
            hunt_hint = (
                "Reuse Q-MEMORY-CONTEXT-AUTHORITY with WRITE and RECALL run.ids. "
                "Reuse Q-MCP-AUTHZ on the recall run. Do not create DET-MEMORY."
            )
        elif lab_id == LAB_GOAL:
            hunt_hint = "Reuse Q-GOAL-INTEGRITY-AUTHORITY and Q-MCP-AUTHZ (do not create DET-GOAL)."
        elif lab_id == LAB_IDENTITY:
            hunt_hint = "Reuse Q-AGENT-DELEGATION-AUTHORITY and Q-MCP-AUTHZ (do not create DET-A2A)."
        elif lab_id == LAB_CAPSTONE:
            hunt_hint = (
                "Reuse Q-RAG-CONTEXT-AUTHORITY on retrieve, Q-MEMORY-CONTEXT-AUTHORITY on write+recall, "
                "and Q-MCP-AUTHZ on the recall run. Do not create DET-CAPSTONE."
            )
        else:
            hunt_hint = "Reuse Q-RUN-EVENTS (do not create a detector)."
        academy = lab_row(lab_id) or {}
        successor = next_lab(lab_id)
        next_lab_ctx = None
        if successor is not None:
            next_href = None
            if successor.get("mode") == "LIVE":
                next_href = "/" if successor["lab_id"] == LAB_PI else f"/labs/{successor['lab_id']}"
            next_lab_ctx = {
                "title": successor.get("title") or successor["lab_id"],
                "mode": successor.get("mode"),
                "href": next_href,
            }
        mcp_policy = coded_policy()
        context_workbench = None
        if lab_id == LAB_RAG:
            context_workbench = {
                "kind": "rag",
                "title": "RAG / Retrieved Context",
                "workshop_url": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_rag_context",
                "security_question": manifest.get("security_question"),
                "attacker_influence": "Closed retrieved document bytes",
                "artifact_label": "Retrieved document",
                "artifact_id": DOCUMENT_ID_MALICIOUS,
                "provenance": RAG_PROVENANCE,
                "trust_label": CONTEXT_TRUST_LABEL,
                "context_control": "CTRL-RAG-CONTEXT-001 · OBSERVE",
                "enforcement_control": "CTRL-MCP-001 · tool PDP",
                "follow_on_tool": RAG_FOLLOW_ON_TOOL,
                "follow_on_scope": RAG_FOLLOW_ON_SCOPE,
                "hunt_id": "Q-RAG-CONTEXT-AUTHORITY",
                "expected_attack": "Context OBSERVE; labeled fail-open MCP ALLOW; handler 1",
                "expected_retest": "Same bytes and request; MCP DENY tool_not_granted; handler 0",
                "semantic_lines": (
                    "RETRIEVED ≠ TRUSTED",
                    "PROVENANCE ≠ AUTHORITY",
                    "OBSERVE ≠ ALLOW",
                    "ALLOW ≠ EXECUTION",
                ),
            }
        elif lab_id == LAB_MEMORY:
            context_workbench = {
                "kind": "memory",
                "title": "Persistent Memory",
                "workshop_url": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_memory_security",
                "security_question": manifest.get("security_question"),
                "attacker_influence": "Closed bytes persisted before a later recall",
                "artifact_label": "Persisted memory",
                "artifact_id": MEMORY_ID_MALICIOUS,
                "provenance": MEMORY_PROVENANCE,
                "trust_label": MEMORY_TRUST_LABEL,
                "context_control": "CTRL-MEMORY-CONTEXT-001 · OBSERVE",
                "enforcement_control": "CTRL-MCP-001 · tool PDP",
                "follow_on_tool": MEMORY_FOLLOW_ON_TOOL,
                "follow_on_scope": MEMORY_FOLLOW_ON_SCOPE,
                "hunt_id": "Q-MEMORY-CONTEXT-AUTHORITY",
                "expected_attack": "WRITE then RECALL; memory OBSERVE; MCP ALLOW; handler 1",
                "expected_retest": "Same bytes and request; MCP DENY tool_not_granted; handler 0",
                "semantic_lines": (
                    "STORED ≠ TRUSTED",
                    "RECALLED ≠ AUTHORIZED",
                    "OBSERVE ≠ ALLOW",
                    "ALLOW ≠ EXECUTION",
                ),
            }
        template_name = (
            "attack_mcp.html"
            if lab_id == LAB_MCP
            else ("attack_context.html" if context_workbench is not None else "attack.html")
        )
        return render_template(
            template_name,
            attack=ATK_002,
            version=settings.version,
            target_name="AcmeBank",
            target_url=client.base_url,
            browser_health_url=browser_health_url,
            manifest=manifest,
            lab_id=lab_id,
            lab_title=manifest.get("title") or lab_id,
            prediction_attack=prediction_for(lab_id, "ATTACK") or {},
            prediction_baseline=prediction_for(lab_id, "BASELINE") or {},
            prediction_retest=prediction_for(lab_id, "RETEST") or {},
            retest_support=RETEST_SUPPORT,
            allowlist=[row for row in allowlist_public_rows() if row["lab_id"] == lab_id],
            specimen_baseline=baseline_ctx.specimen_id if baseline_ctx else "ATK-001",
            specimen_attack=attack_ctx.specimen_id if attack_ctx else "ATK-002",
            specimen_retest=retest_ctx.specimen_id if retest_ctx else "ATK-002",
            payload_preview=payload_preview,
            payload_label=specimen_label,
            technique_name=technique_name,
            technique_id=technique_id,
            expected_defended=expected_defended,
            hunt_hint=hunt_hint,
            mcp_request={
                "tool": attack_ctx.tool if attack_ctx else "",
                "requested_scope": attack_ctx.requested_scope if attack_ctx else "",
            },
            mcp_policy={
                "agent_id": mcp_policy.agent_id,
                "allowed_tools": ", ".join(sorted(mcp_policy.allowed_tools)),
                "allowed_scopes": ", ".join(sorted(mcp_policy.allowed_scopes)),
            },
            context_workbench=context_workbench,
            is_memory_lab=lab_id == LAB_MEMORY,
            is_goal_lab=lab_id == LAB_GOAL,
            is_identity_lab=lab_id == LAB_IDENTITY,
            is_capstone_lab=lab_id == LAB_CAPSTONE,
            academy_level=academy.get("level_title") or "Curriculum",
            next_lab=next_lab_ctx,
            labs=(
                {"lab_id": LAB_PI, "title": "Direct Prompt Injection", "href": "/"},
                {"lab_id": LAB_MCP, "title": "Tool Authorization", "href": "/labs/LAB-MCP-001"},
                {"lab_id": LAB_RAG, "title": "RAG / Retrieved Context", "href": "/labs/LAB-RAG-CONTEXT"},
                {"lab_id": LAB_MEMORY, "title": "Persistent Memory", "href": "/labs/LAB-MEMORY-001"},
                {"lab_id": LAB_GOAL, "title": "Goal / Instruction Integrity", "href": "/labs/LAB-AGENT-GOAL-INTEGRITY-001"},
                {"lab_id": LAB_IDENTITY, "title": "Agent Identity / Delegation", "href": "/labs/LAB-AGENT-DELEGATION-001"},
                {"lab_id": LAB_CAPSTONE, "title": "Lending Assistant Investigation", "href": "/labs/LAB-AGENTSEC-CAPSTONE-001"},
            ),
        )

    @app.get("/api/attacks")
    def list_attacks():
        return jsonify(
            {
                "attacks": [
                    {
                        "attack_id": ATK_002.attack_id,
                        "name": ATK_002.name,
                        "technique_id": ATK_002.technique_id,
                        "expected_defended": ATK_002.expected_defended,
                    }
                ]
            }
        )

    @app.get("/api/allowlist")
    def list_allowlist():
        return jsonify(
            {
                "labs": sorted(known_lab_ids()),
                "retest_support": RETEST_SUPPORT,
                "rows": allowlist_public_rows(),
            }
        )

    @app.get("/api/target-health")
    def target_health():
        """Same-origin profile probe. Browser cannot CORS-fetch AcmeBank /health."""
        status, body = client.health()
        return jsonify(body), status

    @app.get("/api/labs/<lab_id>")
    def lab_manifest_api(lab_id: str):
        try:
            return jsonify(load_lab_manifest(lab_id))
        except FileNotFoundError:
            return jsonify({"error": "unknown_lab", "error_class": "ERROR"}), 404

    @app.post("/api/launch")
    def launch():
        parsed = parse_launch_json(request.get_data(as_text=True))
        status, body = launcher.launch(parsed)
        return jsonify(body), status

    @app.post("/api/compare-handoff")
    def compare_handoff():
        raw = request.get_data(as_text=True)
        from agentsec.json_strict import DuplicateJsonKeyError, loads_json_no_duplicate_keys

        try:
            data = loads_json_no_duplicate_keys(raw) if raw and str(raw).strip() else None
        except (DuplicateJsonKeyError, ValueError):
            status, body = error_body("malformed_compare")
            return jsonify(body), status
        if not isinstance(data, dict):
            status, body = error_body("malformed_compare")
            return jsonify(body), status
        extra = [key for key in data if key not in {"attack_run_id", "retest_run_id"}]
        if extra:
            status, body = error_body("unknown_fields", extra={"extra_fields": extra})
            return jsonify(body), status
        attack_run_id = data.get("attack_run_id")
        retest_run_id = data.get("retest_run_id")
        if not isinstance(attack_run_id, str) or not isinstance(retest_run_id, str):
            status, body = error_body("malformed_compare")
            return jsonify(body), status
        status, body = launcher.compare_handoff(attack_run_id, retest_run_id)
        return jsonify(body), status

    @app.get("/api/launches/<run_id>")
    def get_launch(run_id: str):
        record = launcher.get_record(run_id)
        if record is None or not record.body:
            return jsonify(
                {
                    "error": "unknown_run",
                    "error_class": "ERROR",
                    "evidence_state": "ERROR",
                }
            ), 404
        return jsonify(record.body)

    @app.get("/api/launches/<run_id>/evidence")
    def launch_evidence(run_id: str):
        timeout = request.args.get("timeout_seconds")
        timeout_seconds = None if timeout is None else timeout
        from agentsec.evidence_readiness import clamp_timeout

        status, body = launcher.probe_evidence(
            run_id,
            timeout_seconds=clamp_timeout(timeout_seconds, 0) if timeout is not None else 0,
        )
        return jsonify(body), status

    @app.post("/api/attacks/ATK-002")
    def fire_atk_002():
        payload = {
            "input": ATK_002.payload,
            "user_id": "attacker-lab",
        }
        status, data = client.process(payload)
        return jsonify(data), status

    @app.errorhandler(404)
    def not_found(_e):
        status, body = error_body("unknown_lab")
        body["error"] = "not_found"
        body["detail"] = "No such Attack Service route."
        return jsonify(body), status

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    settings = get_settings()
    app = create_app()
    logger.info(
        "LOCAL EDUCATIONAL SERVICE bind_host=%s port=%s NOT PRODUCTION AUTHENTICATION",
        settings.bind_host,
        settings.attack_port,
    )
    app.run(host=settings.bind_host, port=settings.attack_port, threaded=True)


if __name__ == "__main__":
    main()
