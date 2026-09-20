"""Attack Service — untrusted HTTP client. It never calls Ollama or skips controls."""

from __future__ import annotations

import logging
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request

from agentsec.attacks import ATK_002
from agentsec.experiment_context import LAB_MCP, LAB_PI, lookup_experiment
from agentsec.lab_manifest import load_lab_manifest, prediction_for
from agentsec.launch_catalog import RETEST_SUPPORT, allowlist_public_rows, known_lab_ids
from agentsec.launch_contract import parse_launch_json
from agentsec.launch_service import LaunchService, error_body
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
        if lab_id == LAB_MCP and attack_ctx is not None:
            payload_preview = attack_ctx.payload
            technique_name = "Unauthorized tool request"
            technique_id = attack_ctx.attack_id
            specimen_label = "Server-owned MCP request (not learner-supplied)"
        return render_template(
            "attack.html",
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
            hunt_hint=(
                "Reuse Q-MCP-WHO / Q-MCP-AUTHZ (do not create a detector)."
                if lab_id == LAB_MCP
                else "Reuse Q-RUN-EVENTS (do not create a detector)."
            ),
            labs=(
                {"lab_id": LAB_PI, "title": "Direct Prompt Injection", "href": "/"},
                {"lab_id": LAB_MCP, "title": "Tool Authorization", "href": "/labs/LAB-MCP-001"},
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
