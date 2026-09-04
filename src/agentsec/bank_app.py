"""AcmeBank Flask app — the enforcement side of the trust boundary."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from agentsec.agents import PIPELINE_ORDER
from agentsec.attacks import ATK_001
from agentsec.baseline import BaselineTicker
from agentsec.llm import LLMClient, OllamaClient
from agentsec.pipeline import PipelineResult, result_to_dict, run_loan_pipeline
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink

logger = logging.getLogger("agentsec.acmebank")

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class LabRuntime:
    settings: Settings
    llm: LLMClient
    memory: MemorySink
    sink: FanoutSink
    baseline: BaselineTicker | None = None


def build_runtime(
    settings: Settings | None = None,
    llm: LLMClient | None = None,
    otel_enabled: bool | None = None,
) -> LabRuntime:
    settings = settings or get_settings()
    llm = llm or OllamaClient(settings)
    memory = MemorySink()
    sinks: list = [memory]
    enabled = settings.otel_enabled if otel_enabled is None else otel_enabled
    if enabled:
        sinks.append(OtlpSink(settings))
    sink = FanoutSink(sinks)
    runtime = LabRuntime(settings=settings, llm=llm, memory=memory, sink=sink)

    def _baseline_run(text: str) -> PipelineResult:
        return run_loan_pipeline(
            text,
            llm=runtime.llm,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=runtime.settings,
            user_id="baseline-ticker",
            testbed_mode="BASELINE",
            attack_id="ATK-001",
            expected_behavior=ATK_001.expected_defended,
        )

    runtime.baseline = BaselineTicker(
        _baseline_run,
        enabled=settings.baseline_enabled,
        interval_min=settings.baseline_interval_min_sec,
        interval_max=settings.baseline_interval_max_sec,
        startup_delay=settings.baseline_startup_delay_sec,
    )
    return runtime


def create_app(runtime: LabRuntime | None = None) -> Flask:
    runtime = runtime or build_runtime()
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.config["SECRET_KEY"] = runtime.settings.flask_secret_key
    app.config["AGENTSEC_RUNTIME"] = runtime

    @app.get("/health")
    def health():
        ollama_ok = runtime.llm.health()
        status = {
            "status": "healthy" if ollama_ok else "degraded",
            "service": "acmebank",
            "version": runtime.settings.version,
            "lab.id": runtime.settings.lab_id,
            "security.profile": runtime.settings.security_profile,
            "ollama_reachable": ollama_ok,
            "ollama_model": runtime.settings.ollama_model,
            "baseline": {
                "enabled": runtime.baseline.status.enabled if runtime.baseline else False,
                "running": runtime.baseline.status.running if runtime.baseline else False,
                "ticks": runtime.baseline.status.ticks if runtime.baseline else 0,
            },
        }
        return jsonify(status)

    @app.get("/")
    def index():
        return render_template(
            "acmebank.html",
            profile=runtime.settings.security_profile,
            model=runtime.settings.ollama_model,
            agents=PIPELINE_ORDER,
            version=runtime.settings.version,
        )

    @app.get("/api/v1/agents")
    def list_agents():
        return jsonify(
            {
                "agents": [
                    {
                        "agent_id": agent.agent_id,
                        "name": agent.name,
                        "description": agent.description,
                        "trust_boundary": agent.trust_boundary,
                    }
                    for agent in PIPELINE_ORDER
                ]
            }
        )

    @app.post("/api/v1/process")
    def process_loan():
        data = request.get_json(silent=True) or {}
        user_input = data.get("input")
        if not isinstance(user_input, str) or not user_input.strip():
            return jsonify({"error": "input field required"}), 400

        # Untrusted JSON cannot choose profile, run.id, or skip the control.
        user_id = data.get("user_id")
        if not isinstance(user_id, str) or not user_id.strip():
            user_id = "applicant-web"
        user_id = user_id.strip()[:64]

        technique_id = data.get("technique_id")
        if not isinstance(technique_id, str) or not technique_id.strip():
            technique_id = None
        else:
            technique_id = technique_id.strip()[:32]

        attack_id = data.get("attack_id")
        if attack_id not in ("ATK-001", "ATK-002"):
            attack_id = "ATK-002" if technique_id else "ATK-001"

        result = run_loan_pipeline(
            user_input.strip(),
            llm=runtime.llm,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=runtime.settings,
            user_id=user_id,
            testbed_mode="LIVE",
            technique_id=technique_id,
            attack_id=attack_id,
        )
        return jsonify(result_to_dict(result))

    @app.get("/api/v1/runs/<run_id>")
    def get_run(run_id: str):
        matched = [event for event in runtime.memory.events if event.get("agentsec.run.id") == run_id]
        if not matched:
            return jsonify({"error": "unknown run.id"}), 404
        return jsonify({"run_id": run_id, "event_count": len(matched), "events": matched})

    @app.post("/api/v1/traffic/tick")
    def traffic_tick():
        if runtime.baseline is None:
            return jsonify({"error": "baseline not configured"}), 500
        return jsonify(runtime.baseline.tick_once())

    @app.get("/api/v1/traffic/status")
    def traffic_status():
        if runtime.baseline is None:
            return jsonify({"enabled": False, "running": False})
        status = runtime.baseline.status
        return jsonify(
            {
                "enabled": status.enabled,
                "running": status.running,
                "ticks": status.ticks,
                "last_run_id": status.last_run_id,
                "last_error": status.last_error,
            }
        )

    @app.post("/api/v1/traffic/start")
    def traffic_start():
        if runtime.baseline is None:
            return jsonify({"error": "baseline not configured"}), 500
        status = runtime.baseline.start()
        return jsonify({"enabled": status.enabled, "running": status.running})

    @app.post("/api/v1/traffic/stop")
    def traffic_stop():
        if runtime.baseline is None:
            return jsonify({"error": "baseline not configured"}), 500
        status = runtime.baseline.stop()
        return jsonify({"enabled": status.enabled, "running": status.running})

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    runtime = build_runtime()
    if runtime.baseline:
        runtime.baseline.start()
    app = create_app(runtime)
    # Inside Docker, compose sets AGENTSEC_BIND_HOST=0.0.0.0; host publish stays localhost.
    app.run(host=runtime.settings.bind_host, port=runtime.settings.acmebank_port, threaded=True)


if __name__ == "__main__":
    main()
