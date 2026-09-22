"""AcmeBank Flask app — the enforcement side of the trust boundary."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from agentsec.agents import PIPELINE_ORDER
from agentsec.experiment import (
    resolve_attack_id,
    resolve_mcp_attack_id,
    resolve_mcp_testbed_mode,
    resolve_memory_testbed_mode,
    resolve_goal_testbed_mode,
    resolve_identity_testbed_mode,
    resolve_rag_testbed_mode,
    resolve_testbed_mode,
)
from agentsec.experiment_context import (
    bind_experiment_for_goal,
    bind_experiment_for_identity,
    bind_experiment_for_mcp,
    bind_experiment_for_memory,
    bind_experiment_for_process,
    bind_experiment_for_rag,
    settings_for_experiment,
    ROUTE_CAPSTONE,
)
from agentsec.json_strict import DuplicateJsonKeyError, loads_json_no_duplicate_keys
from agentsec.mcp.pipeline import mcp_result_to_dict, run_mcp_invoke, run_mcp_schema_failure
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.request_contract import parse_mcp_invoke_body
from agentsec.rag.pipeline import rag_result_to_dict, run_rag_retrieve, run_rag_schema_failure
from agentsec.rag.request_contract import parse_rag_retrieve_body
from agentsec.rag.fixtures import RAG_ATTACK_ID
from agentsec.memory.pipeline import (
    memory_recall_result_to_dict,
    memory_write_result_to_dict,
    run_memory_recall,
    run_memory_schema_failure,
    run_memory_write,
)
from agentsec.memory.request_contract import parse_memory_recall_body, parse_memory_write_body
from agentsec.memory.store import InProcessMemoryStore
from agentsec.memory.fixtures import MEMORY_RECALL_ENTRY, MEMORY_WRITE_ENTRY
from agentsec.goal.fixtures import (
    GOAL_AGENT_ID,
    GOAL_ATTACK_ID,
    PRINCIPAL_ID,
    instruction_bytes_for,
)
from agentsec.goal.pipeline import goal_result_to_dict, run_goal_integrity, run_goal_schema_failure
from agentsec.goal.request_contract import parse_goal_evaluate_body
from agentsec.identity.fixtures import IDENTITY_ATTACK_ID, claim_payload_for
from agentsec.identity.pipeline import (
    identity_result_to_dict,
    run_identity_delegation,
    run_identity_schema_failure,
)
from agentsec.identity.request_contract import parse_identity_delegate_body
from agentsec.llm import LLMClient, OllamaClient
from agentsec.pipeline import result_to_dict, run_loan_pipeline, run_schema_failure
from agentsec.request_contract import parse_process_body
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink

logger = logging.getLogger("agentsec.acmebank")

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


@dataclass
class LabRuntime:
    settings: Settings
    llm: LLMClient
    memory: MemorySink
    sink: FanoutSink
    mcp_registry: ToolRegistry
    memory_store: InProcessMemoryStore = field(default_factory=InProcessMemoryStore)


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
    return LabRuntime(
        settings=settings,
        llm=llm,
        memory=memory,
        sink=sink,
        mcp_registry=default_registry(),
        memory_store=InProcessMemoryStore(),
    )


def create_app(runtime: LabRuntime | None = None) -> Flask:
    runtime = runtime or build_runtime()
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
        static_url_path="/static",
    )
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
            "testbed.mode.override": runtime.settings.testbed_mode_override,
            "ollama_reachable": ollama_ok,
            "ollama_model": runtime.settings.ollama_model,
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

    @app.post("/process")
    def process_loan():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_schema_failure(
                    llm=runtime.llm,
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_testbed_mode(
                        input_text="",
                        settings=runtime.settings,
                    ),
                    attack_id="ATK-001",
                    error_reason="duplicate_json_keys",
                )
                return jsonify(result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_process_body(data)
        if not parsed.ok:
            result = run_schema_failure(
                llm=runtime.llm,
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_testbed_mode(
                    input_text=parsed.input_text or "",
                    settings=runtime.settings,
                ),
                attack_id=resolve_attack_id(parsed.input_text or ""),
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                input_text=parsed.input_text,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(result_to_dict(result)), 400

        user_input = parsed.input_text or ""
        ctx, bind_error = bind_experiment_for_process(
            experiment_id=parsed.experiment_id,
            input_text=user_input,
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_schema_failure(
                llm=runtime.llm,
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_testbed_mode(input_text=user_input, settings=runtime.settings),
                attack_id=resolve_attack_id(user_input),
                error_reason=bind_error,
                input_text=user_input,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(result_to_dict(result)), 400

        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
        else:
            run_settings = runtime.settings
            testbed_mode = resolve_testbed_mode(input_text=user_input, settings=runtime.settings)
            attack_id = resolve_attack_id(user_input)
            experiment_id = None
            fingerprint = None
        result = run_loan_pipeline(
            user_input,
            llm=runtime.llm,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            user_id=parsed.user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
        )
        body = result_to_dict(result)
        if result.terminal == "completed_allowed":
            return jsonify(body), 200
        if result.terminal == "completed_denied":
            return jsonify(body), 200
        if result.error_stage == "llm_invocation":
            return jsonify(body), 503
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.post("/mcp/invoke")
    def mcp_invoke():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_mcp_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_mcp_testbed_mode(
                        tool=None,
                        requested_scope=None,
                        settings=runtime.settings,
                    ),
                    attack_id="MCP-004",
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                    registry=runtime.mcp_registry,
                )
                return jsonify(mcp_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_mcp_invoke_body(data)
        policy_id = parsed.arguments.get("policy_id") if isinstance(parsed.arguments.get("policy_id"), str) else None
        if not parsed.ok:
            testbed_mode = resolve_mcp_testbed_mode(
                tool=parsed.tool,
                requested_scope=parsed.requested_scope,
                policy_id=policy_id,
                settings=runtime.settings,
            )
            attack_id = resolve_mcp_attack_id(
                parsed.tool, parsed.requested_scope, policy_id, testbed_mode=testbed_mode
            )
            result = run_mcp_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                attack_id=attack_id,
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                registry=runtime.mcp_registry,
            )
            return jsonify(mcp_result_to_dict(result)), 400

        ctx, bind_error = bind_experiment_for_mcp(
            experiment_id=parsed.experiment_id,
            tool=parsed.tool or "",
            requested_scope=parsed.requested_scope,
            arguments=parsed.arguments,
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_mcp_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_mcp_testbed_mode(
                    tool=parsed.tool,
                    requested_scope=parsed.requested_scope,
                    policy_id=policy_id,
                    settings=runtime.settings,
                ),
                attack_id=resolve_mcp_attack_id(
                    parsed.tool, parsed.requested_scope, policy_id
                ),
                error_reason=bind_error,
                extra_fields=(),
                registry=runtime.mcp_registry,
            )
            return jsonify(mcp_result_to_dict(result)), 400

        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
        else:
            run_settings = runtime.settings
            testbed_mode = resolve_mcp_testbed_mode(
                tool=parsed.tool,
                requested_scope=parsed.requested_scope,
                policy_id=policy_id,
                settings=runtime.settings,
            )
            attack_id = resolve_mcp_attack_id(
                parsed.tool, parsed.requested_scope, policy_id, testbed_mode=testbed_mode
            )
            experiment_id = None
            fingerprint = None

        result = run_mcp_invoke(
            tool=parsed.tool or "",
            arguments=parsed.arguments,
            requested_scope=parsed.requested_scope,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            user_id=parsed.user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            registry=runtime.mcp_registry,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
        )
        body = mcp_result_to_dict(result)
        if result.terminal == "completed_allowed":
            return jsonify(body), 200
        if result.terminal == "completed_denied":
            return jsonify(body), 200
        if result.error_stage == "mcp_invocation":
            return jsonify(body), 500
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.post("/rag/retrieve")
    def rag_retrieve():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_rag_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_rag_testbed_mode(settings=runtime.settings),
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                )
                return jsonify(rag_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_rag_retrieve_body(data)
        if not parsed.ok:
            result = run_rag_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_rag_testbed_mode(settings=runtime.settings),
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(rag_result_to_dict(result)), 400

        ctx, bind_error = bind_experiment_for_rag(
            experiment_id=parsed.experiment_id,
            document_id=parsed.document_id or "",
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_rag_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_rag_testbed_mode(settings=runtime.settings),
                error_reason=bind_error,
                extra_fields=(),
                experiment_id=parsed.experiment_id,
            )
            return jsonify(rag_result_to_dict(result)), 400

        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
        else:
            run_settings = runtime.settings
            testbed_mode = resolve_rag_testbed_mode(settings=runtime.settings)
            attack_id = None
            experiment_id = None
            fingerprint = None

        result = run_rag_retrieve(
            document_id=parsed.document_id or "",
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            user_id=parsed.user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id or RAG_ATTACK_ID,
            registry=runtime.mcp_registry,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
            follow_on_enabled=ctx is None or ctx.runtime_route != ROUTE_CAPSTONE,
        )
        body = rag_result_to_dict(result)
        if result.terminal == "completed_allowed":
            return jsonify(body), 200
        if result.terminal == "completed_denied":
            return jsonify(body), 200
        if result.error_stage == "mcp_invocation":
            return jsonify(body), 500
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.post("/memory/write")
    def memory_write():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_memory_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_memory_testbed_mode(settings=runtime.settings),
                    workflow_entry=MEMORY_WRITE_ENTRY,
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                )
                return jsonify(memory_write_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_memory_write_body(data)
        testbed_mode = resolve_memory_testbed_mode(settings=runtime.settings)
        if not parsed.ok:
            result = run_memory_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                workflow_entry=MEMORY_WRITE_ENTRY,
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(memory_write_result_to_dict(result)), 400
        ctx, bind_error = bind_experiment_for_memory(
            experiment_id=parsed.experiment_id,
            memory_id=parsed.memory_id or "",
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_memory_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                workflow_entry=MEMORY_WRITE_ENTRY,
                error_reason=bind_error,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(memory_write_result_to_dict(result)), 400
        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
            replace_fixture = True
        else:
            run_settings = runtime.settings
            attack_id = None
            experiment_id = None
            fingerprint = None
            replace_fixture = False
        result = run_memory_write(
            memory_id=parsed.memory_id or "",
            store=runtime.memory_store,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            user_id=parsed.user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id or "MEMORY-001",
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
            allow_replace_same_fixture=replace_fixture,
        )
        body = memory_write_result_to_dict(result)
        if result.terminal == "completed_allowed":
            return jsonify(body), 200
        return jsonify(body), 400

    @app.post("/memory/recall")
    def memory_recall():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_memory_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_memory_testbed_mode(settings=runtime.settings),
                    workflow_entry=MEMORY_RECALL_ENTRY,
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                )
                return jsonify(memory_write_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_memory_recall_body(data)
        testbed_mode = resolve_memory_testbed_mode(settings=runtime.settings)
        if not parsed.ok:
            result = run_memory_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                workflow_entry=MEMORY_RECALL_ENTRY,
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(memory_write_result_to_dict(result)), 400
        ctx, bind_error = bind_experiment_for_memory(
            experiment_id=parsed.experiment_id,
            memory_id=parsed.memory_id or "",
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_memory_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                workflow_entry=MEMORY_RECALL_ENTRY,
                error_reason=bind_error,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(memory_write_result_to_dict(result)), 400
        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
        else:
            run_settings = runtime.settings
            attack_id = None
            experiment_id = None
            fingerprint = None
        result = run_memory_recall(
            memory_id=parsed.memory_id or "",
            store=runtime.memory_store,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            user_id=parsed.user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id or "MEMORY-001",
            registry=runtime.mcp_registry,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
        )
        body = memory_recall_result_to_dict(result)
        if result.terminal == "completed_allowed":
            return jsonify(body), 200
        if result.terminal == "completed_denied":
            return jsonify(body), 200
        if result.error_stage == "mcp_invocation":
            return jsonify(body), 500
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.post("/goal/evaluate")
    def goal_evaluate():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_goal_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_goal_testbed_mode(settings=runtime.settings),
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                )
                return jsonify(goal_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_goal_evaluate_body(data)
        if not parsed.ok:
            result = run_goal_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_goal_testbed_mode(settings=runtime.settings),
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                experiment_id=parsed.experiment_id,
            )
            return jsonify(goal_result_to_dict(result)), 400

        ctx, bind_error = bind_experiment_for_goal(
            experiment_id=parsed.experiment_id,
            instruction_id=parsed.instruction_id or "",
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_goal_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_goal_testbed_mode(settings=runtime.settings),
                error_reason=bind_error,
                extra_fields=(),
                experiment_id=parsed.experiment_id,
            )
            return jsonify(goal_result_to_dict(result)), 400

        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
            instruction = ctx.payload
            instruction_id = ctx.instruction_id
        else:
            run_settings = runtime.settings
            testbed_mode = resolve_goal_testbed_mode(settings=runtime.settings)
            attack_id = GOAL_ATTACK_ID
            experiment_id = None
            fingerprint = None
            instruction = instruction_bytes_for(parsed.instruction_id or "")
            instruction_id = parsed.instruction_id
            if instruction is None:
                result = run_goal_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id=parsed.user_id,
                    testbed_mode=testbed_mode,
                    error_reason="unknown_instruction_id",
                    experiment_id=None,
                )
                return jsonify(goal_result_to_dict(result)), 400

        payload = {
            "principal": PRINCIPAL_ID,
            "agent": GOAL_AGENT_ID,
            "instruction": instruction,
        }
        result = run_goal_integrity(
            payload=payload,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            testbed_mode=testbed_mode,
            registry=runtime.mcp_registry,
            attack_id=attack_id,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
            instruction_id=instruction_id,
        )
        body = goal_result_to_dict(result)
        if result.terminal in {"completed_allowed", "completed_denied", "run_completed"}:
            return jsonify(body), 200
        if result.error_stage == "mcp_invocation":
            return jsonify(body), 500
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.post("/identity/delegate")
    def identity_delegate():
        raw = request.get_data(as_text=True)
        if not raw or not str(raw).strip():
            data: object | None = None
        else:
            try:
                data = loads_json_no_duplicate_keys(raw)
            except DuplicateJsonKeyError:
                result = run_identity_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id="unknown",
                    testbed_mode=resolve_identity_testbed_mode(settings=runtime.settings),
                    error_reason="duplicate_json_keys",
                    extra_fields=(),
                )
                return jsonify(identity_result_to_dict(result)), 400
            except json.JSONDecodeError:
                data = None
        parsed = parse_identity_delegate_body(data)
        if not parsed.ok:
            result = run_identity_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_identity_testbed_mode(settings=runtime.settings),
                error_reason=parsed.error_reason,
                extra_fields=parsed.extra_fields,
                experiment_id=parsed.experiment_id,
                claim_id=parsed.claim_id,
            )
            return jsonify(identity_result_to_dict(result)), 400

        ctx, bind_error = bind_experiment_for_identity(
            experiment_id=parsed.experiment_id,
            claim_id=parsed.claim_id or "",
            user_id=parsed.user_id,
        )
        if bind_error:
            result = run_identity_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=resolve_identity_testbed_mode(settings=runtime.settings),
                error_reason=bind_error,
                extra_fields=(),
                experiment_id=parsed.experiment_id,
                claim_id=parsed.claim_id,
            )
            return jsonify(identity_result_to_dict(result)), 400

        if ctx is not None:
            run_settings = settings_for_experiment(runtime.settings, ctx)
            testbed_mode = ctx.mode
            attack_id = ctx.attack_id
            experiment_id = ctx.experiment_id
            fingerprint = ctx.input_fingerprint
            claim_id = ctx.claim_id
            payload = claim_payload_for(claim_id)
        else:
            run_settings = runtime.settings
            testbed_mode = resolve_identity_testbed_mode(settings=runtime.settings)
            attack_id = IDENTITY_ATTACK_ID
            experiment_id = None
            fingerprint = None
            claim_id = parsed.claim_id
            payload = claim_payload_for(claim_id or "")
            if payload is None:
                result = run_identity_schema_failure(
                    sink=runtime.sink,
                    memory=runtime.memory,
                    settings=runtime.settings,
                    user_id=parsed.user_id,
                    testbed_mode=testbed_mode,
                    error_reason="unknown_claim_id",
                    experiment_id=None,
                    claim_id=claim_id,
                )
                return jsonify(identity_result_to_dict(result)), 400

        if payload is None:
            result = run_identity_schema_failure(
                sink=runtime.sink,
                memory=runtime.memory,
                settings=runtime.settings,
                user_id=parsed.user_id,
                testbed_mode=testbed_mode,
                error_reason="unknown_claim_id",
                experiment_id=experiment_id,
                claim_id=claim_id,
            )
            return jsonify(identity_result_to_dict(result)), 400

        result = run_identity_delegation(
            payload=payload,
            sink=runtime.sink,
            memory=runtime.memory,
            settings=run_settings,
            testbed_mode=testbed_mode,
            registry=default_registry(),
            attack_id=attack_id,
            experiment_id=experiment_id,
            input_fingerprint=fingerprint,
            claim_id=claim_id,
        )
        body = identity_result_to_dict(result)
        if result.terminal in {"completed_allowed", "completed_denied", "run_completed"}:
            return jsonify(body), 200
        if result.error_stage == "mcp_invocation":
            return jsonify(body), 500
        if result.error_stage == "control_evaluation":
            return jsonify(body), 500
        return jsonify(body), 400

    @app.get("/api/v1/runs/<run_id>")
    def get_run(run_id: str):
        matched = [
            event
            for event in (runtime.memory.snapshot() if hasattr(runtime.memory, "snapshot") else runtime.memory.events)
            if event.get("agentsec.run.id") == run_id
        ]
        if not matched:
            return jsonify({"error": "unknown run.id"}), 404
        return jsonify({"run_id": run_id, "event_count": len(matched), "events": matched})

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    runtime = build_runtime()
    app = create_app(runtime)
    app.run(host=runtime.settings.bind_host, port=runtime.settings.acmebank_port, threaded=True)


if __name__ == "__main__":
    main()
