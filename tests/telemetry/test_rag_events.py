"""LAB-RAG-001 event sequence and schema 1.6.0 honesty."""

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_STARTED
from agentsec.mcp.registry import default_registry
from agentsec.rag.fixtures import DOCUMENT_ID_MALICIOUS, DOCUMENT_ID_NORMAL
from agentsec.rag.pipeline import run_rag_retrieve
from tests.helpers import assert_all_schema_valid, assert_sequence_ordering, control_events, event_names


def test_baseline_event_order(settings, memory):
    result = run_rag_retrieve(
        document_id=DOCUMENT_ID_NORMAL,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        registry=default_registry(),
        write_evidence=False,
    )
    names = event_names(result.events)
    assert names[0] == "agentsec.run.started"
    assert EVENT_CONTROL_DECISION in names
    assert names[-1] == "agentsec.run.completed"
    assert EVENT_MCP_STARTED not in names
    for event in result.events:
        assert event["agentsec.schema.version"] == "1.9.0"
        assert event["agentsec.attack.id"] == "RAG-001"
        assert event["gen_ai.workflow.name"] == "rag_context_lab"
        assert "full_document" not in event
    rag = next(e for e in control_events(result.events) if e["agentsec.control.type"] == "rag_context_trust")
    assert rag["agentsec.trust_boundary"] == "rag.retrieved.context"
    assert rag["agentsec.content.influence.kind"] == "retrieved_context"
    assert rag["agentsec.rag.context.document.id"] == DOCUMENT_ID_NORMAL
    assert len(rag["agentsec.content.preview"]) <= 200
    assert_all_schema_valid(result.events)
    assert_sequence_ordering(result.events)


def test_retest_distinguishes_observe_from_deny(settings, memory):
    result = run_rag_retrieve(
        document_id=DOCUMENT_ID_MALICIOUS,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=default_registry(),
        write_evidence=False,
    )
    decisions = [(e["agentsec.control.id"], e["agentsec.control.decision"]) for e in control_events(result.events)]
    assert ("CTRL-RAG-CONTEXT-001", "OBSERVE") in decisions
    assert ("CTRL-MCP-001", "DENY") in decisions
    assert EVENT_MCP_STARTED not in event_names(result.events)
    assert_all_schema_valid(result.events)
