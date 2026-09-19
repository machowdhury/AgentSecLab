"""LAB-MEMORY-001 event sequence and schema 1.7.0 honesty."""

from agentsec.events import EVENT_MEMORY_RECALLED, EVENT_MEMORY_WRITTEN
from agentsec.memory.fixtures import MEMORY_ID_NORMAL
from agentsec.memory.pipeline import run_memory_recall, run_memory_write
from agentsec.memory.store import InProcessMemoryStore
from tests.helpers import assert_all_schema_valid, event_names


def test_write_and_recall_events_are_schema_valid(settings, memory):
    store = InProcessMemoryStore()
    write = run_memory_write(
        memory_id=MEMORY_ID_NORMAL,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
    )
    recall = run_memory_recall(
        memory_id=MEMORY_ID_NORMAL,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
    )
    assert_all_schema_valid(write.events)
    assert_all_schema_valid(recall.events)
    written = next(e for e in write.events if e["event.name"] == EVENT_MEMORY_WRITTEN)
    recalled = next(e for e in recall.events if e["event.name"] == EVENT_MEMORY_RECALLED)
    assert written["agentsec.memory.id"] == recalled["agentsec.memory.id"]
    assert written["agentsec.content.hash"] == recalled["agentsec.content.hash"]
    assert written["agentsec.memory.source_run_id"] == write.run_id
    assert recalled["agentsec.memory.source_run_id"] == write.run_id
    assert recalled["agentsec.run.id"] == recall.run_id
    assert written["agentsec.run.id"] != recalled["agentsec.run.id"]
    assert written["agentsec.schema.version"] == "1.9.0"
    assert "agentsec.memory.content" not in written
    assert "agentsec.memory.content" not in recalled
    assert EVENT_MEMORY_WRITTEN in event_names(write.events)
    assert EVENT_MEMORY_RECALLED in event_names(recall.events)
    assert written["agentsec.trust_boundary"] == "agent.memory.store"
