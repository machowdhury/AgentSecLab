from agentsec.agents import PIPELINE_ORDER
from agentsec.attacks import BENIGN_LOAN
from tests.helpers import assert_all_schema_valid, event_names


def test_health_and_agent_list(acme_client):
    health = acme_client.get("/health")
    assert health.status_code == 200
    body = health.get_json()
    assert body["service"] == "acmebank"
    assert body["security.profile"] == "defended"
    assert body["testbed.mode.override"] is None

    agents = acme_client.get("/api/v1/agents")
    ids = [row["agent_id"] for row in agents.get_json()["agents"]]
    assert ids == [agent.agent_id for agent in PIPELINE_ORDER]


def test_process_benign_loan_returns_run_id(acme_client, counting_llm):
    response = acme_client.post("/process", json={"input": BENIGN_LOAN})
    assert response.status_code == 200
    body = response.get_json()
    assert body["blocked"] is False
    assert body["llm_call_count"] == 4
    assert body["run_id"]
    assert body["incident_id"] == body["run_id"]
    assert body["testbed_mode"] == "BASELINE"
    assert len(counting_llm.calls) == 4

    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}")
    assert stored.status_code == 200
    assert stored.get_json()["event_count"] > 0
    assert_all_schema_valid(stored.get_json()["events"])


def test_missing_input_is_400_schema_failure(acme_client, counting_llm):
    response = acme_client.post("/process", json={})
    assert response.status_code == 400
    body = response.get_json()
    assert body["terminal"] == "run_failed"
    assert body["error_stage"] == "schema_validation"
    assert counting_llm.call_count == 0
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    assert "agentsec.llm.started" not in event_names(stored["events"])


def test_empty_input_is_400_control_error(acme_client, counting_llm):
    response = acme_client.post("/process", json={"input": "   "})
    assert response.status_code == 400
    body = response.get_json()
    assert body["hops"][0]["control.decision"] == "ERROR"
    assert body["hops"][0]["operation.outcome"] == "prevented"
    assert counting_llm.call_count == 0


def test_malformed_non_object_is_400(acme_client, counting_llm):
    response = acme_client.post("/process", json=["not", "an", "object"])
    assert response.status_code == 400
    assert counting_llm.call_count == 0
    body = response.get_json()
    assert body["terminal"] == "run_failed"
