from agentsec.agents import PIPELINE_ORDER
from agentsec.attacks import BENIGN_LOAN


def test_health_and_agent_list(acme_client):
    health = acme_client.get("/health")
    assert health.status_code == 200
    body = health.get_json()
    assert body["service"] == "acmebank"
    assert body["security.profile"] == "defended"

    agents = acme_client.get("/api/v1/agents")
    ids = [row["agent_id"] for row in agents.get_json()["agents"]]
    assert ids == [agent.agent_id for agent in PIPELINE_ORDER]
    roles = [row["role"] for row in agents.get_json()["agents"]]
    assert roles == ["intake", "credit", "risk", "compliance"]


def test_process_benign_loan_returns_run_id(acme_client, stub_llm):
    response = acme_client.post("/api/v1/process", json={"input": BENIGN_LOAN})
    assert response.status_code == 200
    body = response.get_json()
    assert body["blocked"] is False
    assert body["llm_call_count"] == 4
    assert body["run_id"]
    assert len(stub_llm.calls) == 4

    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}")
    assert stored.status_code == 200
    assert stored.get_json()["event_count"] > 0


def test_missing_input_is_400(acme_client):
    response = acme_client.post("/api/v1/process", json={})
    assert response.status_code == 400
