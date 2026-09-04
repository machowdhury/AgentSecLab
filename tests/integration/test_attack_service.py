from agentsec.attack_app import AcmeBankClient, create_app


def test_attack_service_posts_atk002_into_acmebank(acme_client, stub_llm):
    def post_fn(path, payload):
        response = acme_client.post(path, json=payload)
        return response.status_code, response.get_json()

    attack_app = create_app(AcmeBankClient("http://acmebank-unused", post_fn=post_fn))
    attack_app.config["TESTING"] = True
    client = attack_app.test_client()

    listed = client.get("/api/attacks")
    assert listed.status_code == 200
    assert listed.get_json()["attacks"][0]["attack_id"] == "ATK-002"

    fired = client.post("/api/attacks/ATK-002", json={})
    assert fired.status_code == 200
    body = fired.get_json()
    assert body["attack_id"] == "ATK-002"
    assert body["blocked"] is True
    assert body["block_reason"] == "input_pattern_matched"
    assert body["llm_call_count"] == 0
    assert stub_llm.calls == []
    assert body["hops"][0]["decision"] == "DENY"
    assert body["hops"][0]["operation_executed"] is False
