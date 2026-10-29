"""6B launch boundary: request validation, concurrency permits, Host-header safety. Fakes only; no model, Docker or Splunk."""

from __future__ import annotations

import json
import threading

import pytest

from agentsec.attack_app import AcmeBankClient, create_app
from agentsec.bank_app import create_app as create_bank

BODY = {"lab_id": "LAB-PI-001", "specimen_id": "ATK-001", "mode": "BASELINE", "execution": "live"}
ORIGIN = "http://lab.example:5001"


def _app(tmp_path, get_fn=None, post_fn=None, limit=2):
    client = AcmeBankClient(
        "http://acmebank-unused",
        get_fn=get_fn or (lambda _p: (200, {"status": "healthy"})),
        post_fn=post_fn or (lambda _p, _b: (200, {})),
    )
    return create_app(client, launch_kwargs={"artifacts_dir": tmp_path, "max_concurrent": limit})


def _post(c, data=None, **kw):
    kw.setdefault("base_url", ORIGIN)
    return c.post("/api/launch", data=json.dumps(data if data is not None else BODY), content_type=kw.pop("content_type", "application/json"), **kw)


def test_valid_non_browser_launch_is_compatible(tmp_path):
    r = _post(_app(tmp_path).test_client())
    assert r.status_code != 400 and r.status_code != 403 and r.status_code != 415  # reaches the unchanged launch logic


def test_same_origin_browser_launch_is_allowed_and_cross_origin_rejected(tmp_path):
    c = _app(tmp_path).test_client()
    assert _post(c, headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}).status_code not in (403, 415)
    for hdr in ({"Origin": "http://evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
        r = _post(c, headers=hdr)
        assert r.status_code == 403 and r.get_json()["error"] == "cross_origin_rejected", hdr


def test_origin_must_match_host_and_port_exactly(tmp_path):
    """Behind the gateway on a non-default port the backend sees Host 'h:8000'; the browser's Origin carries the same port."""
    c = _app(tmp_path).test_client()
    ok = lambda h, base: _post(c, base_url=base, headers=h).status_code not in (403, 415)
    assert ok({"Origin": "https://agentsec.test:8000"}, "https://agentsec.test:8000")
    assert ok({"Origin": "https://AGENTSEC.test:8000"}, "https://agentsec.test:8000")           # hostnames are case-insensitive
    for origin, base in [("https://agentsec.test", "https://agentsec.test:8000"),                # port dropped
                         ("https://agentsec.test:8001", "https://agentsec.test:8000"),           # other port
                         ("https://agentsec.test:8000", "https://agentsec.test"),                # port added
                         ("https://evil.test:8000", "https://agentsec.test:8000"),               # other host, same port
                         ("https://agentsec.test:8000@evil.test", "https://agentsec.test:8000"), # userinfo trick
                         ("ftp://agentsec.test:8000", "https://agentsec.test:8000"), ("null", "https://agentsec.test:8000")]:
        r = _post(c, base_url=base, headers={"Origin": origin})
        assert r.status_code == 403 and r.get_json()["error"] == "cross_origin_rejected", (origin, base)


def test_cross_origin_form_post_is_rejected_before_the_content_type_check(tmp_path):
    r = _post(_app(tmp_path).test_client(), content_type="text/plain", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
def test_unsupported_content_types_rejected(tmp_path, ctype):
    r = _post(_app(tmp_path).test_client(), content_type=ctype)
    assert r.status_code == 415 and r.get_json()["error"] == "unsupported_media_type"


def test_oversized_malformed_and_query_params_rejected(tmp_path):
    c = _app(tmp_path).test_client()
    big = _post(c, {**BODY, "pad": "x" * 20000})
    assert big.status_code == 413 and big.get_json()["error"] == "payload_too_large"
    bad = c.post("/api/launch", data="{not json", content_type="application/json", base_url=ORIGIN)
    assert bad.status_code == 400
    q = c.post("/api/launch?profile=vulnerable", data=json.dumps(BODY), content_type="application/json", base_url=ORIGIN)
    assert q.status_code == 400 and q.get_json()["error"] == "unexpected_parameters"


def test_duplicate_keys_and_forbidden_parameters_still_rejected(tmp_path):
    c = _app(tmp_path).test_client()
    dup = c.post("/api/launch", data='{"lab_id":"LAB-PI-001","lab_id":"LAB-PI-001"}', content_type="application/json", base_url=ORIGIN)
    assert dup.status_code == 400 and dup.get_json()["error"] == "duplicate_json_keys"
    forbidden = _post(c, {**BODY, "profile": "vulnerable"})
    assert forbidden.status_code == 400 and forbidden.get_json()["error"] != ""


def test_compare_handoff_gets_the_same_guard(tmp_path):
    c = _app(tmp_path).test_client()
    assert c.post("/api/compare-handoff", data="{}", content_type="text/plain", base_url=ORIGIN).status_code == 415
    assert c.post("/api/compare-handoff", data="{}", content_type="application/json", headers={"Origin": "http://evil.example"}, base_url=ORIGIN).status_code == 403


def test_acmebank_rejects_cross_origin_but_keeps_non_browser_and_loan_desk(tmp_path):
    c = create_bank().test_client()
    assert c.post("/process", json={}, headers={"Origin": "http://evil.example"}).status_code == 403
    assert c.post("/process", json={}).status_code != 403  # non-browser client policy
    assert c.get("/health").status_code == 200


def test_three_concurrent_launches_under_limit_two(tmp_path):
    entered, release = threading.Semaphore(0), threading.Event()

    def blocking_health(_p):
        entered.release()
        release.wait(10)
        return 503, {"error": "stop here"}  # ends the launch right after the permit was held

    app = _app(tmp_path, get_fn=blocking_health, limit=2)
    results = []
    threads = [threading.Thread(target=lambda: results.append(_post(app.test_client()).status_code)) for _ in range(2)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=5) and entered.acquire(timeout=5)  # both permits are held
    third = _post(app.test_client())
    assert third.status_code == 429 and third.headers["Retry-After"] and third.get_json()["error"] == "launch_busy"
    release.set()
    for t in threads:
        t.join(10)
    assert sorted(results) == [503, 503]  # the two admitted ran to completion


@pytest.mark.parametrize("outcome", ["success", "exception", "timeout"])
def test_permit_released_after_success_exception_and_timeout(tmp_path, outcome):
    def get_fn(_p):
        if outcome == "exception":
            raise RuntimeError("boom")
        if outcome == "timeout":
            raise TimeoutError("runtime timed out")
        return 200, {"status": "healthy"}

    app = _app(tmp_path, get_fn=get_fn, limit=1)
    c = app.test_client()
    for _ in range(3):  # a leaked permit would make the second attempt a 429
        try:
            r = _post(c)
        except (RuntimeError, TimeoutError):
            continue
        assert r.status_code != 429


def test_host_header_cannot_poison_stored_launch_links(tmp_path):
    app = _app(tmp_path)
    c = app.test_client()
    launcher = app.config.get("AGENTSEC_LAUNCHER") or next(v for v in app.config.values() if hasattr(v, "render_body"))
    before = launcher.splunk_web
    r = _post(c, base_url="http://evil.example:5001", headers={"Host": "evil.example:5001"})
    assert launcher.splunk_web == before  # shared state untouched
    run_id = (r.get_json() or {}).get("run_id")
    if run_id:  # the stored record keeps the configured base; only the response is request-scoped
        stored = json.dumps(launcher.get_record(run_id).body)
        assert "evil.example" not in stored
    bad = _post(c, headers={"Host": "evil.example/<script>"})
    assert "<script>" not in bad.get_data(as_text=True)


def test_compare_handoff_links_are_request_scoped_and_leave_no_residue(tmp_path):
    app = _app(tmp_path)
    c = app.test_client()
    a, b = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    post = lambda host: c.post("/api/compare-handoff", data=json.dumps({"attack_run_id": a, "retest_run_id": b}), content_type="application/json", headers={"Host": host}, base_url=f"http://{host}")
    good = post("lab.example:5001").get_data(as_text=True)
    assert "lab.example:8000" in good
    hostile = post("evil.example/x\"<s>").get_data(as_text=True)
    assert "<s>" not in hostile and "evil.example" not in hostile and "127.0.0.1:8000" in hostile
    again = post("127.0.0.1:5001").get_data(as_text=True)
    assert "lab.example" not in again  # the earlier request left nothing in shared state
