"""The Academy status endpoint reports what it MEASURED on the CONFIGURED Splunk endpoint, stage by stage (RC1 M-5).
Reachability is never reported as a working integration; a service that answers on a port nobody configured is never counted."""
import http.server, threading
import pytest
from agentsec import academy_web as aw
from agentsec import splunk_client as sc
from agentsec.attack_app import AcmeBankClient, create_app

ENV = ("AGENTSEC_SPLUNK_MODE", "AGENTSEC_SPLUNK_INTERNAL_URL", "AGENTSEC_SPLUNK_WEB_URL")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ENV: monkeypatch.delenv(k, raising=False)
    aw._REST_CACHE.update(at=0.0, result=None)


@pytest.fixture()
def splunk_web():
    """A real HTTP server that answers like Splunk Web's login page. It runs on a port nobody has configured unless a test says so."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"login")
        def log_message(self, *a): pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_candidates_are_only_configured_endpoints(monkeypatch):
    assert aw._splunk_web_candidates() == ["http://agentsec_splunk:8000"]                      # bundled default: the lab's own container, nothing else
    monkeypatch.setenv("AGENTSEC_SPLUNK_WEB_URL", "http://127.0.0.1:8000/")
    monkeypatch.setenv("AGENTSEC_SPLUNK_INTERNAL_URL", "http://splunk.internal:8000")
    assert aw._splunk_web_candidates() == ["http://splunk.internal:8000", "http://agentsec_splunk:8000", "http://127.0.0.1:8000"]
    joined = " ".join(aw._splunk_web_candidates())
    assert "host.docker.internal" not in joined and "http://splunk:8000" not in joined
    monkeypatch.setenv("AGENTSEC_SPLUNK_MODE", "CLOUD")
    assert aw._splunk_web_candidates() == ["http://splunk.internal:8000"]                      # external mode: never the bundled container


def test_a_service_on_an_unconfigured_port_is_not_reported_as_the_labs_splunk(splunk_web, monkeypatch):
    # something answers on this machine, but the deployment does not name it: the check must say UNAVAILABLE
    probed = []
    real = aw.urllib.request.urlopen
    monkeypatch.setattr(aw.urllib.request, "urlopen", lambda req, timeout=None: probed.append(req.full_url) or (_ for _ in ()).throw(OSError("nope")))
    r = aw.probe_splunk_web(timeout=0.2)
    assert r["state"] == "UNAVAILABLE" and probed == ["http://agentsec_splunk:8000/en-US/account/login"]
    monkeypatch.setattr(aw.urllib.request, "urlopen", real)
    monkeypatch.setenv("AGENTSEC_SPLUNK_WEB_URL", splunk_web)                                    # now it IS configured
    ok = aw.probe_splunk_web(timeout=1)
    assert ok["state"] == "AVAILABLE" and "reachability only" in ok["detail"] and "login or a search" in ok["detail"] and splunk_web not in ok["detail"]


def test_external_mode_without_a_configured_web_url_is_not_probed_and_not_claimed(monkeypatch):
    monkeypatch.setenv("AGENTSEC_SPLUNK_MODE", "EXTERNAL_ENTERPRISE")
    monkeypatch.setattr(aw.urllib.request, "urlopen", lambda *a, **k: pytest.fail("no network call is expected"))
    r = aw.probe_splunk_web()
    assert r["state"] == "NOT CHECKED" and r["evidence"] == "UNTESTED"


class FakeClient:
    def __init__(self, stages): self.stages, self.calls = stages, 0
    def diagnose(self, run_id=None):
        self.calls += 1
        return [(k, v, "x") for k, v in self.stages.items()]


PASS = {"connectivity": "PASS", "authentication": "PASS", "authorization": "PASS", "search": "PASS", "telemetry": "NOT VERIFIED"}


def test_reachability_authentication_and_operation_are_distinct_states():
    ok = aw.probe_splunk_rest(client=FakeClient(PASS))
    assert ok["state"] == "AVAILABLE" and "indexed evidence" in ok["detail"].lower() and "NOT VERIFIED" in ok["detail"]
    for broken, want in [({"authentication": "FAIL"}, "DEGRADED"), ({"authorization": "FAIL"}, "DEGRADED"), ({"search": "FAIL"}, "DEGRADED"),
                         ({"search": "NOT VERIFIED"}, "DEGRADED"), ({"connectivity": "FAIL", "authentication": "NOT VERIFIED", "authorization": "NOT VERIFIED", "search": "NOT VERIFIED"}, "UNAVAILABLE")]:
        r = aw.probe_splunk_rest(client=FakeClient({**PASS, **broken}))
        assert r["state"] == want, (broken, r)
        assert r["state"] != "AVAILABLE" and "working integration" in r["detail"]


def test_bundled_mode_has_no_rest_check_and_a_bad_external_configuration_fails_closed(monkeypatch):
    assert aw.probe_splunk_rest() is None
    monkeypatch.setenv("AGENTSEC_SPLUNK_MODE", "CLOUD")
    monkeypatch.setenv("AGENTSEC_SPLUNK_REST_URL", "http://insecure:8089")
    r = aw.probe_splunk_rest()
    assert r["state"] == "UNAVAILABLE" and "config_invalid" in r["detail"] and "insecure" not in r["detail"] and "falls back" in r["detail"]


def test_the_rest_check_is_cached_briefly(monkeypatch):
    c = FakeClient(PASS); t = [100.0]
    monkeypatch.setattr(sc, "client_for_mode", lambda env=None: c)
    first = aw.probe_splunk_rest(ttl=30, clock=lambda: t[0]); t[0] += 10
    assert aw.probe_splunk_rest(ttl=30, clock=lambda: t[0]) is first and c.calls == 1
    t[0] += 40
    aw.probe_splunk_rest(ttl=30, clock=lambda: t[0]); assert c.calls == 2


def test_the_status_endpoint_lists_the_rest_check_in_external_mode_and_never_claims_indexing(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_SPLUNK_MODE", "EXTERNAL_ENTERPRISE")
    monkeypatch.setattr(sc, "client_for_mode", lambda env=None: FakeClient({**PASS, "authentication": "FAIL"}))
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda p: (200, {"status": "healthy"})), launch_kwargs={"artifacts_dir": tmp_path})
    checks = {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}
    assert checks["Splunk REST (configured endpoint)"]["state"] == "DEGRADED"
    assert checks["Splunk Web (reachability)"]["state"] == "NOT CHECKED"
    assert checks["Splunk indexing"]["state"] == "NOT CHECKED" and "authenticate" in checks["Splunk indexing"]["detail"]


def test_concurrent_status_polls_run_one_diagnose(monkeypatch):
    """RC1 review F6: the cache is filled under a lock, so a burst of learners polling /api/academy/status does not fan out to the external Splunk."""
    import threading, time
    calls = []
    class Slow:
        def diagnose(self, run_id=None):
            calls.append(1); time.sleep(0.3); return [(k, v, "x") for k, v in PASS.items()]
    monkeypatch.setattr(sc, "client_for_mode", lambda env=None: Slow())
    out = []
    ts = [threading.Thread(target=lambda: out.append(aw.probe_splunk_rest(ttl=30))) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(calls) == 1 and len(out) == 8 and all(r["state"] == "AVAILABLE" for r in out)
