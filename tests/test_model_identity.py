"""RC2 phase 1: requested / resolved / executed model identity, exact matching, fail-closed behaviour and evidence.
Uses a REAL local HTTP server that behaves like Ollama (/api/tags, /api/version, /api/chat, /api/generate); no model is downloaded or run."""
import json, threading
import http.server
import pytest
from jsonschema import ValidationError

from agentsec import model_identity as mi
from agentsec.llm import OllamaClient
from agentsec.loan_desk.model import OllamaChat, configured_model_name
from agentsec.loan_desk.events import LoanDeskEmitter
from agentsec.loan_desk.service import LoanDeskService
from agentsec.schema import validate_event
from agentsec.telemetry import MemorySink
from tests.loan_desk_support import GOOD_FORM

DIGEST_1B = "baf6a787fdff" + "0" * 52
DIGEST_3B = "a80c4f17acd5" + "1" * 52


class FakeOllama:
    """tags: list of (name, digest). answer_as: the model name the chat/generate response reports (default: whatever was requested)."""
    def __init__(self, tags, answer_as=None, version="0.40.12", chat_reply=None):
        self.tags, self.answer_as, self.version, self.calls = tags, answer_as, version, []
        self.chat_reply = chat_reply or {"action": "final", "summary": "Income and credit profile are consistent with lending policy for this request.", "recommendation": "PROCEED_TO_UNDERWRITER"}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def _send(self, code, obj):
                b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            def do_GET(self):
                outer.calls.append(("GET", self.path))
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": n, "model": n, "digest": d, "size": 1300000000, "details": {"family": "llama", "parameter_size": "1.2B", "quantization_level": "Q8_0"}} for n, d in outer.tags]})
                elif self.path == "/api/version":
                    self._send(200, {"version": outer.version})
                else:
                    self._send(404, {})
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                outer.calls.append(("POST", self.path, body.get("model")))
                shown = body.get("model") if outer.answer_as is None else outer.answer_as
                if self.path == "/api/chat":
                    self._send(200, {"model": shown, "message": {"role": "assistant", "content": json.dumps(outer.chat_reply)}, "prompt_eval_count": 7, "eval_count": 9})
                elif self.path == "/api/generate":
                    self._send(200, {"model": shown, "response": "ok text", "prompt_eval_count": 3, "eval_count": 2, "total_duration": 5_000_000})
                else:
                    self._send(404, {})
            def log_message(self, *a): pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
    def posts(self): return [c for c in self.calls if c[0] == "POST"]
    def close(self): self.srv.shutdown()


@pytest.fixture()
def ollama():
    made = []
    def make(*a, **k):
        f = FakeOllama(*a, **k); made.append(f); return f
    yield make
    for f in made: f.close()


def _client(settings, url, model):
    import dataclasses
    return OllamaClient(dataclasses.replace(settings, ollama_base_url=url, ollama_model=model), cache=mi.ResolutionCache(ttl=0))


def _gen(c):
    return c.generate(agent_id="a", system_prompt="s", user_message="u", temperature=0.2, max_tokens=20)


# ---- one canonical configuration --------------------------------------------------------------------------------------------------------------
def test_defaults_and_variables_are_unchanged_for_configured_installations(monkeypatch):
    for v in ("OLLAMA_MODEL", "LOANDESK_MODEL"): monkeypatch.delenv(v, raising=False)
    assert mi.requested("pipeline") == "llama3.2:1b" and mi.requested("loan_desk") == "llama3.2:latest" and configured_model_name() == "llama3.2:latest"
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3:4b-instruct-2507-q4_K_M"); monkeypatch.setenv("LOANDESK_MODEL", " llama3.2:3b ")
    assert mi.requested("pipeline") == "qwen3:4b-instruct-2507-q4_K_M" and mi.requested("loan_desk") == "llama3.2:3b" and configured_model_name() == "llama3.2:3b"


def test_settings_and_loan_desk_read_the_same_resolver(monkeypatch, settings):
    from agentsec.settings import get_settings, reset_settings_cache
    monkeypatch.setenv("OLLAMA_MODEL", "granite4.1:3b-q4_K_M"); reset_settings_cache()
    assert get_settings().ollama_model == mi.requested("pipeline") == "granite4.1:3b-q4_K_M"
    reset_settings_cache()


@pytest.mark.parametrize("bad", ["has space:1b", "a:b:c", ":tag", "llama3.2:", "x" * 300, "../etc", "name@sha256:abc", "a\nb"])
def test_a_malformed_model_name_is_refused_not_run(monkeypatch, bad):
    monkeypatch.setenv("OLLAMA_MODEL", bad)
    with pytest.raises(mi.ModelConfigError):
        mi.requested("pipeline")


def test_normalisation_follows_ollamas_untagged_means_latest_rule_and_nothing_more():
    assert mi.normalize("llama3.2") == "llama3.2:latest" and mi.normalize("llama3.2:1b") == "llama3.2:1b"
    assert mi.normalize("Llama3.2:1b") != mi.normalize("llama3.2:1b")        # no case folding or other guessing


# ---- exact resolution --------------------------------------------------------------------------------------------------------------------------
def test_exact_name_resolves_with_digest_and_ollama_version(ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    r = mi.resolve(f.url, "llama3.2:1b")
    assert r.ok and r.digest == DIGEST_1B and r.quantization == "Q8_0" and r.parameter_size == "1.2B" and r.ollama_version == "0.40.12" and r.identity_status == "DIGEST_RECORDED"


@pytest.mark.parametrize("want,installed", [
    ("llama3.2:1b", "llama3.2:latest"),            # same family, different tag (the old family-prefix match accepted this)
    ("llama3.2:latest", "llama3.2:1b"),
    ("llama3.2", "llama3.2:1b"),                   # untagged means :latest, not "any llama3.2"
    ("llama3.2:1b", "llama3.2:1b-instruct-q8_0"),  # a longer tag is a different model
    ("llama3.2:1b", "llama3:1b"), ("llama3.2:1b", "xllama3.2:1b"), ("llama3.2:1b", "LLAMA3.2:1B"),
])
def test_no_family_prefix_tag_or_case_substitution(ollama, want, installed):
    f = ollama([(installed, DIGEST_3B)])
    r = mi.resolve(f.url, want)
    assert r.status == mi.NOT_INSTALLED and not r.ok and r.digest is None


def test_failures_are_classified_and_never_raise(ollama):
    assert mi.resolve("http://127.0.0.1:9", "llama3.2:1b").status == mi.UNREACHABLE
    f = ollama([])
    f.tags = [("llama3.2:1b", "")]                  # installed, but Ollama reports no digest: the name is verified, the digest is not claimed
    r = mi.resolve(f.url, "llama3.2:1b")
    assert r.ok and r.digest is None and r.identity_status == "NAME_VERIFIED"
    class Bad:
        status_code = 200
        def json(self): raise ValueError("x")
    assert mi.resolve("http://x", "llama3.2:1b", get=lambda *a, **k: Bad()).status == mi.ERROR
    class Err:
        status_code = 500
        def json(self): return {}
    assert mi.resolve("http://x", "llama3.2:1b", get=lambda *a, **k: Err()).status == mi.ERROR


# ---- AcmeBank pipeline client ------------------------------------------------------------------------------------------------------------------
def test_pipeline_client_records_requested_resolved_and_executed_identity(settings, ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    r = _gen(_client(settings, f.url, "llama3.2:1b"))
    assert r.ok and r.text == "ok text"
    i = r.identity
    assert i["requested"] == "llama3.2:1b" and i["digest"] == DIGEST_1B and i["ollama_version"] == "0.40.12" and i["identity_status"] == "DIGEST_RECORDED"
    assert i["executed"] == {"response_model": "llama3.2:1b", "name_matches_requested": True}
    assert f.posts() == [("POST", "/api/generate", "llama3.2:1b")]


def test_pipeline_health_is_exact_not_family_prefix(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])
    assert _client(settings, f.url, "llama3.2:1b").health() is False                       # the old code returned True here (family substring)
    assert _client(settings, f.url, "llama3.2:latest").health() is True


def test_pipeline_fails_closed_when_the_model_is_missing_and_sends_nothing(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])                                           # a different tag of the same family IS installed
    r = _gen(_client(settings, f.url, "llama3.2:1b"))
    assert not r.ok and r.error_type == "model_not_installed" and r.text == "" and "llama3.2:1b" in r.error_message
    assert f.posts() == []                                                                 # the prompt never reached any model
    assert r.identity["status"] == mi.NOT_INSTALLED


def test_pipeline_unreachable_keeps_the_connection_error_contract(settings):
    r = _gen(_client(settings, "http://127.0.0.1:9", "llama3.2:1b"))
    assert not r.ok and r.error_type == "connection_error" and r.text == ""


def test_pipeline_discards_text_from_a_model_that_is_not_the_one_requested(settings, ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)], answer_as="qwen3:4b")
    r = _gen(_client(settings, f.url, "llama3.2:1b"))
    assert not r.ok and r.error_type == "model_identity_mismatch" and r.text == "" and r.identity["executed"]["name_matches_requested"] is False
    assert mi.summarize_calls("llama3.2:1b", [r.identity])["identity_status"] == "MISMATCH"                 # judged from THIS call's own record


def test_a_response_that_does_not_name_a_model_is_unverified_not_a_mismatch(settings, ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)], answer_as="")
    r = _gen(_client(settings, f.url, "llama3.2:1b"))
    assert r.ok and r.identity["executed"] == {"response_model": None, "name_matches_requested": None}


# ---- Loan Desk client --------------------------------------------------------------------------------------------------------------------------
def test_loan_desk_identity_keeps_old_keys_and_adds_requested_status_and_version(ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])
    i = OllamaChat(f.url, "llama3.2:latest").identity()
    assert {"name", "digest", "size_bytes", "family", "parameter_size", "quantization", "runtime"} <= set(i)
    assert i["requested"] == "llama3.2:latest" and i["digest"] == DIGEST_3B and i["identity_status"] == "DIGEST_RECORDED" and i["ollama_version"] == "0.40.12"
    gone = OllamaChat(f.url, "llama3.2:1b").identity()
    assert gone["identity_status"] == mi.NOT_INSTALLED and "digest" not in gone


def test_loan_desk_readiness_and_availability_are_exact(ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    m = OllamaChat(f.url, "llama3.2:latest")
    rd = m.readiness()
    assert rd["ollama_reachable"] and not rd["model_installed"] and rd["fix"]["command"] == "ollama pull llama3.2:latest"
    assert m.available() == (False, "Ollama is reachable but model 'llama3.2:latest' is not installed.")


def test_loan_desk_chat_is_refused_when_the_requested_model_is_missing(ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    rep = OllamaChat(f.url, "llama3.2:latest").chat([{"role": "user", "content": "x"}])
    assert not rep.ok and rep.error_type == "model_not_found" and f.posts() == []


def test_loan_desk_chat_discards_a_mismatched_answer(ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)], answer_as="llama3.2:1b")
    rep = OllamaChat(f.url, "llama3.2:latest").chat([{"role": "user", "content": "x"}])
    assert not rep.ok and rep.error_type == "model_identity_mismatch" and rep.text == "" and rep.executed["name_matches_requested"] is False


# ---- Loan Desk events, run view and schema ----------------------------------------------------------------------------------------------------
def _service(settings, url, model="llama3.2:latest"):
    sink = MemorySink()
    return LoanDeskService(settings=settings, model=OllamaChat(url, model), sink=sink, background=False), sink


def test_a_live_style_run_records_requested_resolved_and_executed_in_events_and_view(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])
    svc, sink = _service(settings, f.url)
    view, errors = svc.submit(dict(GOOD_FORM), "hardened")
    assert not errors and view is not None
    final = svc.view(view["run_id"])
    ident = final["model"]["identity"]
    assert ident["requested"] == "llama3.2:latest" and ident["digest"] == DIGEST_3B and ident["ollama_version"] == "0.40.12"
    assert ident["executed"]["response_models"] == ["llama3.2:latest"] and ident["executed"]["all_match_requested"] is True and ident["executed"]["digest_unchanged_during_run"] is True
    ev = [e for e in sink.events if e["event.name"] in ("agentsec.run.started", "agentsec.llm.started", "agentsec.llm.completed")]
    assert ev, "events were emitted"
    for e in ev:
        assert e["agentsec.schema.version"] == "1.1.0" and e["agentsec.model.requested"] == "llama3.2:latest" and e["agentsec.model.digest"] == DIGEST_3B
        assert e["agentsec.model.identity_status"] == "DIGEST_RECORDED" and e["agentsec.ollama.version"] == "0.40.12"
        validate_event(e)
    done = next(e for e in ev if e["event.name"] == "agentsec.llm.completed")
    assert done["agentsec.model.executed_name_matches"] is True and done["gen_ai.request.model"] == "llama3.2:latest"
    assert final["evidence"]["schema"] == "agentsec.loan_desk_event 1.1.0"


def test_a_digest_that_changes_during_a_run_is_reported(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])
    svc, _ = _service(settings, f.url)
    orig = svc.model.chat
    def swap(messages):
        f.tags = [("llama3.2:latest", "ffff" + "2" * 60)]            # the tag is re-pointed while the run is in flight
        return orig(messages)
    svc.model.chat = swap
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    assert svc.view(view["run_id"])["model"]["identity"]["executed"]["digest_unchanged_during_run"] is False


def test_test_doubles_keep_schema_1_0_0_and_gain_no_identity(settings):
    from tests.loan_desk_support import PostureAwareModel
    sink = MemorySink()
    svc = LoanDeskService(settings=settings, model=PostureAwareModel(), sink=sink, background=False)
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    v = svc.view(view["run_id"])
    assert v["model"]["identity"] == {} and v["evidence"]["schema"] == "agentsec.loan_desk_event 1.0.0"
    assert all(e["agentsec.schema.version"] == "1.0.0" and not any(k.startswith("agentsec.model.") for k in e) for e in sink.events)


def test_schema_1_1_0_is_additive_and_closed(settings):
    base = LoanDeskEmitter(sink=lambda e: None, settings=settings, model="m", user_id="u")
    old = base.run_started()
    assert old["agentsec.schema.version"] == "1.0.0"
    validate_event(old)                                                                      # a recorded 1.0.0 event still validates
    new = LoanDeskEmitter(sink=lambda e: None, settings=settings, model="m", user_id="u", identity={"requested": "m", "identity_status": "DIGEST_RECORDED", "digest": "d"}).run_started()
    validate_event(new)
    bad = dict(new); bad["agentsec.model.identity_status"] = "SORT_OF_VERIFIED"
    with pytest.raises(ValidationError):
        validate_event(bad)
    unknown = dict(new); unknown["agentsec.model.guess"] = "x"
    with pytest.raises(ValidationError):
        validate_event(unknown)                                                              # still a closed schema


def test_the_frozen_security_event_schema_is_untouched():
    """security_event.schema.json 1.9.0 stays byte-identical to the published v1.3.0 RC1 file: model identity rides in the Loan Desk family and the evidence manifest."""
    import hashlib
    from pathlib import Path
    digest = hashlib.sha256((Path(__file__).resolve().parents[1] / "schemas" / "security_event.schema.json").read_bytes()).hexdigest()
    assert digest == "83fd480bafe6ebef9263a93dbe6bb6ff96f1320728460f882df1472f9ee634d8"


# ---- AcmeBank /health, Academy status, evidence manifest ---------------------------------------------------------------------------------------
def test_health_reports_each_roles_requested_and_exact_resolution(settings, ollama, monkeypatch):
    from agentsec.bank_app import build_runtime, create_app
    import dataclasses
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    s = dataclasses.replace(settings, ollama_base_url=f.url, ollama_model="llama3.2:1b")
    monkeypatch.setenv("OLLAMA_BASE_URL", f.url); monkeypatch.setenv("LOANDESK_MODEL", "llama3.2:latest")
    rt = build_runtime(s, llm=OllamaClient(s, cache=mi.ResolutionCache(ttl=0)), otel_enabled=False)
    h = create_app(rt).test_client().get("/health").get_json()
    assert h["ollama_reachable"] is True and h["ollama_model"] == "llama3.2:1b" and h["ollama_version"] == "0.40.12"
    assert h["models"]["pipeline"]["installed_exact"] is True and h["models"]["pipeline"]["digest"] == DIGEST_1B
    assert h["models"]["loan_desk"]["requested"] == "llama3.2:latest" and h["models"]["loan_desk"]["installed_exact"] is False       # not substituted by llama3.2:1b


def test_academy_status_shows_the_loan_desk_model_separately_and_does_not_hide_a_missing_one(tmp_path):
    from agentsec.attack_app import AcmeBankClient, create_app
    body = {"status": "healthy", "security.profile": "defended", "ollama_reachable": True, "ollama_model": "llama3.2:1b",
            "models": {"pipeline": {"requested": "llama3.2:1b", "installed_exact": True, "digest": DIGEST_1B},
                       "loan_desk": {"requested": "llama3.2:latest", "installed_exact": False}}}
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda p: (200, body)), launch_kwargs={"artifacts_dir": tmp_path})
    checks = {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}
    assert checks["Optional model (Ollama)"]["state"] == "AVAILABLE" and "exactly that name" in checks["Optional model (Ollama)"]["detail"] and DIGEST_1B[:12] in checks["Optional model (Ollama)"]["detail"]
    row = checks["Loan Desk model"]
    assert row["state"] == "DEGRADED" and row["optional"] is True and "llama3.2:latest" in row["detail"] and "refused rather than run on another model" in row["detail"]
    body["models"]["loan_desk"] = {"requested": "llama3.2:latest", "installed_exact": True, "digest": DIGEST_3B}
    assert {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}["Loan Desk model"]["state"] == "AVAILABLE"


def test_academy_status_is_unchanged_for_an_older_acmebank_without_the_models_field(tmp_path):
    from agentsec.attack_app import AcmeBankClient, create_app
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda p: (200, {"status": "healthy", "ollama_reachable": True, "ollama_model": "m"})), launch_kwargs={"artifacts_dir": tmp_path})
    names = [c["name"] for c in app.test_client().get("/api/academy/status").get_json()["checks"]]
    assert "Loan Desk model" not in names and "Optional model (Ollama)" in names


def _pipeline(settings, url, model, memory):
    """A real pipeline run with the real OllamaClient against the fake Ollama; returns (result, manifest)."""
    import dataclasses
    from pathlib import Path
    from agentsec.attacks import BENIGN_LOAN
    from agentsec.pipeline import run_loan_pipeline
    s = dataclasses.replace(settings, ollama_base_url=url, ollama_model=model)
    r = run_loan_pipeline(BENIGN_LOAN, llm=OllamaClient(s, cache=mi.ResolutionCache(ttl=0)), sink=memory, memory=memory, settings=s, testbed_mode="BASELINE", attack_id="ATK-001")
    return r, json.loads((Path(r.evidence_dir) / "manifest.json").read_text())


def test_manifest_records_requested_resolved_and_executed_for_a_live_pipeline_run(settings, ollama, memory):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    r, m = _pipeline(settings, f.url, "llama3.2:1b", memory)
    ident = m["model.identity"]
    assert m["model"] == "llama3.2:1b"                                                       # the old key is unchanged
    assert r.terminal != "run_failed" and ident["identity_status"] == "DIGEST_RECORDED" and ident["calls"] >= 1
    assert ident["resolved"]["digest"] == DIGEST_1B and ident["resolved"]["ollama_version"] == "0.40.12" and ident["requested"] == "llama3.2:1b"
    assert ident["executed_response_models"] == ["llama3.2:1b"] and ident["digest_observed_before_call"] is True


def test_manifest_reports_a_mismatching_model_in_the_pipeline_path(settings, ollama, memory):
    f = ollama([("llama3.2:1b", DIGEST_1B)], answer_as="qwen3:4b")                           # the real client sees a different model answer
    r, m = _pipeline(settings, f.url, "llama3.2:1b", memory)
    assert r.terminal == "run_failed" and m["model.identity"]["identity_status"] == "MISMATCH"


def test_manifest_does_not_call_an_unnamed_answer_verified(settings, ollama, memory):
    f = ollama([("llama3.2:1b", DIGEST_1B)], answer_as="")                                   # Ollama answers without naming a model
    r, m = _pipeline(settings, f.url, "llama3.2:1b", memory)
    assert m["model.identity"]["identity_status"] == "UNVERIFIED_RESPONSE" and m["model.identity"]["executed_response_models"] == []


def test_a_refused_pipeline_run_records_the_refusal_and_no_digest(settings, ollama, memory):
    _pipeline(settings, ollama([("llama3.2:1b", DIGEST_1B)]).url, "llama3.2:1b", memory)     # an earlier live run in the same process
    f = ollama([("llama3.2:latest", DIGEST_3B)])                                             # now: same family installed, requested tag absent
    r, m = _pipeline(settings, f.url, "llama3.2:1b", memory)
    assert r.error_stage == "llm_invocation" and f.posts() == []
    assert m["model.identity"]["identity_status"] == "NOT_INSTALLED" and m["model.identity"]["resolved"] is None


def test_runs_without_a_model_call_and_stubs_say_not_resolved(settings, memory):
    from agentsec.attacks import BENIGN_LOAN
    from agentsec.llm import StubLLM
    from agentsec.pipeline import run_loan_pipeline
    from pathlib import Path
    r = run_loan_pipeline(BENIGN_LOAN, llm=StubLLM(), sink=memory, memory=memory, settings=settings, testbed_mode="BASELINE", attack_id="ATK-001")
    ident = json.loads((Path(r.evidence_dir) / "manifest.json").read_text())["model.identity"]
    assert ident["identity_status"] == "NOT_RESOLVED" and ident["resolved"] is None and "digest" not in json.dumps(ident["resolved"])


def test_summarize_calls_verdict_order_and_digest_change():
    ok = lambda d, m="llama3.2:1b": {"status": "EXACT", "identity_status": "DIGEST_RECORDED", "digest": d, "name": "llama3.2:1b", "executed": {"response_model": m, "name_matches_requested": True}}
    assert mi.summarize_calls("llama3.2:1b", [ok("a"), ok("a")])["identity_status"] == "DIGEST_RECORDED"
    assert mi.summarize_calls("llama3.2:1b", [ok("a"), ok("b")])["identity_status"] == "DIGEST_CHANGED"
    bad = {**ok("a"), "executed": {"response_model": "x", "name_matches_requested": False}}
    assert mi.summarize_calls("llama3.2:1b", [ok("a"), bad])["identity_status"] == "MISMATCH"                  # mismatch outranks everything
    gone = {"status": "NOT_INSTALLED", "identity_status": "NOT_INSTALLED"}
    assert mi.summarize_calls("llama3.2:1b", [ok("a"), gone])["identity_status"] == "NOT_INSTALLED"
    assert mi.summarize_calls("llama3.2:1b", [])["identity_status"] == "NOT_RESOLVED" and mi.summarize_calls("llama3.2:1b", None)["resolved"] is None
    assert mi.summarize_calls("m", ["junk", None])["identity_status"] == "NOT_RESOLVED"


# ---- review conditions: robustness, cache, names, end-to-end Loan Desk edge cases ------------------------------------------------------------
def test_oversized_or_malformed_fields_from_ollama_are_bounded_and_never_crash_resolution(ollama):
    f = ollama([("llama3.2:1b", "d" * 500)])
    r = mi.resolve(f.url, "llama3.2:1b")
    assert r.ok and len(r.digest) == 128
    class R:
        status_code = 200
        def json(self): return {"models": ["junk", None, {"name": "llama3.2:1b", "digest": 7, "size": "big", "details": "not a dict"}, {"name": "x", "details": []}]}
    r = mi.resolve("http://x", "llama3.2:1b", get=lambda *a, **k: R())
    assert r.ok and r.digest is None and r.size_bytes is None and r.family is None and r.identity_status == "NAME_VERIFIED"


def test_duplicate_names_with_different_digests_are_refused_not_guessed():
    class R:
        status_code = 200
        def json(self): return {"models": [{"name": "llama3.2:1b", "digest": "a" * 64}, {"name": "llama3.2:1b", "digest": "b" * 64}]}
    r = mi.resolve("http://x", "llama3.2:1b", get=lambda *a, **k: R())
    assert r.status == mi.ERROR and not r.ok and "more than once" in r.detail


@pytest.mark.parametrize("good", ["llama3.2:1b", "llama3.2", "library/llama3.2:3b", "registry.example.org/team/model:v1", "localhost:5000/team/model", "localhost:5000/team/model:v2"])
def test_registry_style_names_are_accepted(good):
    assert mi.normalize(good).count(":") >= 1


def test_registry_port_is_not_mistaken_for_a_tag():
    assert mi.normalize("localhost:5000/team/model") == "localhost:5000/team/model:latest"
    assert mi.normalize("localhost:5000/team/model:v2") == "localhost:5000/team/model:v2"


@pytest.mark.parametrize("bad", ["a/../b", "a..b", "host:99999999/x", "UPPER CASE", "a/b/", "a//b", "/abs", "a/:tag"])
def test_unsafe_names_are_invalid(bad):
    with pytest.raises(mi.ModelConfigError):
        mi.normalize(bad)


def test_a_padded_response_model_name_is_not_the_requested_name():
    assert mi.response_matches("llama3.2:1b", "llama3.2:1b") is True
    assert mi.response_matches("llama3.2:1b", " llama3.2:1b") is False and mi.response_matches("llama3.2:1b", "llama3.2:1b\n") is False
    assert mi.response_matches("llama3.2:1b", None) is None and mi.response_matches("llama3.2:1b", "") is None


def test_the_cache_serves_installed_for_its_ttl_but_never_remembers_a_failure(ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    t = [100.0]
    c = mi.ResolutionCache(ttl=5, clock=lambda: t[0])
    assert c.get(f.url, "llama3.2:1b").ok
    n = len([x for x in f.calls if x == ("GET", "/api/tags")])
    t[0] += 3; assert c.get(f.url, "llama3.2:1b").ok
    assert len([x for x in f.calls if x == ("GET", "/api/tags")]) == n                       # inside the TTL: no new request
    t[0] += 3; assert c.get(f.url, "llama3.2:1b").ok
    assert len([x for x in f.calls if x == ("GET", "/api/tags")]) == n + 1                   # after it: asked again
    down = mi.ResolutionCache(ttl=5, clock=lambda: t[0])
    assert down.get("http://127.0.0.1:9", "llama3.2:1b").status == mi.UNREACHABLE
    assert down.get(f.url, "llama3.2:1b").ok                                                 # a transient failure is not remembered (other base url, same key family)
    same_key = mi.ResolutionCache(ttl=5, clock=lambda: t[0])
    calls = []
    def flaky(url, timeout):
        calls.append(url)
        if len(calls) == 1:
            raise __import__("requests").ConnectionError("blip")
        return type("R", (), {"status_code": 200, "json": lambda self: {"models": [{"name": "llama3.2:1b", "digest": "z"}]}})()
    assert same_key.get("http://x", "llama3.2:1b", get=flaky).status == mi.UNREACHABLE
    assert same_key.get("http://x", "llama3.2:1b", get=flaky).ok                             # asked again at once


def test_a_malformed_model_name_does_not_stop_settings_but_every_live_call_is_refused(monkeypatch, settings, ollama):
    from agentsec.settings import get_settings, reset_settings_cache
    monkeypatch.setenv("OLLAMA_MODEL", "bad name:1b"); reset_settings_cache()
    s = get_settings()                                                                        # no crash: the Academy and replay do not need a model
    assert s.ollama_model == "bad name:1b"
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    import dataclasses
    c = OllamaClient(dataclasses.replace(s, ollama_base_url=f.url), cache=mi.ResolutionCache(ttl=0))
    assert c.health() is False
    r = _gen(c)
    assert not r.ok and r.error_type == "model_config_invalid" and f.posts() == []
    reset_settings_cache()


def _desk_events(sink):
    return [e for e in sink.events if e["event.name"].startswith(("agentsec.llm.", "agentsec.run."))]


def test_loan_desk_run_with_a_missing_model_fails_closed_with_the_verdict_in_its_events(settings, ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])                                                 # the family IS installed, the requested tag is not
    svc, sink = _service(settings, f.url, "llama3.2:latest")
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    v = svc.view(view["run_id"])
    assert v["status"] == "FAILED" and f.posts() == []
    failed = [e for e in sink.events if e["event.name"] == "agentsec.llm.failed"]
    assert failed and all(e["agentsec.model.identity_status"] == "NOT_INSTALLED" and "agentsec.model.digest" not in e for e in failed)
    for e in sink.events: validate_event(e)


def test_loan_desk_mismatch_run_is_marked_mismatch_not_digest_recorded(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)], answer_as="llama3.2:1b")
    svc, sink = _service(settings, f.url)
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    failed = [e for e in sink.events if e["event.name"] == "agentsec.llm.failed"]
    assert failed and all(e["agentsec.model.identity_status"] == "MISMATCH" and e["agentsec.model.executed_name_matches"] is False for e in failed)
    ex = svc.view(view["run_id"])["model"]["identity"]["executed"]
    assert ex["all_match_requested"] is False
    for e in sink.events: validate_event(e)


def test_loan_desk_response_without_a_model_name_is_unverified_not_a_match(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)], answer_as="")
    svc, sink = _service(settings, f.url)
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    ex = svc.view(view["run_id"])["model"]["identity"]["executed"]
    assert ex["all_match_requested"] is None and ex["calls_unverified"] >= 1 and ex["response_models"] == []
    done = [e for e in sink.events if e["event.name"] == "agentsec.llm.completed"]
    assert done and all("agentsec.model.executed_name_matches" not in e for e in done)       # absent, never True


# ---- review L2: a refused call is attempted but NOT executed ----------------------------------------------------------------------------------
def test_pipeline_refusal_is_fail_closed_and_its_manifest_inherits_no_digest(settings, ollama, memory):
    """The frozen security_event 1.9.0 requires operation.executed=true on llm events, so the pipeline's events keep that field; what they CANNOT hide is the outcome:
    error.type model_not_installed, no model response, nothing sent, and a manifest that records no model identity for the run (even after an earlier live call)."""
    import dataclasses
    from agentsec.attacks import BENIGN_LOAN
    from agentsec.events import EVENT_LLM_COMPLETED, EVENT_LLM_FAILED
    from agentsec.llm import CountingLLM
    from agentsec.pipeline import run_loan_pipeline
    from tests.helpers import events_named
    good = ollama([("llama3.2:1b", DIGEST_1B)])
    _gen(_client(settings, good.url, "llama3.2:1b"))                               # an earlier live call put a digest into the process registry
    f = ollama([("llama3.2:latest", DIGEST_3B)])                                  # same family installed, requested tag absent
    s = dataclasses.replace(settings, ollama_base_url=f.url, ollama_model="llama3.2:1b")
    result = run_loan_pipeline(BENIGN_LOAN, llm=CountingLLM(OllamaClient(s, cache=mi.ResolutionCache(ttl=0))), sink=memory, memory=memory, settings=s, testbed_mode="BASELINE", attack_id="ATK-001")
    failed = events_named(result.events, EVENT_LLM_FAILED)
    assert failed and events_named(result.events, EVENT_LLM_COMPLETED) == [] and failed[0]["error.type"] == "model_not_installed"
    assert result.error_stage == "llm_invocation" and f.posts() == []
    from pathlib import Path
    manifest = json.loads((Path(result.evidence_dir) / "manifest.json").read_text())
    assert manifest["model.identity"]["identity_status"] == "NOT_INSTALLED" and manifest["model.identity"]["resolved"] is None     # the refusal, and no inherited digest


def test_loan_desk_events_say_attempted_but_not_executed_when_the_model_is_refused(settings, ollama):
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    svc, sink = _service(settings, f.url, "llama3.2:latest")
    svc.submit(dict(GOOD_FORM), "hardened")
    started = [e for e in sink.events if e["event.name"] == "agentsec.llm.started"]
    failed = [e for e in sink.events if e["event.name"] == "agentsec.llm.failed"]
    assert started and failed
    for e in started + failed:
        assert e["agentsec.operation.attempted"] is True and e["agentsec.operation.executed"] is False and e["agentsec.model.identity_status"] == "NOT_INSTALLED"
        assert e["agentsec.schema.version"] == "1.1.0"
        validate_event(e)


def test_an_unreachable_ollama_keeps_the_executed_true_connection_contract(settings):
    svc, sink = _service(settings, "http://127.0.0.1:9", "llama3.2:latest")
    svc.submit(dict(GOOD_FORM), "hardened")
    for e in [e for e in sink.events if e["event.name"] in ("agentsec.llm.started", "agentsec.llm.failed")]:
        assert e["agentsec.operation.executed"] is True


def test_the_schema_allows_executed_false_only_for_a_fail_closed_refusal(settings):
    em = LoanDeskEmitter(sink=lambda e: None, settings=settings, model="m", user_id="u",
                         identity={"requested": "m", "identity_status": "NOT_INSTALLED"})
    em.run_started()
    span = em.llm_started(1, executed=False)
    ok = em.events[-1]
    validate_event(ok)
    for patch in ({"agentsec.model.identity_status": "DIGEST_RECORDED"}, {"agentsec.schema.version": "1.0.0"}):
        with pytest.raises(ValidationError):
            validate_event({**ok, **patch})
    em2 = LoanDeskEmitter(sink=lambda e: None, settings=settings, model="m", user_id="u")      # no identity: a 1.0.0 event can never claim executed=false
    em2.llm_started(1)
    with pytest.raises(ValidationError):
        validate_event({**em2.events[-1], "agentsec.operation.executed": False})
    em.llm_completed(1, span, duration_ms=1, tokens_in=1, tokens_out=1, response_model="m")
    with pytest.raises(ValidationError):
        validate_event({**em.events[-1], "agentsec.operation.executed": False})              # a completed call was executed, by definition


# ---- final-review conditions: M4 TypeError, M5 readiness guard, N2 model vanishing mid-run -----------------------------------------------------
@pytest.mark.parametrize("payload", [{"models": 5}, {"models": "x"}, {"models": {"a": 1}}, ["x"], 7, None])
def test_non_list_or_non_object_model_lists_never_raise(payload):
    class R:
        status_code = 200
        def json(self): return payload
    r = mi.resolve("http://x", "llama3.2:1b", get=lambda *a, **k: R())
    assert r.status in (mi.ERROR, mi.NOT_INSTALLED) and not r.ok


def test_a_malformed_loan_desk_model_name_gives_status_answers_not_a_crash(settings, ollama, monkeypatch):
    from agentsec.bank_app import build_runtime, create_app
    import dataclasses
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    s = dataclasses.replace(settings, ollama_base_url=f.url, ollama_model="llama3.2:1b")
    monkeypatch.setenv("LOANDESK_MODEL", "bad name")
    rt = build_runtime(s, llm=OllamaClient(s, cache=mi.ResolutionCache(ttl=0)), otel_enabled=False)
    c = create_app(rt).test_client()
    r = c.get("/api/v1/loan-desk/status")
    assert r.status_code == 200
    body = r.get_json()
    assert body["available"] is False and body["readiness"]["fix"]["kind"] == "invalid_model_name" and body["identity"]["identity_status"] == "INVALID_NAME"
    assert c.get("/health").status_code == 200


def test_a_model_that_disappears_mid_run_yields_valid_events_that_say_so(settings, ollama):
    f = ollama([("llama3.2:latest", DIGEST_3B)])
    svc, sink = _service(settings, f.url)
    real = svc.model.chat
    n = {"calls": 0}
    def vanish(messages):
        n["calls"] += 1
        rep = real(messages)
        f.tags = []                                                                     # the model is deleted after the first answer
        svc.model._cache.clear()
        return rep
    svc.model.chat = vanish
    view, _ = svc.submit(dict(GOOD_FORM), "hardened")
    for e in sink.events:
        validate_event(e)                                                               # every event, including the refused second call, is valid
    refused = [e for e in sink.events if e["event.name"] in ("agentsec.llm.started", "agentsec.llm.failed") and e["agentsec.operation.executed"] is False]
    assert n["calls"] == 1 and len(refused) == 2
    assert all(e["agentsec.model.identity_status"] == "NOT_INSTALLED" and "agentsec.model.digest" not in e for e in refused)
    v = svc.view(view["run_id"])
    assert v["status"] == "FAILED" and v["stop_reason"] == "model_unavailable" and "model_not_found" in v["error"]


@pytest.mark.parametrize("payload", [[1, 2], {"models": 5}, {"models": "x"}, {"models": [1, None, "x"]}, "text", None])
def test_loan_desk_readiness_survives_any_model_list_payload(payload):
    import requests
    class R:
        status_code = 200
        def json(self): return payload
    m = OllamaChat("http://x", "llama3.2:latest")
    orig = requests.get
    requests.get = lambda *a, **k: R()
    try:
        rd = m.readiness()
    finally:
        requests.get = orig
    assert rd["model_installed"] is False and rd["fix"] is not None                          # answered, never raised


def test_a_timeout_after_resolution_is_recorded_as_a_failed_call_not_as_nothing(settings, ollama, memory, monkeypatch):
    import requests
    f = ollama([("llama3.2:1b", DIGEST_1B)])
    def boom(*a, **k): raise requests.Timeout("slow")
    monkeypatch.setattr(requests, "post", boom)
    r, m = _pipeline(settings, f.url, "llama3.2:1b", memory)
    assert r.terminal == "run_failed" and m["model.identity"]["calls"] == 1 and m["model.identity"]["identity_status"] == "CALL_FAILED"
    assert m["model.identity"]["resolved"]["digest"] == DIGEST_1B                            # the digest Ollama observed before the call that timed out
