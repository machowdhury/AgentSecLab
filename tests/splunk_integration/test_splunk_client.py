"""Provider-neutral Splunk layer: configuration validation, strict TLS, staged diagnosis, backends. MOCK ONLY (see mock_splunk.py);
real-Splunk verification is listed in docs/SPLUNK_INTEGRATION.md as NOT VERIFIED."""
import os, re, subprocess, sys, time
from pathlib import Path
import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / "src"), str(HERE), str(ROOT / "tests" / "gateway")]
import mock_splunk as ms                                                   # noqa: E402
from gwhelpers import make_ca, make_leaf, needs_openssl                    # noqa: E402
from agentsec import splunk_client as sc                                   # noqa: E402
from agentsec.loan_desk import search as srch                              # noqa: E402

pytestmark = needs_openssl


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("spl")
    ca, cak = make_ca(d / "ca", "mock-splunk-ca")
    cert, key = make_leaf(d / "good", ca, cak, "DNS:splunk.test,IP:127.0.0.1")
    wrong_cert, wrong_key = make_leaf(d / "wrongname", ca, cak, "DNS:someone-else.test")
    exp_cert, exp_key = make_leaf(d / "exp", ca, cak, "IP:127.0.0.1", "server", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z")
    other_ca, _ = make_ca(d / "other", "unrelated-ca")
    servers = {n: ms.start(c, k) for n, (c, k) in {"good": (cert, key), "wrongname": (wrong_cert, wrong_key), "expired": (exp_cert, exp_key)}.items()}
    yield {"dir": d, "ca": ca, "other_ca": other_ca, "servers": servers}
    for s in servers.values(): s.shutdown()


def tokfile(tmp_path, value, mode=0o600, name="tok"):
    p = tmp_path / name; p.write_text(value); p.chmod(mode); return p


def env(pki, tmp_path, token=ms.TOK_ADMIN, server="good", ca="ca", mode="EXTERNAL_ENTERPRISE", **over):
    e = {"AGENTSEC_SPLUNK_MODE": mode, "AGENTSEC_SPLUNK_REST_URL": f"https://127.0.0.1:{pki['servers'][server].server_port}",
         "AGENTSEC_SPLUNK_CA_BUNDLE_FILE": str(pki[ca]), "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": str(tokfile(tmp_path, token)), "AGENTSEC_SPLUNK_TIMEOUT_SEC": "2"}
    e.update(over); return e


def client(pki, tmp_path, **kw):
    return sc.SplunkRestClient(sc.config_from_env(env(pki, tmp_path, **kw)))


def codes(e): return {(f.level, f.code) for f in sc.validate_config(e)}


# ---------------- configuration ----------------
def test_bundled_is_the_default_and_ignores_external_settings():
    assert sc.validate_config({}) == [] and sc.config_from_env({}).mode == "BUNDLED"
    assert ("WARN", "EXTERNAL_SETTINGS_IGNORED") in codes({"AGENTSEC_SPLUNK_REST_URL": "https://x:8089"})


def test_valid_external_configuration_has_no_errors(pki, tmp_path):
    assert not [f for f in sc.validate_config(env(pki, tmp_path)) if f.level == "ERROR"]


@pytest.mark.parametrize("over,code", [({"AGENTSEC_SPLUNK_MODE": "SOMETHING"}, "MODE_INVALID"), ({"AGENTSEC_SPLUNK_REST_URL": ""}, "REST_URL_MISSING"),
    ({"AGENTSEC_SPLUNK_REST_URL": "http://splunk:8089"}, "REST_URL_INVALID"), ({"AGENTSEC_SPLUNK_REST_URL": "https://u:p@splunk:8089"}, "REST_URL_INVALID"),
    ({"AGENTSEC_SPLUNK_REST_URL": "https://splunk:8089/services?token=x"}, "REST_URL_INVALID"), ({"AGENTSEC_SPLUNK_REST_URL": "https://splunk:8089/x"}, "REST_URL_INVALID"),
    ({"AGENTSEC_SPLUNK_CA_BUNDLE_FILE": "/nonexistent/ca.pem"}, "CA_BUNDLE_MISSING"), ({"AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": "/nonexistent"}, "TOKEN_FILE_MISSING"),
    ({"AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": ""}, "TOKEN_FILE_MISSING"), ({"AGENTSEC_SPLUNK_INDEX": "a b;"}, "INDEX_INVALID"),
    ({"AGENTSEC_SPLUNK_TIMEOUT_SEC": "0"}, "TIMEOUT_INVALID"), ({"AGENTSEC_SPLUNK_TIMEOUT_SEC": "600"}, "TIMEOUT_INVALID"),
    ({"AGENTSEC_SPLUNK_HEC_URL": "http://h:8088"}, "HEC_URL_INVALID"), ({"AGENTSEC_SPLUNK_HEC_URL": "https://h:8088", "AGENTSEC_SPLUNK_HEC_TOKEN_FILE": "/nonexistent"}, "HEC_TOKEN_FILE_MISSING")])
def test_invalid_settings_are_refused(pki, tmp_path, over, code):
    assert ("ERROR", code) in codes(env(pki, tmp_path, **over))


def test_token_file_problems_and_permissions(pki, tmp_path):
    for body, code in (("", "TOKEN_FILE_EMPTY"), ("a\nb", "TOKEN_FILE_EMPTY"), ("x" * 5000, "TOKEN_FILE_TOO_LARGE")):
        assert ("ERROR", code) in codes(env(pki, tmp_path, AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE=str(tokfile(tmp_path, body, name="override"))))
    assert ("WARN", "TOKEN_FILE_PERMISSIONS") in codes(env(pki, tmp_path, AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE=str(tokfile(tmp_path, "t", 0o644, name="override"))))


def test_garbage_ca_bundle_is_refused(pki, tmp_path):
    bad = tmp_path / "bad.pem"; bad.write_text("not a certificate")
    assert ("ERROR", "CA_BUNDLE_INVALID") in codes(env(pki, tmp_path, AGENTSEC_SPLUNK_CA_BUNDLE_FILE=str(bad)))


def test_cloud_mode_states_its_requirements_and_flags_an_unrecognised_host(pki, tmp_path):
    c = codes(env(pki, tmp_path, mode="CLOUD", AGENTSEC_SPLUNK_REST_URL="https://acme.splunkcloud.com:8089"))
    assert ("WARN", "CLOUD_REST_ACCESS") in c and ("WARN", "CLOUD_HOST_UNRECOGNIZED") not in c
    assert ("WARN", "CLOUD_HOST_UNRECOGNIZED") in codes(env(pki, tmp_path, mode="CLOUD"))


def test_invalid_external_configuration_refuses_to_build_a_client(pki, tmp_path):
    with pytest.raises(sc.SplunkError) as e: sc.config_from_env(env(pki, tmp_path, AGENTSEC_SPLUNK_REST_URL="http://x"))
    assert e.value.code == "config_invalid"


def test_secrets_never_appear_in_findings_reprs_or_errors(pki, tmp_path):
    cfg = sc.config_from_env(env(pki, tmp_path))
    assert ms.TOK_ADMIN not in repr(cfg) and ms.TOK_ADMIN not in str(cfg)
    assert ms.TOK_ADMIN not in " ".join(f.message for f in sc.validate_config(env(pki, tmp_path, AGENTSEC_SPLUNK_CA_BUNDLE_FILE="/nonexistent")))
    with pytest.raises(sc.SplunkError) as e: client(pki, tmp_path, token="bad").server_info()
    assert "bad" not in str(e.value) and "Bearer" not in str(e.value)


# ---------------- strict TLS ----------------
def test_valid_ca_and_token_succeed(pki, tmp_path):
    client(pki, tmp_path).server_info()


@pytest.mark.parametrize("kw", [dict(ca="other_ca"), dict(server="wrongname"), dict(server="expired")])
def test_certificate_failures_fail_closed(pki, tmp_path, kw):
    with pytest.raises(sc.SplunkError) as e: client(pki, tmp_path, **kw).server_info()
    assert (e.value.stage, e.value.code) == ("connectivity", "tls_verification_failed")


def test_a_private_ca_is_rejected_without_the_bundle_but_never_bypassed(pki, tmp_path):
    e = env(pki, tmp_path); e.pop("AGENTSEC_SPLUNK_CA_BUNDLE_FILE")
    with pytest.raises(sc.SplunkError) as x: sc.SplunkRestClient(sc.config_from_env(e)).server_info()
    assert x.value.code == "tls_verification_failed"       # the system trust store does not know the mock CA


def test_redirects_are_never_followed_so_the_token_cannot_leave(pki, tmp_path):
    ms.Handler.seen.clear()
    with pytest.raises(sc.SplunkError) as e: client(pki, tmp_path, token=ms.TOK_REDIRECT).server_info()
    assert e.value.code == "redirect_refused" and all("evil" not in p for _, p, _, _ in ms.Handler.seen)


def test_connection_refused_and_timeouts_are_classified(pki, tmp_path):
    e = env(pki, tmp_path, AGENTSEC_SPLUNK_REST_URL="https://127.0.0.1:1")
    with pytest.raises(sc.SplunkError) as x: sc.SplunkRestClient(sc.config_from_env(e)).server_info()
    assert (x.value.stage, x.value.code) == ("connectivity", "connect_failed")
    with pytest.raises(sc.SplunkError) as t: client(pki, tmp_path, token=ms.TOK_SLOW).export_csv("search SLOWSEARCH", timeout_s=1)
    assert t.value.code in ("timeout",)


def test_tokens_travel_only_in_the_authorization_header(pki, tmp_path):
    ms.Handler.seen.clear(); client(pki, tmp_path).server_info(); client(pki, tmp_path).export_csv("| makeresults count=1")
    assert ms.Handler.seen and all(ms.TOK_ADMIN not in path and auth for _, path, auth, _ in ms.Handler.seen)


def test_oversized_responses_are_refused(pki, tmp_path):
    with pytest.raises(sc.SplunkError) as e: client(pki, tmp_path).export_csv("search BIGRESPONSE")
    assert e.value.code == "too_large"


# ---------------- staged diagnosis ----------------
def stages(res): return {s: (st, d) for s, st, d in res}


def test_good_token_passes_every_service_stage_but_telemetry_stays_unverified(pki, tmp_path):
    s = stages(client(pki, tmp_path).diagnose())
    assert [s[k][0] for k in ("connectivity", "authentication", "authorization", "search")] == ["PASS"] * 4 and s["telemetry"][0] == "NOT VERIFIED"


def test_telemetry_is_verified_only_for_a_run_with_events(pki, tmp_path):
    assert stages(client(pki, tmp_path).diagnose("r-present"))["telemetry"][0] == "PASS"
    assert stages(client(pki, tmp_path).diagnose("r-absent"))["telemetry"][0] == "NOT VERIFIED"
    assert stages(client(pki, tmp_path).diagnose("bad id;"))["telemetry"][0] == "NOT VERIFIED"


def test_bad_token_is_an_authentication_failure_not_a_connectivity_one(pki, tmp_path):
    s = stages(client(pki, tmp_path, token="bad").diagnose())
    assert s["connectivity"][0] == "PASS" and s["authentication"][0] == "FAIL" and s["search"][0] == "NOT VERIFIED"


def test_search_only_token_is_accepted_even_though_server_info_is_forbidden(pki, tmp_path):
    s = stages(client(pki, tmp_path, token=ms.TOK_SEARCH_ONLY).diagnose())
    assert s["authentication"][0] == "PASS" and s["authorization"][0] == "PASS" and s["search"][0] == "PASS"


def test_a_token_that_may_not_search_is_an_authorization_failure(pki, tmp_path):
    s = stages(client(pki, tmp_path, token=ms.TOK_NO_SEARCH).diagnose())
    assert s["authentication"][0] == "PASS" and s["authorization"][0] == "FAIL" and s["search"][0] == "NOT VERIFIED"


def test_unreachable_endpoint_leaves_later_stages_unverified(pki, tmp_path):
    s = stages(client(pki, tmp_path, ca="other_ca").diagnose())
    assert s["connectivity"] == ("FAIL", "tls_verification_failed") and all(s[k][0] == "NOT VERIFIED" for k in ("authentication", "authorization", "search", "telemetry"))


# ---------------- no arbitrary searches ----------------
@pytest.mark.parametrize("spl", ["search x | delete", "| outputlookup t.csv", "| rest /services/authentication/users", "search a | collect index=x", "| script python", "| sendemail to=x", "   ", "x" * 9000])
def test_dangerous_or_oversized_spl_is_refused_before_any_request(pki, tmp_path, spl):
    ms.Handler.seen.clear()
    with pytest.raises(sc.SplunkError) as e: client(pki, tmp_path).export_csv(spl)
    assert e.value.code == "forbidden_spl" and not [x for x in ms.Handler.seen if x[0] == "POST"]


def test_every_application_search_template_passes_the_read_only_guard():
    import uuid
    run, other = str(uuid.uuid4()), str(uuid.uuid4())
    for t in srch.TEMPLATES.values():
        spl, _ = t.build(run, {}, other if t.runs == 2 else None)
        sc.assert_read_only_spl(spl)


# ---------------- backends and selection ----------------
def test_bundled_selects_the_unchanged_docker_backend_and_external_selects_rest(pki, tmp_path):
    assert isinstance(srch.default_backend({}), srch.DockerExecBackend)
    assert isinstance(srch.default_backend(env(pki, tmp_path)), srch.RestBackend)


def test_misconfigured_external_mode_fails_closed_and_never_uses_docker(pki, tmp_path):
    b = srch.default_backend(env(pki, tmp_path, AGENTSEC_SPLUNK_REST_URL="http://insecure:8089"))
    assert isinstance(b, srch.UnavailableBackend) and b.run("search x").error == "backend_unavailable"


def test_rest_backend_maps_results_and_failures_to_the_fixed_outcome_codes(pki, tmp_path):
    ok = srch.RestBackend(client(pki, tmp_path)).run("search ROWS", max_rows=5)
    assert ok.ok and ok.truncated and len(ok.rows) == 5 and ok.columns == ["a", "b"]
    assert srch.RestBackend(client(pki, tmp_path, token="bad")).run("search x").error == "access_denied"   # a refused identity is named, not folded into a generic failure
    assert srch.RestBackend(client(pki, tmp_path, token=ms.TOK_NO_SEARCH)).run("search x").error == "access_denied"   # authenticated but not allowed to search: also a refusal
    assert srch.RestBackend(client(pki, tmp_path, ca="other_ca")).run("search x").error == "backend_unavailable"
    assert srch.RestBackend(client(pki, tmp_path, token=ms.TOK_SLOW)).run("search SLOWSEARCH", timeout_s=1).error == "timeout"
    assert srch.RestBackend(client(pki, tmp_path)).run("search x | delete").error == "search_failed"


def test_reconcile_and_evidence_probe_use_the_same_client_in_external_modes(pki, tmp_path, monkeypatch):
    from agentsec import evidence_readiness as er
    from agentsec.loan_desk import reconcile as rc
    e = env(pki, tmp_path)
    for k, v in e.items(): monkeypatch.setenv(k, v)
    assert rc.run_spl("search x")[0]["events"] == "3"                     # strict REST rows, no docker
    assert er.select_probe(e)("r-present")["splunk_count"] == 5 and er.select_probe(e)("r-absent")["splunk_count"] == 0
    bad = er.select_probe(env(pki, tmp_path, ca="other_ca"))("r-present")
    assert bad["error"] == "tls_verification_failed" and not bad["splunk_ok"]
    assert er.select_probe(env(pki, tmp_path, token="bad"))("r-present")["error"] == "probe_auth_failed"
    monkeypatch.setenv("AGENTSEC_SPLUNK_REST_URL", "http://insecure")
    with pytest.raises(RuntimeError): rc.run_spl("search x")               # invalid external config: error, not a docker fallback


def test_bundled_mode_still_uses_the_docker_paths(monkeypatch):
    from agentsec import evidence_readiness as er
    monkeypatch.delenv("AGENTSEC_SPLUNK_MODE", raising=False)
    assert er.select_probe({}) is er.probe_splunk_count


def test_no_tls_bypass_anywhere_in_the_client_or_its_backends():
    for f in ("src/agentsec/splunk_client.py", "src/agentsec/loan_desk/search.py", "src/agentsec/academy_search.py", "src/agentsec/installer/splunk_access.py"):
        t = (ROOT / f).read_text()
        assert not re.search(r"CERT_NONE|verify\s*=\s*False|_create_unverified|check_hostname\s*=\s*False|curl -[a-z]*k |--insecure", t), f


def test_cli_validate_and_check_exit_codes(pki, tmp_path):
    base = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    ok = subprocess.run([sys.executable, "-m", "agentsec.splunk_client", "check", "--run-id", "r-present"], env={**base, **env(pki, tmp_path)}, capture_output=True, text=True)
    assert ok.returncode == 0 and "TELEMETRY PASS" in ok.stdout and ms.TOK_ADMIN not in ok.stdout + ok.stderr
    bad = subprocess.run([sys.executable, "-m", "agentsec.splunk_client", "check"], env={**base, **env(pki, tmp_path, token="bad")}, capture_output=True, text=True)
    assert bad.returncode == 1 and "AUTHENTICATION FAIL" in bad.stdout
    inv = subprocess.run([sys.executable, "-m", "agentsec.splunk_client", "validate"], env={**base, **env(pki, tmp_path, AGENTSEC_SPLUNK_REST_URL="http://x")}, capture_output=True, text=True)
    assert inv.returncode == 1 and "INVALID" in inv.stdout
    assert subprocess.run([sys.executable, "-m", "agentsec.splunk_client", "check"], env={**base, "AGENTSEC_SPLUNK_MODE": "BUNDLED"}, capture_output=True, text=True).returncode == 0


def test_the_only_unverified_certificate_fetch_is_the_installers_loopback_read_of_the_certificate_it_then_verifies_against():
    hits = [str(p.relative_to(ROOT)) for p in (ROOT / "src").rglob("*.py") if "get_server_certificate" in p.read_text(encoding="utf-8")]
    assert hits == ["src/agentsec/installer/splunk_access.py"]
