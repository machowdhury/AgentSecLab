"""CTF through the gateway: the nginx MODEL (tests/gateway/nginx_model.py, NOT nginx) feeds the real Flask CTF app with exactly the headers it would send upstream.
Modelled, not nginx-verified: location choice, anchored captures, method limits, operator/Origin checks, which locations get the secret. Static checks: files, perms, compose YAML.
NOT verified here: nginx syntax, `set` + `proxy_set_header` evaluation order in a real nginx, the 8081 quota, TLS, real containers (no nginx or Docker is run)."""
import os, re, stat, subprocess
import pytest
from flask import Flask
from gwhelpers import ROOT, needs_openssl
from nginx_model import Gateway, basic
from agentsec.ctf.web import register_ctf
from agentsec.request_guard import install_request_guard
from agentsec.gateway_config import validate
from tests.ctf_support import FAKE, make_service

S = "0123456789abcdef" * 4                      # the gateway-owned secret (64 hex chars, as init generates)
HOST = "agentsec.test"
H = {"host": HOST}
ID = "a" * 32


def gw(**kw):
    return Gateway(host=HOST, ctf="enabled", ctf_secret=S, **kw)


def req(g, method, target, user="learner", **hdr):
    h = {"Host": HOST, "Authorization": basic(user), **hdr}
    return g.handle(method, target, h)


@pytest.fixture
def app(tmp_path, monkeypatch):
    svc, _ = make_service(tmp_path)
    a = Flask(__name__)
    register_ctf(a, service=svc)
    install_request_guard(a)
    monkeypatch.setenv("AGENTSEC_CTF_ALLOW_GATEWAY", "1")
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", S)
    return a.test_client()


def via(client, d, body=None):
    """Hand the Flask app exactly what the model says the upstream receives (peer = a mesh address, never loopback)."""
    assert d.status == 200 and d.upstream == "attack_service", d
    return client.open(d.path, method=d.method, headers=d.headers, environ_base={"REMOTE_ADDR": "172.18.0.4"}, json=body)


# ---- (B) through the model into the real app
def test_injected_secret_reaches_the_ctf_api():
    d = req(gw(), "GET", "/api/ctf/challenges")
    assert d.status == 200 and d.headers["x-agentsec-gateway-secret"] == S and d.headers["x-remote-user"] == "learner" and d.path == "/api/ctf/challenges"


def test_flask_answers_200_for_the_model_produced_headers(app):
    assert via(app, req(gw(), "GET", "/api/ctf/challenges")).status_code == 200
    assert via(app, req(gw(), "GET", "/api/ctf/scoreboard")).status_code == 200
    r = via(app, req(gw(), "POST", f"/api/ctf/challenges/{FAKE.id}/attempts", user="operator"), body={})
    assert r.status_code == 201, r.get_json()


def test_default_disabled_gateway_has_no_ctf_route_and_sends_no_secret():
    g = Gateway(host=HOST, ctf="disabled", ctf_secret=S)
    for m, t in (("GET", "/api/ctf/challenges"), ("GET", "/attack-service/ctf"), ("POST", "/api/ctf/challenges/x/attempts"), ("GET", "/attack-service/ctf/scoreboard")):
        d = req(g, m, t, user="operator")
        assert d.status == 404 and d.upstream is None, (m, t, d)


def test_secret_not_injected_means_the_app_refuses(app):
    d = req(Gateway(host=HOST, ctf="enabled", ctf_secret=None), "GET", "/api/ctf/challenges")
    assert d.status == 200 and "x-agentsec-gateway-secret" not in d.headers
    assert via(app, d).status_code == 403


def test_wrong_injected_secret_is_refused(app):
    assert via(app, req(Gateway(host=HOST, ctf="enabled", ctf_secret="f" * 64), "GET", "/api/ctf/challenges")).status_code == 403


def test_app_without_a_configured_secret_or_opt_in_refuses_even_the_correct_secret(app, monkeypatch):
    d = req(gw(), "GET", "/api/ctf/challenges")
    monkeypatch.delenv("AGENTSEC_CTF_GATEWAY_SECRET")
    assert via(app, d).status_code == 403
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", S); monkeypatch.delenv("AGENTSEC_CTF_ALLOW_GATEWAY")
    assert via(app, d).status_code == 403


def test_client_spoofed_secret_never_reaches_upstream(app):
    spoof = "attacker-chosen-secret-0123456789"
    d = req(gw(), "GET", "/api/ctf/challenges", **{"X-AgentSec-Gateway-Secret": spoof, "x-agentsec-gateway-secret": spoof.upper()})
    assert d.headers["x-agentsec-gateway-secret"] == S and spoof not in str(d.headers) and spoof.upper() not in str(d.headers)
    assert via(app, d).status_code == 200
    # spoofing the REAL secret from a client where the gateway injects nothing (CTF location absent / other location): overwritten away, so the app refuses
    for g, t in ((Gateway(host=HOST, ctf="disabled"), "/api/ctf/challenges"), (gw(), "/learn"), (Gateway(host=HOST, ctf="enabled", ctf_secret=None), "/api/ctf/challenges")):
        d = req(g, "GET", t, **{"X-AgentSec-Gateway-Secret": S})
        assert d.status in (200, 404) and "x-agentsec-gateway-secret" not in d.headers, (t, d.headers)
    assert via(app, req(Gateway(host=HOST, ctf="enabled", ctf_secret=None), "GET", "/api/ctf/challenges", **{"X-AgentSec-Gateway-Secret": S})).status_code == 403


def test_x_remote_user_alone_never_suffices(app):
    r = app.get("/api/ctf/challenges", headers={"Host": HOST, "X-Remote-User": "operator"}, environ_base={"REMOTE_ADDR": "172.18.0.4"})
    assert r.status_code == 403


def test_secret_is_attached_in_ctf_locations_only():
    g = gw()
    cases = [("GET", "/learn", "learner"), ("GET", "/api/target-health", "learner"), ("GET", "/attack-service/", "learner"), ("GET", "/attack-service/acmebank", "learner"),
             ("GET", "/api/labs/LAB-PI-001", "learner"), ("POST", "/api/launch", "operator"), ("POST", "/api/attacks/ATK-002", "operator"), ("GET", "/static/x.css", "learner")]
    for m, t, u in cases:
        d = req(g, m, t, user=u, **{"X-AgentSec-Gateway-Secret": S})
        assert d.status == 200 and "x-agentsec-gateway-secret" not in d.headers, (t, d.headers)
    assert [loc for loc in g.locations if "ctf-secret.conf" in loc[2]]                      # and the CTF locations do carry it
    assert all(loc[1].startswith(("^/api/ctf/", "^/attack-service/(?<asp>ctf")) for loc in g.locations if "ctf-secret.conf" in loc[2])
    for f in (ROOT / "gateway").glob("*.conf"):
        assert ("include /etc/nginx/ctf-secret.conf;" in f.read_text()) == (f.name == "ctf-enabled.conf"), f.name
    assert "include /etc/nginx/ctf-secret.conf;" not in (ROOT / "gateway/templates/gateway.conf.template").read_text()


@pytest.mark.parametrize("target", [
    "/api/ctf", "/api/ctf/", "/api/ctf/nope", "/api/ctf/challenges/", "/api/ctf/challenges/x/attempts/", "/api/ctf/challenges/x/y/hint", "/api/ctf/attempts/x/run/extra",
    "/api/ctf/challenges/a%252e%252e", "/api/ctf/challenges/a%5cb", "/api/ctf/challenges/a.b", "/api/ctf/challenges/%00", "/api/ctf/challenges/a%00b",
    "/attack-service/ctf/a/b", "/attack-service/ctf/", "/attack-service/ctf%2fx%2fy", "/attack-service/ctf/a.b", "/attack-service/ctf/%252e", "/attack-service/ctfx"])
def test_malformed_traversal_and_encoded_paths_never_get_the_secret(target):
    d = req(gw(), "GET", target, user="operator")
    assert d.upstream is None or "x-agentsec-gateway-secret" not in d.headers or (d.path and re.fullmatch(r"/(api/ctf/[A-Za-z0-9_/-]+|ctf(/[A-Za-z0-9_-]+)?)", d.path.split("?")[0])), (target, d)
    assert d.status in (400, 404, 200)
    if d.status == 200:
        assert "%" not in d.path and ".." not in d.path


@pytest.mark.parametrize("target,ok", [("/api/ctf/challenges/a%2fhint", "/api/ctf/challenges/a/hint"), ("/api/ctf/challenges/../health", "/api/ctf/health"),
                                       ("/api/ctf//scoreboard", "/api/ctf/scoreboard"), ("/attack-service/ctf/./scoreboard", "/ctf/scoreboard")])
def test_decoded_or_normalised_paths_are_rebuilt_from_the_allowlisted_capture(target, ok):
    d = req(gw(), "GET", target)
    assert d.status == 200 and d.path == ok and d.headers["x-agentsec-gateway-secret"] == S


def test_traversal_out_of_the_ctf_allowlist_loses_the_secret():
    for t in ("/api/ctf/challenges/../../learn/config", "/attack-service/ctf/../labs/LAB-PI-001", "/api/ctf/%2e%2e/target-health"):
        d = req(gw(), "GET", t)
        assert "x-agentsec-gateway-secret" not in d.headers, (t, d)


def test_pages_and_api_use_the_approved_paths_and_prefix():
    d = req(gw(), "GET", "/attack-service/ctf/scoreboard")
    assert d.status == 200 and d.path == "/ctf/scoreboard" and d.headers["x-forwarded-prefix"] == "/attack-service" and d.headers["x-agentsec-gateway-secret"] == S
    assert "x-forwarded-prefix" not in req(gw(), "GET", "/api/ctf/health").headers


def test_wrong_methods_are_denied():
    g = gw()
    for m, t in (("POST", "/attack-service/ctf"), ("PUT", "/attack-service/ctf/x"), ("POST", "/api/ctf/challenges"), ("DELETE", "/api/ctf/scoreboard"), ("POST", "/api/ctf/health"),
                 ("GET", f"/api/ctf/attempts/{ID}/run"), ("GET", "/api/ctf/challenges/x/attempts"), ("PUT", f"/api/ctf/attempts/{ID}/redeem"), ("DELETE", f"/api/ctf/attempts/{ID}/reset"),
                 ("PATCH", f"/api/ctf/attempts/{ID}/verify"), ("HEAD", f"/api/ctf/attempts/{ID}/run")):
        d = req(g, m, t, user="operator")
        assert d.status == 403 and d.upstream is None, (m, t, d.status)
    assert req(g, "HEAD", "/attack-service/ctf").status == 200


@pytest.mark.parametrize("t", ["/api/ctf/challenges/x/attempts", f"/api/ctf/attempts/{ID}/run", f"/api/ctf/attempts/{ID}/verify", f"/api/ctf/attempts/{ID}/redeem", f"/api/ctf/attempts/{ID}/reset"])
def test_post_needs_operator_same_origin_and_authentication(t):
    g = gw()
    assert req(g, "POST", t, user="operator").status == 200 and req(g, "POST", t, user="operator").headers["x-agentsec-gateway-secret"] == S
    body = next(b for _, p, b in g.locations if p == req(g, "POST", t, user="operator").location)
    assert "auth_request /_authz_operator;" in body                                      # the operator check + shared quota guard the secret-bearing POST locations
    assert req(g, "POST", t, user="learner").status == 403                              # missing operator role
    assert g.handle("POST", t, {"Host": HOST}).status == 401                            # no credentials
    for bad in ({"Origin": "https://evil.example"}, {"Origin": f"http://{HOST}"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
        d = req(g, "POST", t, user="operator", **bad)
        assert d.status == 403 and d.upstream is None, (bad, d.status)
    assert req(g, "POST", t, user="operator", Origin=f"https://{HOST}", **{"Sec-Fetch-Site": "same-origin"}).status == 200


def test_wrong_host_and_port_are_refused():
    assert Gateway(host=HOST, port="8443", ctf="enabled", ctf_secret=S).handle("GET", "/api/ctf/health", {"Host": HOST, "Authorization": basic()}).status == 421
    assert gw().handle("GET", "/api/ctf/health", {"Host": "evil.example", "Authorization": basic()}).upstream is None


def test_ctf_enabled_requires_the_attack_tier(monkeypatch):
    assert any(f.code == "CTF_GATEWAY_NEEDS_ATTACK_TIER" for f in validate({"AGENTSEC_CTF_GATEWAY": "enabled", "AGENTSEC_ATTACK_TIER": "disabled"}))
    assert any(f.code == "CTF_GATEWAY_INVALID" for f in validate({"AGENTSEC_CTF_GATEWAY": "yes"}))
    assert not any(f.code.startswith("CTF_GATEWAY") for f in validate({"AGENTSEC_CTF_GATEWAY": "enabled"}))
    with pytest.raises(AssertionError):
        Gateway(host=HOST, tier="disabled", ctf="enabled")


# ---- static: compose + files + gitignore (no Docker, no nginx)
def test_compose_overlays_deliver_the_secret_only_through_the_ctf_overlay():
    base = (ROOT / "docker-compose.gateway.yml").read_text()
    ctf = (ROOT / "docker-compose.gateway-ctf.yml").read_text()
    code = lambda t: "\n".join(l for l in t.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"CTF_ALLOW_GATEWAY|GATEWAY_SECRET|ctf-secret|ctf-gateway-secret", code(base)) and "AGENTSEC_CTF_GATEWAY=disabled" in base
    assert "AGENTSEC_CTF_GATEWAY=enabled" in ctf and "AGENTSEC_CTF_ALLOW_GATEWAY=1" in ctf
    assert "AGENTSEC_CTF_GATEWAY_SECRET_FILE=/run/secrets/agentsec_ctf_gateway_secret" in ctf and not re.search(r"AGENTSEC_CTF_GATEWAY_SECRET=", ctf)   # a file, never the value in the environment
    assert all(l.strip().endswith(":ro") for l in ctf.splitlines() if l.strip().startswith("- ${") and "CTF_STATE_HOST" not in l) and "ports" not in code(ctf)
    assert "docker-compose.gateway-ctf.yml" in (ROOT / "scripts/gateway.sh").read_text() and "CTF" not in code((ROOT / "docker-compose.yml").read_text()).replace("AGENTSEC_CTF_STATE", "")


def test_gateway_dir_is_gitignored_so_the_secret_cannot_be_committed():
    for f in (".gateway/ctf-gateway-secret", ".gateway/ctf-secret.conf"):
        assert subprocess.run(["git", "check-ignore", "-q", f], cwd=ROOT).returncode == 0, f


@needs_openssl
def test_init_and_ctf_enable_handle_the_secret_safely(tmp_path):
    g = tmp_path / "g"
    env = {**os.environ, "AGENTSEC_GATEWAY_DIR": str(g)}
    run = lambda *a: subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), *a], cwd=ROOT, env=env, capture_output=True, text=True)
    p = run("init"); assert p.returncode == 0, p.stderr
    sec, conf = g / "ctf-gateway-secret", g / "ctf-secret.conf"
    s = sec.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", s)                                                  # 32 random bytes
    assert conf.read_text() == f'set $gw_secret "{s}";\nauth_request_set $gw_secret "{s}";\n'
    assert stat.S_IMODE(sec.stat().st_mode) == 0o600 and stat.S_IMODE(conf.stat().st_mode) == 0o600
    assert "AGENTSEC_CTF_GATEWAY=disabled" in (g / "gateway.env").read_text() and s not in (g / "gateway.env").read_text()
    assert s not in p.stdout + p.stderr
    e1 = run("ctf-enable"); assert e1.returncode == 0 and s not in e1.stdout + e1.stderr
    e2 = run("ctf-enable"); assert e2.returncode == 0 and sec.read_text().strip() == s       # idempotent: the secret is kept
    assert (g / "gateway.env").read_text().count("AGENTSEC_CTF_GATEWAY=") == 1 and "AGENTSEC_CTF_GATEWAY=enabled" in (g / "gateway.env").read_text()
    assert "AGENTSEC_PUBLIC_HOST" in (g / "gateway.env").read_text()                         # other settings preserved
    assert run("ctf-disable").returncode == 0 and "AGENTSEC_CTF_GATEWAY=disabled" in (g / "gateway.env").read_text()
    # the model renders the very same file content the script wrote
    assert Gateway(host=HOST, ctf="enabled", ctf_secret=re.search(r'"(.*)"', conf.read_text()).group(1)).handle("GET", "/api/ctf/health", {"Host": HOST, "Authorization": basic()}).headers["x-agentsec-gateway-secret"] == s
    sec.unlink(); conf.unlink()
    assert run("ctf-enable").returncode == 0 and sec.read_text().strip() != s                # rotation = delete + enable
    assert not subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "ctf-enable"], cwd=ROOT, env={**env, "AGENTSEC_GATEWAY_DIR": str(tmp_path / "none")}, capture_output=True).returncode == 0
