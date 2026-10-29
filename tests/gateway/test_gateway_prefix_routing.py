"""Routing decisions for the approved classic-UI prefix, evaluated with the pure-Python model in nginx_model.py (a MODEL, not nginx: see its docstring)."""
import re
import pytest
from nginx_model import Gateway, basic, normalise, ROOT

G = Gateway()
H = {"host": "agentsec.test", "authorization": basic("learner")}
SAFE_UPSTREAM = re.compile(r"^/(labs/[A-Za-z0-9_-]+|acmebank|academy/(home|foundations|path|status|missions/loan-desk|labs/[A-Za-z0-9_-]+))?$")
OK = {"/attack-service/": "/", "/attack-service/labs/LAB-MCP-001": "/labs/LAB-MCP-001", "/attack-service/acmebank": "/acmebank",
      "/attack-service/academy/home": "/academy/home", "/attack-service/academy/path": "/academy/path", "/attack-service/academy/status": "/academy/status",
      "/attack-service/academy/foundations": "/academy/foundations", "/attack-service/academy/labs/LAB-MCP-001": "/academy/labs/LAB-MCP-001",
      "/attack-service/academy/missions/loan-desk": "/academy/missions/loan-desk"}


@pytest.mark.parametrize("target,up", OK.items())
def test_approved_pages_reach_the_attack_service_only(target, up):
    d = G.handle("GET", target, H)
    assert (d.status, d.upstream, d.path) == (200, "attack_service", up)
    assert d.headers["x-forwarded-prefix"] == "/attack-service" and d.headers["x-remote-user"] == "learner"
    assert G.handle("HEAD", target, H).status == 200


def test_bare_prefix_redirects_to_the_slash_form_without_a_host():
    d = G.handle("GET", "/attack-service", H)
    assert (d.status, d.redirect) == (302, "/attack-service/")


# path traversal, encodings, lookalikes, case, internal services: none may reach any backend (status != 200 or upstream path in the closed set)
BAD = ["/attack-service/../api/tags", "/attack-service/%2e%2e/%2e%2e/en-US/", "/attack-service/labs/%2e%2e/%2e%2e/api/tags", "/attack-service/labs/..%2fx",
       "/attack-service/%252e%252e/api/tags", "/attack-service/labs/%252e%252e", "/attack-service/labs/a%2fb", "/attack-service/labs\\..\\x", "/attack-service/labs/a%5cb",
       "/attack-service/labs/x%00", "/attack-service/%00", "/attack-service//labs/../../x", "/attack-service/acmebank.", "/attack-service/acmebank/", "/attack-service/acmebank%2f",
       "/attack-service/ACMEBANK", "/Attack-Service/acmebank", "/ATTACK-SERVICE/", "/attack-service/labs/", "/attack-service/labs", "/attack-service/labs/a.b",
       "/attack-service/labs/аdmin", "/attack-service/labs/%D0%B0", "/attack-service/acmеbank", "/attack-service/．．/x", "/attack-service/labs/ x",
       "/attack-service/api/launch", "/attack-service/api/tags", "/attack-service/static/x", "/attack-service/learn", "/attack-service/academy", "/attack-service/academy/",
       "/attack-service/academy/missions", "/attack-service/academy/labs", "/attack-service/health", "/attack-service/process", "/attack-service/acmebank/process",
       "/attack-service/services/", "/attack-service/en-US/app/search", "/attack-service/v1/ollama", "/attack-service/:5000/", "/attack-service/@evil/", "/attack-service/http://acmebank:5000/",
       "/acmebank", "/labs/LAB-PI-001", "/academy/home", "/academy/path", "/process", "/services/server/info", "/servicesNS/x", "/en-US/app/search/search", "/v1/ollama/api/tags", "/api/tags",
       "/api/v1/loan-desk/status", "/_authz_operator", "//attack-service/../acmebank/process", "/learn/../acmebank", "/static/../acmebank", "/:5000/health", "/services/collector/event", "/8088/"]


@pytest.mark.parametrize("target", BAD)
def test_nothing_outside_the_allowlist_is_routable(target):
    d = G.handle("GET", target, H)
    assert d.upstream is None and d.status in (302, 400, 403, 404), (target, d.status, d.path, d.location)


@pytest.mark.parametrize("target", ["/attack-service//labs/LAB-MCP-001", "/attack-service/./labs/LAB-MCP-001", "/attack-service/labs/../acmebank", "/attack-service/labs/%4cAB-X"])
def test_inputs_nginx_normalises_into_an_allowed_page_get_only_the_rebuilt_upstream_path(target):
    d = G.handle("GET", target, H)
    assert d.status == 200 and SAFE_UPSTREAM.match(d.path), (d.status, d.path)   # the raw (un-normalised) target never reaches the backend on this location


def test_normaliser_model_basics():
    assert normalise("/a/%2e%2e/b") == "/b" and normalise("/a//b/") == "/a/b/" and normalise("/%252e") == "/%2e" and normalise("/..") is None and normalise("/a%00") is None


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "CONNECT"])
@pytest.mark.parametrize("target", list(OK))
def test_other_methods_are_refused_on_every_page(method, target):
    d = G.handle(method, target, H)
    assert d.status == 403 and d.upstream is None


def test_the_prefix_cannot_carry_the_attack_apis_or_a_second_proxy_hop():
    for t in ("/attack-service/api/launch", "/attack-service/api/launches/abc", "/attack-service/api/missions/loan-desk/runs"):
        assert G.handle("POST", t, {**H, "authorization": basic("operator")}).upstream is None


def test_authentication_host_and_port_checks_come_first():
    assert G.handle("GET", "/attack-service/acmebank", {"host": "agentsec.test"}).status == 401
    assert G.handle("GET", "/attack-service/acmebank", {"host": "agentsec.test", "authorization": "Basic Zm9vOmJhcg=="}).status == 401
    assert G.handle("GET", "/attack-service/acmebank", {"authorization": basic()}).status == 404 and G.handle("GET", "/attack-service/acmebank", {"authorization": basic()}).upstream is None
    for hh in ("evil.example", "agentsec.test.evil.example", "127.0.0.1", "agentsec.test:5000"):
        d = G.handle("GET", "/attack-service/acmebank", {**H, "host": hh}); assert d.upstream is None and d.status in (404, 421), hh
    assert Gateway(port="8000").handle("GET", "/attack-service/", {**H, "host": "agentsec.test:8000"}).status == 200
    assert Gateway(port="8000").handle("GET", "/attack-service/", {**H, "host": "agentsec.test"}).status == 421


def test_client_sent_forwarding_and_identity_headers_never_reach_the_backend_unchanged():
    spoof = {**H, "x-forwarded-prefix": "/evil", "x-remote-user": "operator", "x-auth-role": "operator", "x-forwarded-for": "10.0.0.1", "x-forwarded-user": "root",
             "x-forwarded-proto": "http", "x-authz-user": "operator", "x-forwarded-groups": "admins"}
    for t in ("/attack-service/acmebank", "/learn"):
        h = G.handle("GET", t, spoof).headers
        assert (h["x-remote-user"], h["x-auth-role"], h["x-forwarded-for"], h["x-forwarded-proto"]) == ("learner", "learner", "203.0.113.9", "https"), t
        assert "x-forwarded-user" not in h and "x-forwarded-groups" not in h and "authorization" not in h
        assert h.get("x-forwarded-prefix", "") == ("/attack-service" if "attack-service" in t else "")
    assert "x-authz-user" not in G.handle("GET", "/learn", spoof).headers     # blanked since the review (Low-2)


def test_attack_posts_keep_their_operator_tier_origin_and_method_rules():
    op, ln = {**H, "authorization": basic("operator")}, H
    assert G.handle("POST", "/api/launch", op).status == 200 and G.handle("POST", "/api/launch", ln).status == 403          # learner is not an operator
    assert G.handle("POST", "/api/launch", {**op, "origin": "https://evil.example"}).status == 403                            # cross-origin Origin
    assert G.handle("POST", "/api/launch", {**op, "origin": "https://agentsec.test"}).status == 200
    assert G.handle("POST", "/api/launch", {**op, "origin": "http://agentsec.test"}).status == 403
    assert G.handle("POST", "/api/launch", {**op, "sec-fetch-site": "cross-site"}).status == 403
    assert G.handle("PUT", "/api/launch", op).status == 403 and G.handle("DELETE", "/api/launch", op).status == 403
    assert G.handle("POST", "/api/launch", {"host": "agentsec.test"}).status == 401


def test_redirect_targets_are_constants_so_nothing_user_controlled_enters_a_location_header():
    text = (ROOT / "gateway/templates/gateway.conf.template").read_text()
    assert not re.search(r"return 30[12] [^;]*\$", text) and "$request_uri" not in text and "$uri" not in text.replace("$uri;", "")   # no variable in any redirect / upstream URI
    for t in ("/attack-service\r\nSet-Cookie: x=1", "/attack-service%0d%0aSet-Cookie:%20x=1", "/attack-service%0aX:1"):
        d = G.handle("GET", t, H); assert d.redirect in (None, "/attack-service/") and d.status in (302, 400, 404)


def test_disabled_tier_keeps_the_pages_but_closes_the_launch_api():
    g = Gateway(tier="disabled"); op = {**H, "authorization": basic("operator")}
    assert g.handle("GET", "/attack-service/acmebank", op).status == 200 and g.handle("POST", "/api/launch", op).status == 404


def test_no_route_to_internal_services_exists_in_the_configuration_text():
    text = (ROOT / "gateway/templates/gateway.conf.template").read_text() + (ROOT / "gateway/attack-enabled.conf").read_text()
    live = "\n".join(l.split("#")[0] for l in text.splitlines())          # configuration without comments
    upstreams = set(re.findall(r"proxy_pass\s+([^;]+);", live)) | set(re.findall(r"set \$\w+ (http://[^;]+);", live))
    assert upstreams == {"$attack", "$attack/$asp", "http://attack_service:5001", "http://127.0.0.1:8081"}, upstreams
    for banned in (":5000", "8088", "8089", "11434", "ollama", "4317", "13133", "splunk", "/services", "/en-US", "/v1/"):
        assert banned not in live.lower(), banned


def test_the_one_read_api_the_classic_pages_poll_is_reachable_for_get_only():
    assert G.handle("GET", "/api/target-health", H).upstream == "attack_service" and G.handle("POST", "/api/target-health", H).upstream is None
    assert G.handle("GET", "/api/target-health/x", H).upstream is None


def test_target_health_is_rate_limited_per_user_and_get_only():
    d = G.handle("GET", "/api/target-health", H)
    assert (d.upstream, d.zone) == ("attack_service", "health")
    text = (ROOT / "gateway/templates/gateway.conf.template").read_text()
    assert re.search(r"limit_req_zone \$binary_remote_addr zone=health:\d+m rate=\d+r/m;", text)
    assert G.handle("PUT", "/api/target-health", H).upstream is None


@pytest.mark.parametrize("name", ["X-Authz-User", "X-Authz-Method", "X-Authz-Reason", "X-Remote-Addr", "X-Remote-Host", "X-Remote-Role", "X-Remote-Roles", "X-Forwarded-Prefix"])
@pytest.mark.parametrize("target", ["/learn", "/health", "/api/target-health", "/attack-service/acmebank", "/static/x.css"])
def test_client_sent_internal_headers_never_reach_the_backend(name, target):
    h = G.handle("GET", target, {**H, name: "operator"}).headers
    assert name.lower() not in h or (name == "X-Forwarded-Prefix" and h[name.lower()] in ("", "/attack-service") and "operator" not in h[name.lower()])
    op = {**H, "authorization": basic("operator"), name: "x"}
    for t in ("/api/launch",):
        assert name.lower() not in G.handle("POST", t, op).headers or name == "X-Forwarded-Prefix"


def test_gateway_adds_frame_ancestors_csp_on_normal_and_denied_responses():
    for f in ("gateway/templates/gateway.conf.template", "gateway/attack-enabled.conf"):
        assert """add_header Content-Security-Policy "frame-ancestors 'none'" always;""" in (ROOT / f).read_text(), f
